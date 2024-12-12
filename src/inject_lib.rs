use std::{env, os::raw::c_void, ptr};
use imp::FARPROC;
use pe_parser::{ get_export_offset_from_file, get_pe_file_machine, is_pe_file, offset_ptr };
use windows::{
    core::*,
    Win32::{
        Foundation::{ SetLastError, HANDLE, HMODULE, WIN32_ERROR, BOOL },
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            LibraryLoader::{ GetModuleHandleW, GetProcAddress },
            Memory::{ VirtualAllocEx, MEM_COMMIT, PAGE_READWRITE },
            ProcessStatus::{ EnumProcessModulesEx, GetModuleBaseNameW, LIST_MODULES_32BIT },
            SystemInformation::{
                IMAGE_FILE_MACHINE,
                IMAGE_FILE_MACHINE_AMD64,
                IMAGE_FILE_MACHINE_I386,
                IMAGE_FILE_MACHINE_UNKNOWN,
            },
            Threading::*,
        },
    },
};
use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
use ms_detours::{DetourCreateProcessWithDllExW, PDETOUR_CREATE_PROCESS_ROUTINEW};
use crate::inject_lib::iat_injection_tools::get_process_machine;

mod pe_parser;
mod iat_injection_tools;

fn is_same_bitness(dll_path: &String, h_proc: HANDLE, event_history: &mut Vec<String>) -> bool {
    let dll_bitness = get_pe_file_machine(dll_path, event_history);
    let process_bitness = get_process_machine(h_proc, event_history);
    if dll_bitness == IMAGE_FILE_MACHINE_UNKNOWN || process_bitness == IMAGE_FILE_MACHINE_UNKNOWN {
        return false;
    }
    return dll_bitness == process_bitness;
}

fn get_native_load_library_addr(event_history: &mut Vec<String>) -> windows::core::Result<FARPROC> {
    unsafe {
        let k32 = GetModuleHandleW(w!("kernel32.dll")).map_err(|e| {
            event_history.push(format!("Failed to locate kernel32.dll. Error: {}", e));
            e
        })?;

        return Ok(
            Some(
                GetProcAddress(k32, s!("LoadLibraryW")).ok_or_else(|| {
                    event_history.push(
                        format!(
                            "Failed to locate LoadLibraryW. Error: {}",
                            windows::core::Error::from_win32()
                        )
                    );
                    windows::core::Error::from_win32()
                })?
            )
        );
    }
}

fn expand_env_vars(input: &str) -> String {
    let mut result = input.to_string().to_lowercase();
    for (key, value) in env::vars() {
        let placeholder = format!("%{}%", key.to_lowercase());
        println!("placeholder: {}", placeholder);
        result = result.replace(&placeholder, &value);
    }
    result
}

fn get_wow64_load_library_addr(
    h_proc: HANDLE,
    event_history: &mut Vec<String>
) -> windows::core::Result<FARPROC> {
    unsafe {
        let mut modules: [HMODULE; 1024] = [HMODULE::default(); 1024];
        let mut needed: u32 = 0;
        let _em = EnumProcessModulesEx(
            h_proc,
            modules.as_mut_ptr(),
            (std::mem::size_of::<HMODULE>() * modules.len()) as u32,
            &mut needed,
            LIST_MODULES_32BIT
        ).map_err(|e| {
            event_history.push(
                format!("Failed to enumerate modules in target process. Error: {}", e)
            );
            e
        })?;
        let num_modules = (needed as usize) / std::mem::size_of::<HMODULE>();
        for &module in &modules[..num_modules] {
            let mut module_name = vec![0u16; 13]; // only care about kernel32.dll which is 13 chars
            let len = GetModuleBaseNameW(h_proc, module, &mut module_name);
            if len == 0 {
                continue;
            }
            let module_name_str = String::from_utf16_lossy(&module_name[..len as usize]);
            println!("{}", module_name_str);
            if module_name_str.eq_ignore_ascii_case("kernel32.dll") {
                let sys_wow_k32_path = expand_env_vars("%systemroot%\\syswow64\\kernel32.dll");
                    // .map_err(|e| {
                    //     event_history.push(
                    //         format!("Failed to get syswow64 k32 path. Error: {}", e)
                    //     );
                    //     SetLastError(WIN32_ERROR(203) /*ERROR_ENVAR_NOT_FOUND*/);
                    //     windows::core::Error::from_win32()
                    // })?;
                println!("expanded: {}", sys_wow_k32_path);
                let load_library_wow64_offset = get_export_offset_from_file(
                    &sys_wow_k32_path.as_str().to_string(),
                    &"LoadLibraryW".to_string()
                ).map_err(|e| {
                    event_history.push(
                        format!("Failed to get loadlibrary wow64 offset. Error: {}", e)
                    );
                    SetLastError(WIN32_ERROR(87));
                    windows::core::Error::from_win32()
                })?;
                return Ok(
                    std::mem::transmute(
                        offset_ptr(module.0 as *const c_void, load_library_wow64_offset)
                    )
                );
            }
        }
        SetLastError(WIN32_ERROR(2) /* ERROR_FILE_NOT_FOUND */);
        Err(windows::core::Error::from_win32())
    }
}

fn get_load_library_addr(
    h_proc: HANDLE,
    event_history: &mut Vec<String>
) -> windows::core::Result<FARPROC> {
    match get_process_machine(h_proc, event_history) {
        IMAGE_FILE_MACHINE_AMD64 => {
            return get_native_load_library_addr(event_history);
        }
        IMAGE_FILE_MACHINE_I386 => {
            return get_wow64_load_library_addr(h_proc, event_history);
        }
        _ => {
            unsafe {
                SetLastError(WIN32_ERROR(87));
            } // ERROR_INVALID_PARAMETER
            return Err(windows::core::Error::from_win32());
        }
    }
}

fn write_dll_path_to_process(
    h_proc: HANDLE,
    dll_path: &str,
    event_history: &mut Vec<String>
) -> windows::core::Result<*mut c_void> {
    unsafe {
        let dll_path_hstring = HSTRING::from(dll_path);
        let bytes_to_write =
            dll_path_hstring.len() * std::mem::size_of::<u16>() + std::mem::size_of::<u16>();
        let dll_path_addr = VirtualAllocEx(
            h_proc,
            None,
            bytes_to_write,
            MEM_COMMIT,
            PAGE_READWRITE
        );
        if dll_path_addr.is_null() {
            event_history.push(
                format!(
                    "Failed to allocate memory in target process. Error: {}",
                    windows::core::Error::from_win32()
                )
            );
            return Err(windows::core::Error::from_win32());
        }

        if WriteProcessMemory(
            h_proc,
            dll_path_addr,
            dll_path_hstring.as_ptr() as *const c_void,
            bytes_to_write,
            None
        ).is_err()
        {
            event_history.push(
                format!(
                    "Failed to write memory in target process. Error: {:?}",
                    windows::core::Error::from_win32()
                )
            );
            return Err(windows::core::Error::from_win32());
        }
        Ok(dll_path_addr)
    }
}

pub(crate) fn inject(
    dll_path: &String,
    pid: u32,
    event_history: &mut Vec<String>
) -> windows::core::Result<()> {
    unsafe {
        if !is_pe_file(dll_path, event_history) {
            SetLastError(WIN32_ERROR(87)); // ERROR_INVALID_PARAMETER
            return Err(windows::core::Error::from_win32());
        }

        // let dll_path_hstring = HSTRING::from(dll_path.clone());
        // println!("Target PID: {}", pid);
        // println!("dll to inject: {}", dll_path_hstring);

        let h_proc = Owned::new(
            OpenProcess(PROCESS_ALL_ACCESS, false, pid).map_err(|e| {
                event_history.push(format!("Failed to open process {}: {}", pid, e));
                e
            })?
        );

        if !is_same_bitness(dll_path, *h_proc, event_history) {
            SetLastError(WIN32_ERROR(216)); // ERROR_EXE_MACHINE_TYPE_MISMATCH
            return Err(windows::core::Error::from_win32());
        }

        let load_library_addr = get_load_library_addr(*h_proc, event_history).map_err(|e| {
            event_history.push(format!("Failed to locate LoadLibraryW. Error: {}", e));
            e
        })?;

        let dll_path_addr = write_dll_path_to_process(*h_proc, dll_path, event_history).map_err(|e| {
            e
        })?;

        let _ = Owned::new(
            CreateRemoteThread(
                *h_proc,
                None,
                0,
                std::mem::transmute(load_library_addr),
                Some(dll_path_addr),
                0,
                None
            ).map_err(|e| {
                event_history.push(format!("Failed to create remote thread. Error: {}", e));
                e
            })?
        );

        // println!("Successfully injected {} into process {}", dll_path, pid);

        // Optional: Wait for user input before exiting
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
    }

    Ok(())
}

type NtQueueApcThreadFn = unsafe extern "system" fn(
    thread_handle: HANDLE,
    apc_routine: *mut   c_void,
    apc_argument1: *mut c_void,
    apc_argument2: *mut c_void,
    apc_argument3: *mut c_void,
) -> i32;

pub(crate) fn inject_new_process_apc(dll_path: &str,
                                     exe_path: &str,
                                     event_history: &mut Vec<String>
) -> windows::core::Result<()> {
    unsafe {

        let mut _exe_path: Vec<u16> = exe_path.trim_matches('"').encode_utf16().collect();
        _exe_path.push(0);
        let exe_path_pwstr = PWSTR(_exe_path.as_mut_ptr());

        let si = STARTUPINFOW{
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_SHOW.0 as u16,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        CreateProcessW(None, exe_path_pwstr, None, None, BOOL(0), CREATE_SUSPENDED, None, None, &si, &mut pi).map_err(|e| {
            event_history.push(format!("Failed to Create process {}. Error: {}", exe_path, e));
            e
        })?;

        let dll_path_addr = write_dll_path_to_process(pi.hProcess, dll_path.trim_matches('"'), event_history ).map_err(|e| {
            e
        })?;

        let load_library_addr = get_load_library_addr(pi.hProcess, event_history).map_err(|e| {
            event_history.push(format!("Failed to locate LoadLibraryW. Error: {}", e));
            e
        })?;

        let nt_queue_apc_thread_farproc = GetProcAddress(GetModuleHandleW(w!("ntdll.dll"))?, s!("NtQueueApcThread"));
        if nt_queue_apc_thread_farproc == FARPROC::default() {
            event_history.push(format!("Failed to locate NtQueueApcThread. Error: {}", windows::core::Error::from_win32()));
            return Err(windows::core::Error::from_win32());
        }
        let nt_queue_apc_thread: NtQueueApcThreadFn = std::mem::transmute(nt_queue_apc_thread_farproc);
        let status = nt_queue_apc_thread(pi.hThread, std::mem::transmute(load_library_addr),  dll_path_addr, ptr::null_mut(), ptr::null_mut());

        if status != 0 {
            event_history.push(format!("Failed to queue APC thread. Error: {:x}", status));
        }
        
        let resume_res = ResumeThread(pi.hThread);

        if (status != 0) || resume_res == u32::MAX{
            if status != 0 {
                event_history.push(format!("Failed to queue APC thread. Error: {:x}", status));
            }
            if resume_res == u32::MAX {
                event_history.push(format!("Failed to resume thread. Error: {}", windows::core::Error::from_win32()));
            }
            return Err(windows::core::Error::from_win32());
        }
    }

    Ok(())
}

// extern "C" {
//     pub fn DetourCreateProcessWithDllExW(
//         lpApplicationName: LPCWSTR,
//         lpCommandLine: LPWSTR,
//         lpProcessAttributes: LPSECURITY_ATTRIBUTES,
//         lpThreadAttributes: LPSECURITY_ATTRIBUTES,
//         bInheritHandles: BOOL,
//         dwCreationFlags: DWORD,
//         lpEnvironment: LPVOID,
//         lpCurrentDirectory: LPCWSTR,
//         lpStartupInfo: LPSTARTUPINFOW,
//         lpProcessInformation: LPPROCESS_INFORMATION,
//         lpDllName: LPCSTR,
//         pfCreateProcessW: PDETOUR_CREATE_PROCESS_ROUTINEW,
//     ) -> BOOL;
// }

// pub (crate) fn inject_new_process_iat(dll_path: &str, exe_path: &str, event_history: &mut Vec<String>) -> windows::core::Result<()> {
//     unsafe {
//         let mut _exe_path: Vec<u16> = exe_path.trim_matches('"').encode_utf16().collect();
//         _exe_path.push(0);
//         let exe_path_pwstr = PCWSTR(_exe_path.as_mut_ptr());
// 
//         PROCESS_INFORMATION
//         DetourCreateProcessWithDllExW(exe_path_pwstr, PWSTR::null(), None, None,   )
//     }
// 
//     Ok(())
// }