use std::{ffi::c_void, mem, ptr};
use windows::core::{Owned, PCWSTR};
use windows::Win32::Foundation::{SetLastError, BOOLEAN, GENERIC_READ, HANDLE, WIN32_ERROR};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::Diagnostics::Debug::{
    ImageDirectoryEntryToDataEx, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_SECTION_HEADER,
};
use windows::Win32::System::Memory::{CreateFileMappingW, MapViewOfFile, VirtualQueryEx, FILE_MAP_READ, MEMORY_BASIC_INFORMATION, MEMORY_MAPPED_VIEW_ADDRESS, MEM_FREE, PAGE_READONLY};
use windows::Win32::System::SystemInformation::{IMAGE_FILE_MACHINE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_UNKNOWN};
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;
use windows::Win32::System::Threading::{GetProcessId, IsWow64Process2};

pub(crate) fn find_first_ordinal(dll_file_path: &str) -> windows::core::Result<u16> {
    unsafe {
        let mut _dll_file_path: Vec<u16> = dll_file_path.trim_matches('"').encode_utf16().collect();
        _dll_file_path.push(0);
        let dll_file_path_pcwstr = PCWSTR(_dll_file_path.as_mut_ptr());
        let h_file = Owned::new(
            CreateFileW(
                dll_file_path_pcwstr,
                GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .map_err(|e| e)?,
        );

        let h_mapping = Owned::new(
            CreateFileMappingW(*h_file, None, PAGE_READONLY, 0, 0, PCWSTR::null())
                .map_err(|e| e)?,
        );

        let base_address = MapViewOfFile(*h_mapping, FILE_MAP_READ, 0, 0, 0);
        if (base_address == MEMORY_MAPPED_VIEW_ADDRESS::default()) {
            return Err(windows::core::Error::from_win32());
        }

        let mut section_header: *mut IMAGE_SECTION_HEADER = ptr::null_mut();
        let mut table_size: u32 = 0;
        let export_dir = ImageDirectoryEntryToDataEx(
            base_address.Value as *const c_void,
            BOOLEAN(0),
            IMAGE_DIRECTORY_ENTRY_EXPORT,
            &mut table_size,
            Some(&mut section_header),
        ) as *const IMAGE_EXPORT_DIRECTORY;

        if export_dir.is_null() {
            SetLastError(WIN32_ERROR(87));
            return Err(windows::core::Error::from_win32());
        }

        let mut ordinal: u16 = 0;
        if (*export_dir).NumberOfFunctions > 0 {
            ordinal += (*export_dir).Base as u16;
        }

        return Ok(ordinal);
    }
}

pub(crate) fn get_process_machine(h_proc: HANDLE, event_history: &mut Vec<String>) -> IMAGE_FILE_MACHINE {
    unsafe {
        let mut process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        let mut native_machine = IMAGE_FILE_MACHINE_UNKNOWN;
        let result = IsWow64Process2(h_proc, &mut process_machine, Some(&mut native_machine));
        if result.is_err() {
            event_history.push(
                format!(
                    "Failed to check process machine type {}: {}",
                    GetProcessId(h_proc),
                    result.unwrap_err()
                )
            );
        }
        return if process_machine != IMAGE_FILE_MACHINE_UNKNOWN { process_machine } else { native_machine };
    }
}

pub(crate) fn alloc_near_base(h_process: HANDLE, module: *mut u8, size: u32, event_history: &mut Vec<String>) -> windows::core::Result<*mut u8>  {
    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();
        let last = module;
        let mut stop = false;
        while !stop {
            mbi = MEMORY_BASIC_INFORMATION::default();
            if VirtualQueryEx(h_process, Some(last as *const c_void), &mut mbi, mem::size_of_val(&mbi)) == 0 {
                return Err(windows::core::Error::from_win32());
            }

            if mbi.RegionSize & 0xfff == 0xfff {
                SetLastError(WIN32_ERROR(87));
                return Err(windows::core::Error::from_win32());
            }

            if mbi.State != MEM_FREE {
                continue;
            }

            let mut address = if mbi.BaseAddress as usize > module as usize { mbi.BaseAddress as *mut u8} else { module };
            let round_up: usize = 0x999;
            address = ((address as usize + round_up) & !round_up) as *mut u8;

            if get_process_machine(h_process, event_history) == IMAGE_FILE_MACHINE_AMD64 {
                const GB4: usize = ((1_usize << 32) - 1);
                let offset = (address.add(size as usize - 1) as usize).wrapping_sub(module as usize);
                if offset > GB4 {
                    event_history.push(format!(
                        "find_and_allocate_near_base(1) failing due to distance >4GB {:p}",
                        address
                    ));
                    SetLastError(WIN32_ERROR(87));
                    return Err(windows::core::Error::from_win32());
                }
            }


        }
    }
    Ok((0 as *mut u8))
}
