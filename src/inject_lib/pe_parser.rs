use std::{ ffi::{ c_void, CStr }, fs, slice };

use windows::Win32::System::{
    Diagnostics::Debug::{ IMAGE_NT_HEADERS32, IMAGE_SECTION_HEADER },
    SystemServices::{
        IMAGE_DOS_HEADER,
        IMAGE_DOS_SIGNATURE,
        IMAGE_EXPORT_DIRECTORY,
        IMAGE_NT_SIGNATURE,
    },
    SystemInformation::IMAGE_FILE_MACHINE,
};

pub(crate) fn read_file(file_path: &String) -> Result<Vec<u8>, String> {
    if file_path.is_empty() {
        // event_history.push("empty path".to_string());
        return Err("empty path".to_string());
    }

    let file_bytes = fs
        ::read(file_path)
        .map_err(|e| {
            return format!(
                "Failed to read file {}, error: {}",
                file_path,
                e.to_string()
            ).to_string();
        })?;

    return Ok(file_bytes);
}

pub(crate) fn offset_ptr(base_address: *const c_void, offset: u32) -> *const c_void {
    (base_address as *const u8).wrapping_add(offset as usize) as *const c_void
}

// pub(crate) fn offset_from_base(base_address: *const c_void, address: *const c_void) -> u32 {
//     ((address as usize) - (base_address as usize)) as u32
// }

pub(crate) fn get_containing_section(
    image_nt_headers: *const IMAGE_NT_HEADERS32,
    rva: u32
) -> Option<*const IMAGE_SECTION_HEADER> {
    unsafe {
        let ish = offset_ptr(
            image_nt_headers as *const c_void,
            std::mem::size_of::<IMAGE_NT_HEADERS32>() as u32
        ) as *const IMAGE_SECTION_HEADER;

        for i in 0..(*image_nt_headers).FileHeader.NumberOfSections as usize {
            let section = ish.add(i);
            if
                rva >= (*section).VirtualAddress &&
                rva < (*section).VirtualAddress + (*section).SizeOfRawData
            {
                return Some(section);
            }
        }
        None
    }
}

pub(crate) fn get_image_file_offset(
    image_dos_header: *const IMAGE_DOS_HEADER,
    rva: u32
) -> Option<u32> {
    unsafe {
        let inth = offset_ptr(image_dos_header as *const c_void, (*image_dos_header).e_lfanew as u32) as *const IMAGE_NT_HEADERS32;

        if (*inth).Signature != IMAGE_NT_SIGNATURE {
            return None;
        }

        let section = get_containing_section(inth, rva);
        if section.is_none() {
            return None;
        }

        let section_offset: u32 = rva - (*section.unwrap()).VirtualAddress;
        return Some((*section.unwrap()).PointerToRawData + section_offset);
    }
}

pub(crate) fn get_image_file_ptr(
    image_dos_header: *const IMAGE_DOS_HEADER,
    rva: u32
) -> Option<*const c_void> {
    let file_offset = get_image_file_offset(image_dos_header, rva);
    if file_offset == None {
        return None;
    }

    return Some(offset_ptr(image_dos_header as *const c_void, file_offset.unwrap()));
}

pub(crate) fn get_export_rva(
    image_dos_header: *const IMAGE_DOS_HEADER,
    image_export_dir: *const IMAGE_EXPORT_DIRECTORY,
    function_name: &String
) -> Option<u32> {
    unsafe {
        let addr_of_functions = get_image_file_ptr(
            image_dos_header,
            (*image_export_dir).AddressOfFunctions
        );
        let addr_of_names = get_image_file_ptr(
            image_dos_header,
            (*image_export_dir).AddressOfNames
        );
        let addr_of_name_ordinals = get_image_file_ptr(
            image_dos_header,
            (*image_export_dir).AddressOfNameOrdinals
        );

        if addr_of_functions == None || addr_of_names == None || addr_of_name_ordinals == None {
            return None;
        }

        let number_of_names = (*image_export_dir).NumberOfNames as usize;
        let names_rvas: &[u32] = slice::from_raw_parts(
            addr_of_names.unwrap() as *const u32,
            number_of_names
        );
        let name_ordinals: &[u16] = slice::from_raw_parts(
            addr_of_name_ordinals.unwrap() as *const u16,
            number_of_names
        );
        let function_rvas: &[u32] = slice::from_raw_parts(
            addr_of_functions.unwrap() as *const u32,
            number_of_names
        );

        for (i, &name_rva) in names_rvas.iter().enumerate() {
            let name_ptr = get_image_file_ptr(image_dos_header, name_rva);
            if name_ptr == None {
                continue;
            }

            let name = CStr::from_ptr(name_ptr.unwrap() as *const i8)
                .to_str()
                .ok();
            if name == None {
                continue;
            }

            if name.unwrap() == function_name {
                let ordinal = name_ordinals[i] as usize;
                return if ordinal < function_rvas.len() {
                    Some(function_rvas[ordinal])
                } else {
                    None
                };
            }
        }
        None
    }
}

pub(crate) fn get_export_offset_from_file(
    file_path: &String,
    export_name: &String
) -> Result<u32, String> {
    unsafe {
        let idh_vec = read_file(file_path).map_err(|e| {
            return e;
        })?;

        if idh_vec.len() < 64 {
            return Err(format!("file {} is too small.", file_path));
        }

        let idh = idh_vec.as_ptr() as *const IMAGE_DOS_HEADER;

        if (*idh).e_magic != IMAGE_DOS_SIGNATURE {
            return Err(format!("file {} is not a PE file", file_path));
        }

        let image_nt_headers = offset_ptr(
            idh as *const c_void,
            (*idh).e_lfanew as u32
        ) as *const IMAGE_NT_HEADERS32;

        if (*image_nt_headers).Signature != IMAGE_NT_SIGNATURE {
            return Err(format!("file {} missing nt headers", file_path));
        }

        let optional_header = &(*image_nt_headers).OptionalHeader;
        if optional_header.NumberOfRvaAndSizes < 1 {
            return Err(format!("file {} has no directories.", file_path));
        }

        let export_data_dir = &optional_header.DataDirectory[0 /*IMAGE_DIRECTORY_ENTRY_EXPORT*/];
        if export_data_dir.VirtualAddress == 0 || export_data_dir.Size == 0 {
            return Err(format!("file {} has no exports.", file_path));
        }

        let export_dir = get_image_file_ptr(idh, export_data_dir.VirtualAddress);
        if export_dir.is_none() {
            return Err(format!("failed to get export directory in file {}", file_path));
        }

        return Ok(
            get_export_rva(idh, export_dir.unwrap() as *const IMAGE_EXPORT_DIRECTORY, export_name).unwrap()
        );
    }
}

pub(crate) fn is_pe_file(file_path: &String, event_history: &mut Vec<String>) -> bool {
    if file_path.is_empty() {
        event_history.push("empty path".to_string());
        return false;
    }

    let file_bytes = fs
        ::read(file_path)
        .map_err(|e| {
            event_history.push(
                format!("Failed to read file {}, error: {}", file_path, e.to_string())
            );
            return false;
        })
        .unwrap();

    if file_bytes[0] != b'M' || file_bytes[1] != b'Z' {
        event_history.push(format!("file {} is not MZ", file_path));
        return false;
    }

    if file_bytes.len() < 64 {
        event_history.push(format!("file {} is too small", file_path));
        return false;
    }

    let e_lfanew = u32::from_le_bytes(file_bytes[60..64].try_into().unwrap());

    let pe_header_offset: usize = e_lfanew.try_into().unwrap();

    if file_bytes.len() < pe_header_offset + 4 {
        event_history.push(format!("file {} is too small", file_path));
        return false;
    }
    let pe_signature = u32::from_le_bytes(
        file_bytes[pe_header_offset..pe_header_offset + 4].try_into().unwrap()
    );
    return pe_signature == 0x4550;
}

pub(crate) fn get_pe_file_machine(
    file_path: &String,
    event_history: &mut Vec<String>
) -> IMAGE_FILE_MACHINE {
    // assume the file exists and is PE
    let file_bytes = fs
        ::read(file_path)
        .map_err(|e| {
            event_history.push(
                format!("Failed to read file {}, error: {}", file_path, e.to_string())
            );
            return 0;
        })
        .unwrap();

    let e_lfanew = u32::from_le_bytes(file_bytes[60..64].try_into().unwrap());
    let pe_signature_offset: usize = e_lfanew.try_into().unwrap();

    return IMAGE_FILE_MACHINE(
        u16::from_le_bytes(
            file_bytes[pe_signature_offset + 4..pe_signature_offset + 6].try_into().unwrap()
        )
    );
}
