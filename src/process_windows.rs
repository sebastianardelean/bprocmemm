// src/windows_proc.rs
#[cfg(target_os = "windows")]
pub mod process_windows {

    use crate::process::process::*;
    use core::panic;
    use std::ffi::{c_void, CStr};
    use std::os::raw::c_char;
    use windows::core::PSTR;

    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;

    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualProtectEx, MEM_RESERVE, PAGE_EXECUTE, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_NOCACHE,
        PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOMBINE, PAGE_WRITECOPY,
    };
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::Diagnostics::Debug::ReadProcessMemory,
        System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT},
        System::Threading::*,
    };

    pub fn convert_ppf_to_string(protection: PAGE_PROTECTION_FLAGS) -> String {
        let protection_flags_to_string = |flags: PAGE_PROTECTION_FLAGS| -> String {
            let mut protection_str: Vec<&str> = Vec::new();
            if flags & PAGE_NOACCESS == PAGE_NOACCESS {
                protection_str.push("NOACCESS");
            }
            if flags & PAGE_READONLY == PAGE_READONLY {
                protection_str.push("READONLY");
            }
            if flags & PAGE_READWRITE == PAGE_READWRITE {
                protection_str.push("READWRITE");
            }
            if flags & PAGE_WRITECOPY == PAGE_WRITECOPY {
                protection_str.push("WRITECOPY");
            }
            if flags & PAGE_EXECUTE == PAGE_EXECUTE {
                protection_str.push("EXECUTE");
            }
            if flags & PAGE_EXECUTE_READ == PAGE_EXECUTE_READ {
                protection_str.push("EXECUTE_READ");
            }
            if flags & PAGE_EXECUTE_READWRITE == PAGE_EXECUTE_READWRITE {
                protection_str.push("EXECUTE_READWRITE");
            }
            if flags & PAGE_EXECUTE_WRITECOPY == PAGE_EXECUTE_WRITECOPY {
                protection_str.push("EXECUTE_WRITECOPY");
            }
            if flags & PAGE_GUARD == PAGE_GUARD {
                protection_str.push("GUARD");
            }
            if flags & PAGE_NOCACHE == PAGE_NOCACHE {
                protection_str.push("NOCACHE");
            }
            if flags & PAGE_WRITECOMBINE == PAGE_WRITECOMBINE {
                protection_str.push("WRITECOMBINE");
            }

            if protection_str.is_empty() {
                protection_str.push("UNKNOWN");
            }

            protection_str.join(" | ")
        };
        protection_flags_to_string(protection)
    }

    pub fn close_handler(handle: HANDLE) {
        unsafe {
            match CloseHandle(handle) {
                Ok(_) => {}
                Err(_) => {
                    panic!("Error on close process handler!")
                }
            }
        }
    }

    pub fn get_process(pid: u32) -> (String, HANDLE) {
        let handle = unsafe {
            match OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                false,
                pid,
            ) {
                Ok(handler) => handler,
                Err(_) => {
                    panic!("Error opening process");
                }
            }
        };
        let mut proc_name = vec![0u8; 1024];
        let mut proc_name_size = 1024;

        unsafe {
            match QueryFullProcessImageNameA(
                handle,
                PROCESS_NAME_WIN32,
                PSTR(proc_name.as_mut_ptr()),
                &mut proc_name_size,
            ) {
                Ok(_) => {}
                Err(_) => {
                    panic!("Could not get process name!")
                }
            }
        };

        let c_str = unsafe { CStr::from_ptr(proc_name.as_ptr() as *const c_char) };
        let name = c_str.to_string_lossy().into_owned();
        (name, handle)
    }

    pub fn read_memory_regions(handle: HANDLE) -> Vec<MemoryRegion> {
        let mut memory_regions: Vec<MemoryRegion> = Vec::new();

        let mut memory_info = MEMORY_BASIC_INFORMATION::default();
        let mut addr: Option<*const c_void> = Some(0 as *const c_void);

        unsafe {
            while VirtualQueryEx(
                handle,
                addr,
                &mut memory_info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                if memory_info.State == MEM_COMMIT {
                    memory_regions.push(MemoryRegion {
                        address: memory_info.BaseAddress as usize,
                        size: memory_info.RegionSize,
                        permissions: convert_ppf_to_string(memory_info.Protect),
                    });
                }
                addr = Some(
                    (memory_info.BaseAddress as usize + memory_info.RegionSize) as *const c_void,
                );
            }
        }
        memory_regions
    }

    pub fn read_memory_region(
        handle: HANDLE,
        memory_reg: MemoryRegion,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut mem = vec![0u8; memory_reg.size];

        let result = unsafe {
            ReadProcessMemory(
                handle,
                memory_reg.address as *const c_void,
                mem.as_mut_ptr() as *mut _,
                mem.len(),
                Some(0 as *mut usize),
            )
        };
        match result {
            Ok(_) => Ok(mem),
            Err(error) => Err(error.into()),
        }
    }

    pub fn read_address(
        handle: HANDLE,
        address: usize,
        size: usize,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut memory_data = vec![0u8; size];
        let result = unsafe {
            ReadProcessMemory(
                handle,
                address as *const c_void,
                memory_data.as_mut_ptr() as *mut _,
                memory_data.len(),
                Some(0 as *mut usize),
            )
        };
        match result {
            Ok(_) => Ok(memory_data),
            Err(error) => Err(error.into()),
        }
    }

    pub fn write_region(
        handle: HANDLE,
        memory_reg: MemoryRegion,
        data: &[u8],
    ) -> Result<(), std::io::Error> {
        assert!(data.len() <= memory_reg.size);
        let result = unsafe {
            WriteProcessMemory(
                handle,
                memory_reg.address as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(0 as *mut usize),
            )
        };
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn write_address(
        handle: HANDLE,
        address: usize,
        data: &[u8],
    ) -> Result<(), std::io::Error> {
        let result = unsafe {
            WriteProcessMemory(
                handle,
                address as *const c_void,
                data.as_ptr() as *const c_void,
                data.len(),
                Some(0 as *mut usize),
            )
        };
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub fn allocate_memory(
        handle: HANDLE,
        address: usize,
        size: usize,
    ) -> Result<MemoryRegion, std::io::Error> {
        let result = unsafe {
            VirtualAllocEx(
                handle,
                Some(address as *const c_void),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if result.is_null() {
            return Err(windows::core::Error::from_win32().into());
        } else {
            Ok(MemoryRegion {
                address: result as usize,
                size: size,
                permissions: convert_ppf_to_string(PAGE_EXECUTE_READWRITE),
            })
        }
    }

    pub fn set_protection(
        handle: HANDLE,
        memory_reg: MemoryRegion,
        protection_string: String,
    ) -> Result<(), std::io::Error> {
        let map_protection_str_to_flags = |protection_string: String| -> PAGE_PROTECTION_FLAGS {
            let mut flags: PAGE_PROTECTION_FLAGS = PAGE_PROTECTION_FLAGS(0u32);
            for part in protection_string.split(" | ") {
                match part {
                    "NOACCESS" => flags |= PAGE_NOACCESS,
                    "READONLY" => flags |= PAGE_READONLY,
                    "READWRITE" => flags |= PAGE_READWRITE,
                    "WRITECOPY" => flags |= PAGE_WRITECOPY,
                    "EXECUTE" => flags |= PAGE_EXECUTE,
                    "EXECUTE_READ" => flags |= PAGE_EXECUTE_READ,
                    "EXECUTE_READWRITE" => flags |= PAGE_EXECUTE_READWRITE,
                    "EXECUTE_WRITECOPY" => flags |= PAGE_EXECUTE_WRITECOPY,
                    "GUARD" => flags |= PAGE_GUARD,
                    "NOCACHE" => flags |= PAGE_NOCACHE,
                    "WRITECOMBINE" => flags |= PAGE_WRITECOMBINE,
                    _ => {}
                }
            }
            flags
        };

        let mut old_protection: PAGE_PROTECTION_FLAGS = PAGE_NOACCESS; //old protection show be read from mem struct
        let new_protection: PAGE_PROTECTION_FLAGS = map_protection_str_to_flags(protection_string);
        let result = unsafe {
            VirtualProtectEx(
                handle,
                memory_reg.address as *const c_void,
                memory_reg.size,
                new_protection,
                &mut old_protection as *mut PAGE_PROTECTION_FLAGS,
            )
        };
        match result {
            Ok(_) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}
