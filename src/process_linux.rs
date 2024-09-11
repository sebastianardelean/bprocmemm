// src/linux_proc.rs

#[cfg(target_os = "linux")]
pub mod process_linux {
    use crate::process::process::*;
    use core::panic;
    use libc::{iovec, process_vm_readv, process_vm_writev};
    use std::{fs, io::Error};

    pub fn get_process(pid: i32) -> String {
        let file_path: String = format!("/proc/{}/status", pid);

        let proc_status_content = fs::read_to_string(file_path).unwrap_or_else(|err| {
            panic!("File not found: {}", err);
        });

        let extract_name = |proc_status_content: String| -> String {
            let name_line: String = proc_status_content.lines().next().unwrap_or("").to_string();
            if let Some(tab_index) = name_line.find('\t') {
                name_line[(tab_index + 1)..].to_string()
            } else {
                String::from("")
            }
        };
        extract_name(proc_status_content)
    }

    pub fn read_memory_regions(pid: i32) -> Vec<MemoryRegion> {
        let mut memory_regions: Vec<MemoryRegion> = Vec::new();
        let file_path: String = format!("/proc/{}/maps", pid);

        let maps_content = fs::read_to_string(file_path).unwrap_or_else(|err| {
            panic!("File not found: {}", err);
        });

        for line in maps_content.lines().filter(|line| !line.trim().is_empty()) {
            let mut parts = line.split_whitespace();

            // Extract the first two parts (addresses and permissions)
            if let (Some(addresses), Some(permissions)) = (parts.next(), parts.next()) {
                // Split the addresses into start and end
                let mut addr_parts = addresses.split('-');
                if let (Some(start), Some(end)) = (addr_parts.next(), addr_parts.next()) {
                    // Parse the start and end addresses as hexadecimal numbers
                    if let (Ok(start_addr), Ok(end_addr)) = (
                        usize::from_str_radix(start, 16),
                        usize::from_str_radix(end, 16),
                    ) {
                        // Calculate the memory size
                        let size = end_addr - start_addr;

                        memory_regions.push(MemoryRegion {
                            address: start_addr,
                            size: size,
                            permissions: permissions.to_string(),
                        });
                    }
                }
            }
        }
        memory_regions
    }

    pub fn read_memory_region(
        pid: i32,
        memory_reg: MemoryRegion,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut mem = vec![0u8; memory_reg.size];

        let local_iov = iovec {
            iov_base: mem.as_mut_ptr() as *mut libc::c_void,
            iov_len: memory_reg.size,
        };

        // Prepare remote buffer info (not used, but must be provided)
        let remote_iov = iovec {
            iov_base: memory_reg.address as *mut libc::c_void,
            iov_len: memory_reg.size,
        };

        // Perform the read operation
        let result = unsafe {
            process_vm_readv(
                pid,
                &local_iov,
                1, // Number of local iovec structures
                &remote_iov,
                1, // Number of remote iovec structures (0 means no remote iovecs)
                0, // Flags (0 for default behavior)
            )
        };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        Ok(mem)
    }

    pub fn read_address(pid: i32, address: usize, size: usize) -> Result<Vec<u8>, std::io::Error> {
        let mut mem = vec![0u8; size];

        let local_iov = iovec {
            iov_base: mem.as_mut_ptr() as *mut libc::c_void,
            iov_len: size,
        };

        // Prepare remote buffer info (not used, but must be provided)
        let remote_iov = iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: size,
        };

        // Perform the read operation
        let result = unsafe {
            process_vm_readv(
                pid,
                &local_iov,
                1, // Number of local iovec structures
                &remote_iov,
                1, // Number of remote iovec structures (0 means no remote iovecs)
                0, // Flags (0 for default behavior)
            )
        };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        Ok(mem)
    }

    pub fn write_region(
        pid: i32,
        memory_reg: MemoryRegion,
        data: &[u8],
    ) -> Result<(), std::io::Error> {
        let local_iov = iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };

        // Prepare remote buffer info (not used, but must be provided)
        let remote_iov = iovec {
            iov_base: memory_reg.address as *mut libc::c_void,
            iov_len: memory_reg.size,
        };

        // Perform the read operation
        let result = unsafe {
            process_vm_writev(
                pid,
                &local_iov,
                1, // Number of local iovec structures
                &remote_iov,
                1, // Number of remote iovec structures (0 means no remote iovecs)
                0, // Flags (0 for default behavior)
            )
        };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }

    pub fn write_address(pid: i32, address: usize, data: &[u8]) -> Result<(), std::io::Error> {
        let local_iov = iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };

        // Prepare remote buffer info (not used, but must be provided)
        let remote_iov = iovec {
            iov_base: address as *mut libc::c_void,
            iov_len: data.len(),
        };

        // Perform the read operation
        let result = unsafe {
            process_vm_writev(
                pid,
                &local_iov,
                1, // Number of local iovec structures
                &remote_iov,
                1, // Number of remote iovec structures (0 means no remote iovecs)
                0, // Flags (0 for default behavior)
            )
        };
        if result == -1 {
            return Err(Error::last_os_error());
        }
        Ok(())
    }
}
