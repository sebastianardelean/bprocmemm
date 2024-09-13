pub mod process {

    use std::fmt;

    #[cfg(target_os = "linux")]
    use std::io;

    #[cfg(target_os = "linux")]
    use crate::process_linux::*;

    #[cfg(target_os = "windows")]
    use crate::process_windows::*;

    #[cfg(target_os = "windows")]
    use windows::Win32::Foundation::HANDLE;

    #[cfg(target_os = "linux")]
    pub type HANDLE = u64; // Stub for Linux

    #[derive(Clone, Debug)]
    pub struct MemoryRegion {
        pub address: usize,
        pub size: usize,
        pub permissions: String,
    }

    impl MemoryRegion {
        pub fn new(address: usize, size: usize, permissions: String) -> MemoryRegion {
            MemoryRegion {
                address,
                size,
                permissions,
            }
        }

        pub fn show_memory_regions(&self) -> String {
            format!(
                "Base address: {:#x} Size: {} Permission: {}",
                self.address, self.size, self.permissions
            )
        }
    }

    #[derive(Debug)]
    pub enum ProcessError {
        MissingOptionError(String),
    }

    // Implement std::fmt::Display for ProcessError
    impl fmt::Display for ProcessError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ProcessError::MissingOptionError(msg) => write!(f, "Error Missing Option: {}", msg),
            }
        }
    }

    // Implement std::error::Error for MyError
    impl std::error::Error for ProcessError {}

    #[derive(Debug, Default)]
    pub struct Proc {
        pid: u32,
        name: String,
        handle: HANDLE,
    }

    impl Drop for Proc {
        fn drop(&mut self) {
            #[cfg(target_os = "windows")]
            {
                process_windows::close_handler(self.handle);
            }
        }
    }

    impl Proc {
        pub fn new(pid: u32) -> Proc {
            #[cfg(target_os = "linux")]
            {
                Proc {
                    pid: pid,
                    name: process_linux::get_process(pid as i32),
                    handle: pid as u64,
                }
            }
            #[cfg(target_os = "windows")]
            {
                let (name, handle) = process_windows::get_process(pid);
                Proc {
                    pid: pid,
                    name: name,
                    handle: handle,
                }
            }
        }

        pub fn get_pid(&self) -> u32 {
            #[cfg(target_os = "linux")]
            {
                assert!(self.pid as u64 == self.handle);
            }
            self.pid
        }

        pub fn get_name(&self) -> String {
            self.name.clone()
        }

        pub fn read_memory_regions(&self) -> Vec<MemoryRegion> {
            #[cfg(target_os = "linux")]
            {
                process_linux::read_memory_regions(self.pid as i32)
            }
            #[cfg(target_os = "windows")]
            {
                process_windows::read_memory_regions(self.handle)
            }
        }

        pub fn read_memory_region(
            &self,
            memory_reg: MemoryRegion,
        ) -> Result<Vec<u8>, std::io::Error> {
            #[cfg(target_os = "linux")]
            {
                process_linux::read_memory_region(self.pid as i32, memory_reg)
            }
            #[cfg(target_os = "windows")]
            {
                process_windows::read_memory_region(self.handle, memory_reg)
            }
        }

        pub fn read_address(&self, address: usize, size: usize) -> Result<Vec<u8>, std::io::Error> {
            #[cfg(target_os = "linux")]
            {
                process_linux::read_address(self.pid as i32, address, size)
            }
            #[cfg(target_os = "windows")]
            {
                process_windows::read_address(self.handle, address, size)
            }
        }

        pub fn write_region(
            &self,
            memory_reg: MemoryRegion,
            data: &[u8],
        ) -> Result<(), std::io::Error> {
            assert!(data.len() <= memory_reg.size);

            #[cfg(target_os = "linux")]
            {
                process_linux::write_region(self.pid as i32, memory_reg, data)
            }
            #[cfg(target_os = "windows")]
            {
                process_windows::write_region(self.handle, memory_reg, data)
            }
        }

        pub fn write_address(&self, address: usize, data: &[u8]) -> Result<(), std::io::Error> {
            #[cfg(target_os = "linux")]
            {
                process_linux::write_address(self.pid as i32, address, data)
            }
            #[cfg(target_os = "windows")]
            {
                process_windows::write_address(self.handle, address, data)
            }
        }
        pub fn allocate_memory(
            &self,
            address: usize,
            size: usize,
        ) -> Result<MemoryRegion, std::io::Error> {
            #[cfg(target_os = "linux")]
            {
                let _ = address;
                let _ = size;
                eprintln!("Option not available on Linux");
                let custom_error =
                    ProcessError::MissingOptionError("Something went wrong".to_string());
                return Err(io::Error::new(io::ErrorKind::Other, custom_error));
            }
            #[cfg(target_os = "windows")]
            {
                process_windows::allocate_memory(self.handle, address, size)
            }
        }

        pub fn set_protection(
            &self,
            memory_reg: MemoryRegion,
            protection_string: String,
        ) -> Result<(), std::io::Error> {
            #[cfg(target_os = "linux")]
            {
                let _ = memory_reg;
                let _ = protection_string;
                eprintln!("Option not available on Linux");
                let custom_error =
                    ProcessError::MissingOptionError("Something went wrong".to_string());
                return Err(io::Error::new(io::ErrorKind::Other, custom_error));
            }
            #[cfg(target_os = "windows")]
            {
                process_windows::set_protection(self.handle, memory_reg, protection_string)
            }
        }
    }
}
