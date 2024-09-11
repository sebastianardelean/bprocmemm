pub mod process;

#[cfg(target_os = "linux")]
pub mod process_linux;

#[cfg(target_os = "windows")]
pub mod process_windows;
