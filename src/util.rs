use std::path::Path;

use crate::{InjectorConfig, InjectorError};
use libc::pid_t;
use thiserror::Error;

#[derive(Debug)]
pub enum LibraryDependency {
    Allocator,

    #[cfg(target_os = "android")]
    Linker,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Internal injection error `{0}`")]
    Injection(#[from] InjectorError),

    #[error("Process not found! `{0}`")]
    ProcessNotFound(String),

    #[error("Configuration error, unable to find required resources: `{0:?}`")]
    Library(LibraryDependency),

    #[error("General parsing error")]
    Parsing,
}

fn find_mod_map<P: FnMut(&str) -> bool>(
    mut predicate: P,
    pid: pid_t,
) -> Option<proc_maps::MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(pid).ok()?;
    maps.into_iter()
        .filter(|m| m.is_read() && m.is_exec())
        .find(|m| match m.filename() {
            Some(p) => p
                .file_name()
                .and_then(|f| f.to_str())
                .map(&mut predicate)
                .unwrap_or(false),
            None => false,
        })
}

/// Attempts to read ptrace's yama scope for the operating system.
/// If this is restricted, the injector is liable to run into operating system permission issues.
pub fn check_yama_scope() {
    let path = Path::new("/proc/sys/kernel/yama/ptrace_scope");

    let Ok(contents) = std::fs::read_to_string(path) else {
        log::warn!("ptrace's scope yama directive could not be read.");
        return;
    };

    if contents != "0" {
        log::warn!("yama scope is not in permissive scope. errors are liable to happen related to permissions.");
    }
}

#[cfg(target_os = "linux")]
pub fn find_libraries(pid: pid_t) -> Result<InjectorConfig, CliError> {
    // On linux
    // Libc provides the spoof return addr, allocation, and dl functions
    let libc_mod = find_mod_map(|mod_name| mod_name.contains("libc."), pid)
        .ok_or(CliError::Library(LibraryDependency::Allocator))?;
    let path = libc_mod.filename().ok_or(CliError::Parsing)?;
    let path_buf = path.to_owned();

    Ok(InjectorConfig {
        spoof_so_path: path_buf.clone(),
        allocator_so_path: path_buf.clone(),
        linker_so_path: path_buf,
    })
}

#[cfg(target_os = "android")]
pub fn find_libraries(pid: pid_t) -> Result<InjectorConfig, CliError> {
    // On android
    // Libc provides the spoof return addr, allocation
    let libc_mod = find_mod_map(|mod_name| mod_name.contains("libc."), pid)
        .ok_or(CliError::Library(LibraryDependency::Allocator))?;
    let libc_path = libc_mod.filename().ok_or(CliError::Parsing)?;
    let libc_path = libc_path.to_owned();

    // Depending on the android version level the dl function provider changes
    // This is especially true on Emulators.
    let linker_mod = find_mod_map(|mod_name| mod_name.contains("libdl."), pid)
        .ok_or(CliError::Library(LibraryDependency::Linker))?;
    let linker_path = linker_mod.filename().ok_or(CliError::Parsing)?;
    let linker_path = linker_path.to_owned();

    Ok(InjectorConfig {
        spoof_so_path: libc_path.clone(),
        allocater_so_path: libc_path,
        linker_so_path: linker_path,
    })
}
