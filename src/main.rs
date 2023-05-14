use std::path::PathBuf;

use clap::Parser;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use thiserror::Error;
use yaui::{inject_into, InjectorError};

#[derive(Parser, Debug)]
#[clap(
    name = "yaui",
    version = "0.1.0",
    about = "Yet Another Unix Injector with support for Android/Android Emulator i686/x64/arm/aarch64"
)]
struct Args {
    /// Process name to inject into
    #[clap(short, long, value_parser)]
    target: String,

    /// Relative path to payload dll
    #[clap(short, long, value_parser)]
    payload: String,
}

#[derive(Debug)]
enum LibraryDependency {
    Allocator,
    Linker,
    Spoof,
}

#[derive(Debug, Error)]
enum CliError {
    #[error("Internal injection error `{0}`")]
    Injection(#[from] InjectorError),

    #[error("Process not found! `{0}`")]
    ProcessNotFound(String),

    #[error("Configuration error, unable to find required resources: `{0:?}`")]
    Library(LibraryDependency),

    #[error("General parsing error")]
    Parsing,
}

#[derive(Debug)]
struct InjectConfig {
    spoof_so_path: PathBuf,
    allocater_so_path: PathBuf,
    linker_so_path: PathBuf,
}

fn find_mod_map_fuzzy(mod_name: &str, pid: impl Into<libc::pid_t>) -> Option<proc_maps::MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(pid.into()).expect("alive");
    maps.into_iter()
        .filter(|m| m.is_read() && m.is_exec())
        .find(|m| match m.filename() {
            Some(p) => p
                .file_name()
                .and_then(|f| f.to_str())
                .map(|f| f.contains(mod_name))
                .unwrap_or(false),
            None => false,
        })
}

#[cfg(target_os = "linux")]
fn find_libraries(pid: impl Into<libc::pid_t>) -> Result<InjectConfig, CliError> {
    // On linux
    // Libc provides the spoof return addr, allocation, and dl functions
    let libc_mod =
        find_mod_map_fuzzy("libc", pid).ok_or(CliError::Library(LibraryDependency::Allocator))?;
    let path = libc_mod.filename().ok_or(CliError::Parsing)?;
    let path_buf = path.to_owned();

    Ok(InjectConfig {
        spoof_so_path: path_buf.clone(),
        allocater_so_path: path_buf.clone(),
        linker_so_path: path_buf,
    })
}

#[cfg(target_os = "android")]
fn find_libraries(pid: impl Into<libc::pid_t>) -> Result<InjectConfig, CliError> {
    let pid = pid.into();

    // On android
    // Libc provides the spoof return addr, allocation
    let libc_mod =
        find_mod_map_fuzzy("libc.", pid).ok_or(CliError::Library(LibraryDependency::Allocator))?;
    let libc_path = libc_mod.filename().ok_or(CliError::Parsing)?;
    let libc_path = libc_path.to_owned();

    let linker_mod =
        find_mod_map_fuzzy("libdl.", pid).ok_or(CliError::Library(LibraryDependency::Linker))?;
    let linker_path = linker_mod.filename().ok_or(CliError::Parsing)?;
    let linker_path = linker_path.to_owned();

    Ok(InjectConfig {
        spoof_so_path: libc_path.clone(),
        allocater_so_path: libc_path,
        linker_so_path: linker_path,
    })
}

fn main() -> Result<(), CliError> {
    tracing_subscriber::fmt::init();
    tracing::info!("Yaui: Yet another unix injector!");

    let args = Args::parse();
    let process_name = &args.target;
    let payload_location = &args.payload;

    tracing::info!("Target application for injection: {process_name}");
    tracing::info!("Target payload: {payload_location}");

    let mut sys = System::new_all();
    sys.refresh_processes();
    let process = sys
        .processes_by_name(process_name)
        .next()
        .ok_or(CliError::ProcessNotFound(process_name.to_string()))?;

    let traced_pid = process.pid().as_u32() as i32;
    let injector_config = find_libraries(traced_pid)?;
    tracing::warn!("Using injection configs: {injector_config:#?}");

    inject_into(
        payload_location,
        traced_pid,
        injector_config.spoof_so_path,
        injector_config.allocater_so_path,
        injector_config.linker_so_path,
    )?;
    Ok(())
}
