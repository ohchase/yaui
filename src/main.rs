use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use thiserror::Error;
use yaui::{eject, inject, InjectorError};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, ValueEnum)]
enum Mode {
    Inject,
    Eject,
}

#[derive(Parser, Debug)]
#[clap(
    name = "yaui",
    version = "0.1.0",
    about = "Yet Another Unix Injector with support for Android/Android Emulator i686/x64/arm/aarch64"
)]
struct Args {
    /// Optional Process name to inject into
    /// If you set the target name, you must not set the pid
    #[clap(short, long, value_parser)]
    target: Option<String>,

    /// Optional Process pid to inject into
    /// If you set the pid, you must not set the target name.
    #[clap(long, value_parser)]
    pid: Option<i32>,

    /// Relative path to payload dll
    #[clap(short, long, value_parser)]
    payload: String,

    /// Mode, inject versus eject. Default is inject as expected
    #[clap(short, long, value_enum, default_value_t = Mode::Inject)]
    mode: Mode,
}

#[derive(Debug)]
enum LibraryDependency {
    Allocator,

    #[cfg(target_os = "android")]
    Linker,
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
        find_mod_map_fuzzy("libc.", pid).ok_or(CliError::Library(LibraryDependency::Allocator))?;
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

    // Depending on the android version level the dl function provider changes
    // This is especially true on Emulators.
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

fn init_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    let stdout_log = tracing_subscriber::fmt::layer().pretty();
    let subscriber = tracing_subscriber::Registry::default().with(stdout_log);

    // Upgrade logger on android
    #[cfg(target_os = "android")]
    let subscriber = {
        let android_layer = tracing_android::layer("yaui")
            .expect("Unable to create android tracing layer");
        subscriber.with(android_layer)
    };

    tracing::subscriber::set_global_default(subscriber).expect("Unable to set global subscriber");
}

fn main() -> Result<(), CliError> {
    init_logging();
    tracing::info!("Yaui: Yet another unix injector!");

    let args = Args::parse();
    let payload_location = &args.payload;
    tracing::info!("Target payload: {payload_location}");

    let process_pid = match (args.target, args.pid) {
        (Some(_proc_name), Some(_pid)) => {
            tracing::error!("--target and --pid are exclusive, you must specify one or the other!");
            return Err(CliError::Parsing);
        }
        (None, Some(pid)) => {
            tracing::info!("Target pid for injection: {pid}");
            pid
        }
        (Some(process_name), None) => {
            tracing::info!("Target application for injection: {process_name}");
            let mut sys = System::new_all();
            sys.refresh_processes();
            let process = sys
                .processes_by_name(&process_name)
                .next()
                .ok_or(CliError::ProcessNotFound(process_name.to_string()))?;
            let pid = process.pid().as_u32() as i32;
            tracing::info!("Target pid successfully found by name {pid}");
            pid
        }
        (None, None) => args.pid.expect("Must specify either --target or --pid."),
    };

    let injector_config = find_libraries(process_pid)?;
    tracing::info!("Using configs: {injector_config:#?}");

    match args.mode {
        Mode::Inject => {
            inject(
                payload_location,
                process_pid,
                injector_config.spoof_so_path,
                injector_config.allocater_so_path,
                injector_config.linker_so_path,
            )?;
        }
        Mode::Eject => {
            eject(
                payload_location,
                process_pid,
                injector_config.spoof_so_path,
                injector_config.allocater_so_path,
                injector_config.linker_so_path,
            )?;
        }
    }
    Ok(())
}
