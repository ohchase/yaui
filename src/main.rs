use clap::Parser;
use clap_verbosity_flag::Verbosity;
use std::path::PathBuf;
use sysinfo::System;
use yaui::{
    inject_into,
    util::{check_yama_scope, find_libraries, CliError},
};

#[derive(Parser, Debug)]
#[clap(
    name = "yaui",
    about = "Yet Another Unix Injector with support for Android/Android Emulator i686/x64/arm/aarch64"
)]
struct Args {
    /// Primary process pid targeting functionality
    #[clap(short, long, value_parser)]
    target_pid: Option<i32>,

    /// Secondary process name targeting functionality
    #[clap(long, value_parser)]
    target_name: Option<String>,

    /// Relative path to payload dll
    #[clap(short, long)]
    payload: PathBuf,

    #[command(flatten)]
    verbose: Verbosity,
}

fn main() -> Result<(), CliError> {
    let args = Args::parse();
    env_logger::builder()
        .filter_level(args.verbose.log_level_filter())
        .init();

    check_yama_scope();

    let payload_location = &args.payload;
    log::info!("Target payload: {payload_location:?}");

    let process_pid = match (args.target_name, args.target_pid) {
        (Some(_proc_name), Some(_pid)) => {
            log::error!("--target and --pid are exclusive, you must specify one or the other!");
            return Err(CliError::Parsing);
        }
        (None, Some(pid)) => {
            log::info!("Target pid for injection: {pid}");
            pid
        }
        (Some(process_name), None) => {
            log::info!("Target application for injection: {process_name}");
            let mut sys = System::new_all();
            sys.refresh_all();

            let process = sys
                .processes_by_name(std::ffi::OsStr::new(&process_name))
                .next()
                .ok_or(CliError::ProcessNotFound(process_name.clone()))?;
            let pid = process.pid().as_u32() as i32;
            log::info!("Target pid successfully found by name {pid}");
            pid
        }
        (None, None) => args
            .target_pid
            .expect("Must specify either --target or --pid."),
    };

    let injector_config = find_libraries(process_pid)?;
    log::warn!("Using injection configs: {injector_config:?}");
    inject_into(payload_location, process_pid, injector_config)?;
    Ok(())
}
