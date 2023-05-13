use clap::Parser;
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
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

fn main() -> Result<(), InjectorError> {
    tracing_subscriber::fmt::init();
    tracing::info!("Yaui: Yet another unix injector!");

    let args = Args::parse();
    let process_name = &args.target;
    let payload_location = &args.payload;

    tracing::info!("Target application for injection: {process_name}");
    tracing::info!("Target payload: {payload_location}");

    let mut sys = System::new_all();
    sys.refresh_processes();
    let process = sys.processes_by_name(process_name).next();
    let process = match process {
        Some(process) => {
            tracing::info!("Identified process by name with pid: {}", process.pid());
            process
        }
        None => {
            tracing::error!("Process does not exist/is not actively running");
            return Err(InjectorError::ProcessNotActive(args.target));
        }
    };

    inject_into(
        payload_location,
        process.pid().as_u32() as i32,
        "/apex/com.android.runtime/lib64/bionic/libc.so",
        "/apex/com.android.runtime/lib64/bionic/libc.so",
        "/apex/com.android.runtime/lib64/bionic/libdl.so",
    )?;
    Ok(())
}
