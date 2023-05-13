use std::path::Path;

use libc::pid_t;
use proc_maps::MapRange;
use ptrace_do::{ProcessIdentifier, RawProcess, TracedProcess};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InjectorError {
    #[error("Payload does not exist: `{0}`")]
    PayloadMissing(String),
    #[error("Payload location unable to be initialized as a CString: `{0}`")]
    PayloadCString(#[from] std::ffi::NulError),
    #[error("Payload location unable to be canonicalized: `{0}`")]
    PayloadCanonicalization(#[from] std::io::Error),
    #[error("Payload location unable to be converted to a str")]
    PayloadConversion,
    #[error("Process is not active: `{0}`")]
    ProcessNotActive(String),

    #[error("Tracer error: `{0}`")]
    Tracer(#[from] ptrace_do::TraceError),

    #[error("Remote procedure not found `{0}`")]
    RemoteProcedure(String),
}

fn find_mod_map_fuzzy(
    mod_name: impl AsRef<str>,
    process: &impl ProcessIdentifier,
) -> Option<MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(process.pid()).expect("alive");
    maps.into_iter().find(|m| match m.filename() {
        Some(p) => p
            .to_str()
            .map(|s| s.contains(mod_name.as_ref()))
            .unwrap_or(false),
        None => false,
    })
}

fn find_mod_map(mod_name: impl AsRef<str>, process: &impl ProcessIdentifier) -> Option<MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(process.pid()).expect("alive");
    maps.into_iter().find(|m| match m.filename() {
        Some(p) => p.to_str().map(|s| s == mod_name.as_ref()).unwrap_or(false),
        None => false,
    })
}

pub fn find_remote_procedure(
    mod_name: &impl AsRef<str>,
    self_process: &impl ProcessIdentifier,
    traced_process: &impl ProcessIdentifier,
    function_address: usize,
) -> Option<usize> {
    let internal_module = find_mod_map_fuzzy(mod_name, self_process)?;
    tracing::info!(
        "Identifed internal range {} ({:?}) at {:X?}",
        mod_name.as_ref(),
        internal_module.filename(),
        internal_module.start()
    );

    let remote_module = find_mod_map_fuzzy(mod_name.as_ref(), traced_process)?;
    tracing::info!(
        "Identifed remote range {} ({:?}) at {:X?}",
        mod_name.as_ref(),
        remote_module.filename(),
        remote_module.start()
    );
    Some(function_address - internal_module.start() + remote_module.start())
}

/// Injects the payload pointed to by `payload_location` into `pid`.
pub fn inject_into(
    payload_location: impl AsRef<Path>,
    pid: impl Into<pid_t>,
) -> Result<(), InjectorError> {
    let payload_location = match std::fs::canonicalize(payload_location) {
        Ok(p) => p,
        Err(e) => return Err(InjectorError::PayloadCanonicalization(e)),
    };
    let pid = pid.into();

    tracing::info!(
        "Injecting Payload: {:#?} into Pid: {}",
        payload_location,
        pid
    );

    let payload_cstring = match std::ffi::CString::new(
        payload_location
            .to_str()
            .ok_or(InjectorError::PayloadConversion)?,
    ) {
        Ok(cstring) => cstring,
        Err(err) => {
            tracing::error!("Unable to create CString from payload absolute path");
            return Err(InjectorError::PayloadCString(err));
        }
    };

    // everyone needs libc!

    // android stuffs: ...

    let libc_path = "/apex/com.android.runtime/lib64/bionic/libc.so";
    // <= 23
    let _linker_path = "/apex/com.android.runtime/bin/linker64";
    let libdl_path = "/apex/com.android.runtime/lib64/bionic/libdl.so";

    let self_process = RawProcess::new(std::process::id() as i32);
    let traced_process = TracedProcess::attach(RawProcess::new(pid))?;
    tracing::info!("Successfully attached to the process");

    let mmap_remote_procedure = find_remote_procedure(
        &libc_path,
        &self_process,
        &traced_process,
        libc::mmap as usize,
    )
    .ok_or(InjectorError::RemoteProcedure(libc_path.to_owned()))?;
    tracing::info!("Identified remote mmap procedure at {mmap_remote_procedure:X?}");

    let dlopen_remote_procedure = find_remote_procedure(
        &libdl_path,
        &self_process,
        &traced_process,
        libc::dlopen as usize,
    )
    .ok_or(InjectorError::RemoteProcedure(libdl_path.to_owned()))?;

    // return address stuff if needed....
    let libc_base_addr = find_mod_map(libc_path, &traced_process)
        .ok_or(InjectorError::RemoteProcedure(libdl_path.to_owned()))?
        .start();
    tracing::info!("Identified libc base address for bionic namespace: {libc_base_addr:X?}");

    let frame = traced_process.next_frame()?;
    tracing::info!("Successfully waited for a frame");

    let mmap_params: [usize; 6] = [
        0,
        0x3000,
        (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as usize,
        (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as usize,
        0,
        0,
    ];
    let (regs, mut frame) =
        frame.invoke_remote(mmap_remote_procedure, libc_base_addr, &mmap_params)?;
    tracing::info!("Successfully executed remote mmap function");
    tracing::info!("The return value was {:X?}", regs.return_value());
    let allocated_memory_addr = regs.return_value();

    let _memory = frame.write_memory(allocated_memory_addr, payload_cstring.as_bytes())?;
    tracing::info!(
        "Successfully wrote payload location to {:X?}",
        regs.return_value()
    );

    let dlopen_params: [usize; 2] = [
        allocated_memory_addr, // addr to a null terminated cstring of the target dl to open
        (libc::RTLD_NOW | libc::RTLD_GLOBAL) as usize, // the flaps
    ];
    let (regs, _frame) =
        frame.invoke_remote(dlopen_remote_procedure, libc_base_addr, &dlopen_params)?;
    tracing::info!("Successfully executed remote dlopen function");
    tracing::info!("The return value was {:X?}", regs.return_value());

    // drop frame

    Ok(())
}
