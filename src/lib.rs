use std::path::{Path, PathBuf};

use libc::pid_t;
use proc_maps::MapRange;
use ptrace_do::{ProcessIdentifier, RawProcess, TracedProcess};
use thiserror::Error;

/// Access to utility functions related to resolving dependencies and checking security features
pub mod util;

/// A minimal struct for representing all the required information to attempt inject.
#[derive(Debug)]
pub struct InjectorConfig {
    /// We need to spoof a return address when calling libc's dlopen.
    pub spoof_so_path: PathBuf,

    /// We need to allocate memory in the target application
    pub allocator_so_path: PathBuf,

    /// We need to call libc's dlopen
    pub linker_so_path: PathBuf,
}

/// Error class representing all possible errors that can occur during yaui's injection.
#[derive(Error, Debug)]
pub enum InjectorError {
    #[error("Payload does not exist: `{0}`")]
    PayloadMissing(PathBuf),

    #[error("Payload location unable to be initialized as a CString: `{0}`")]
    PayloadCString(#[from] std::ffi::NulError),

    #[error("Payload location unable to be canonicalized: `{0}`")]
    PayloadCanonicalization(std::io::Error),

    #[error("Payload location unable to be converted to a str")]
    PayloadConversion,

    #[error("Process is not active: `{0}`")]
    ProcessNotActive(String),

    #[error("Tracer error: `{0}`")]
    Tracer(#[from] ptrace_do::TraceError),

    #[error("Remote procedure failed `{0}`")]
    ExecuteRemoteProcedure(String),

    #[error("Unable to read the pid: `{0}` proc maps")]
    ProcMaps(std::io::Error),

    #[error("Unable to find process module with name `{0}`")]
    ProcMapFind(PathBuf),
}

/// Internal helper function to resolve a module's start address by pid
fn find_mod_map(mod_path: &Path, process_pid: pid_t) -> Result<MapRange, InjectorError> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(process_pid).map_err(InjectorError::ProcMaps)?;
    maps.into_iter()
        .find(|m| match m.filename() {
            Some(p) => p == mod_path,
            None => false,
        })
        .ok_or(InjectorError::ProcMapFind(mod_path.to_path_buf()))
}

/// Resolves (*calculates*) the address of a function in the remote process.
/// Crawls the system proc maps (/procs/{pid}/maps) of our own process and the remote process.
/// Assumes {mod_name}'s target function is mapped with the same offset in ourself and the remote process.
/// In turn the remote process is at {function_address} - {self_mod_base} + {remote_mod_base}.
fn resolve_remote_proc(
    mod_name: &Path,
    self_process: pid_t,
    traced_process: pid_t,
    function_address: usize,
) -> Result<usize, InjectorError> {
    let internal_module = find_mod_map(mod_name, self_process)?;
    log::debug!(
        "Identifed internal range {mod_name:?} at {:X?}",
        internal_module.start()
    );

    let remote_module = find_mod_map(mod_name, traced_process)?;
    log::debug!(
        "Identifed remote range {mod_name:?} at {:X?}",
        remote_module.start()
    );
    Ok(function_address - internal_module.start() + remote_module.start())
}

/// Injects the payload pointed to by `payload_location` into `pid`.
/// Spoof path specifies a loaded module to feign calling from where the name is `spoof_so_path`
/// Memory allocation is expected to be provided by `allocater_so_path`: libc::mmap
/// Dl/So handling is expected to be provided by `linker_so_path`: libc::dlopen , libc::dlclose, libc::dlerror
pub fn inject_into(
    payload_location: impl AsRef<Path>,
    target_pid: pid_t,
    config: InjectorConfig,
) -> Result<(), InjectorError> {
    let payload_location =
        std::fs::canonicalize(payload_location).map_err(InjectorError::PayloadCanonicalization)?;
    log::info!("Injecting Payload: {payload_location:?} into Pid: {target_pid}");

    if !payload_location.exists() {
        return Err(InjectorError::PayloadMissing(payload_location));
    }

    let payload_cstring = std::ffi::CString::new(
        payload_location
            .to_str()
            .ok_or(InjectorError::PayloadConversion)?,
    )
    .map_err(InjectorError::PayloadCString)?;

    let self_process = RawProcess::new(std::process::id() as i32);
    let traced_process = RawProcess::new(target_pid);
    let traced_process = TracedProcess::attach(traced_process)?;
    log::info!("Successfully attached to the remote process");

    let mmap_remote_procedure = resolve_remote_proc(
        &config.allocator_so_path,
        self_process.pid(),
        traced_process.pid(),
        libc::mmap as usize,
    )?;
    log::info!("Identified remote mmap procedure at {mmap_remote_procedure:X?}");

    let dlerror_remote_procedure = resolve_remote_proc(
        &config.linker_so_path,
        self_process.pid(),
        traced_process.pid(),
        libc::dlerror as usize,
    )?;
    log::info!("Identified remote dlerror procedure at {dlerror_remote_procedure:X?}");

    let dlopen_remote_procedure = resolve_remote_proc(
        &config.linker_so_path,
        self_process.pid(),
        traced_process.pid(),
        libc::dlopen as usize,
    )?;
    log::info!("Identified remote dlopen procedure at {dlopen_remote_procedure:X?}");

    // return address stuff if needed....
    let spoof_addr = find_mod_map(&config.spoof_so_path, traced_process.pid())?.start();
    log::info!("Identified spoof module base address for return address: {spoof_addr:X?}");

    let frame = traced_process.next_frame()?;
    log::info!("Successfully waited for the mmap frame");

    let allocation_size: usize = page_size::get();
    let mmap_params: [usize; 6] = [
        0,
        allocation_size,
        (libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC) as usize,
        (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as usize,
        0,
        0,
    ];
    let (regs, mut frame) = frame.invoke_remote(mmap_remote_procedure, spoof_addr, &mmap_params)?;
    // -1 means mmap failed.
    let allocated_memory_addr = match regs.return_value() as isize {
        -1 => {
            log::warn!("Failed to execute mmap with return value: -1");
            return Err(InjectorError::ExecuteRemoteProcedure("mmap.".into()));
        }
        n => n as usize,
    };
    log::info!(
        "Mmap was successful created new mapping at {:X?} with size {:X?}",
        allocated_memory_addr,
        allocation_size,
    );

    let _bytes_written =
        frame.write_memory(allocated_memory_addr, payload_cstring.as_bytes_with_nul())?;
    log::info!(
        "Successfully wrote payload location to {:X?}",
        allocated_memory_addr
    );

    let dlopen_params: [usize; 2] = [
        allocated_memory_addr, // addr to a null terminated cstring of the target dl to open
        libc::RTLD_NOW as usize, // the flags
    ];
    let (regs, frame) = frame.invoke_remote(dlopen_remote_procedure, spoof_addr, &dlopen_params)?;
    log::info!("Executed remote dlopen function");

    if regs.return_value() == 0 {
        log::error!(
            "Failed to execute dlopen in remote process return value was: {}",
            regs.return_value()
        );

        let (regs, mut frame) = frame.invoke_remote(dlerror_remote_procedure, spoof_addr, &[])?;
        log::info!("Last error is cstring at: {:X?}", regs.return_value());

        let error_string = frame.read_memory(regs.return_value(), page_size::get())?;
        let error_string = unsafe { std::ffi::CStr::from_ptr(error_string.as_ptr() as *const _) };
        log::error!("Last Dl Error was {error_string:?}");

        return Err(InjectorError::ExecuteRemoteProcedure("dlopen".into()));
    }
    log::info!("Successfully executed remote dlopen function");

    // drop frame

    Ok(())
}
