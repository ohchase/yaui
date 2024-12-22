use std::path::{Path, PathBuf};

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

    #[error("Module is missing `{0}`")]
    ModMissing(PathBuf),

    #[error("Remote procedure failed `{0}`")]
    ExecuteRemoteProcedure(String),

    #[error("Remote procedure not found `{0}` in mod `{1}`")]
    FindRemoteProcedure(String, PathBuf),
}

fn find_mod_map(mod_path: impl AsRef<Path>, process: &impl ProcessIdentifier) -> Option<MapRange> {
    use proc_maps::get_process_maps;
    let maps = get_process_maps(process.pid()).expect("alive");
    maps.into_iter().find(|m| match m.filename() {
        Some(p) => p == mod_path.as_ref(),
        None => false,
    })
}

pub fn find_remote_procedure(
    mod_name: &impl AsRef<Path>,
    self_process: &impl ProcessIdentifier,
    traced_process: &impl ProcessIdentifier,
    function_address: usize,
) -> Option<usize> {
    let internal_module = find_mod_map(mod_name, self_process)?;
    tracing::info!(
        "Identifed internal range {:?} at {:X?}",
        mod_name.as_ref(),
        internal_module.start()
    );

    let remote_module = find_mod_map(mod_name, traced_process)?;
    tracing::info!(
        "Identifed remote range {:?} at {:X?}",
        mod_name.as_ref(),
        remote_module.start()
    );
    Some(function_address - internal_module.start() + remote_module.start())
}

/// Injects the payload pointed to by `payload_location` into `pid`.
/// Spoof path specifies a loaded module to feign calling from where the name is `spoof_so_path`
/// Memory allocation is expected to be provided by `allocater_so_path`: libc::mmap
/// Dl/So handling is expected to be provided by `linker_so_path`: libc::dlopen , libc::dlclose, libc::dlerror
pub fn inject(
    payload_location: impl AsRef<Path>,
    pid: impl Into<pid_t>,
    spoof_so_path: impl AsRef<Path>,
    allocator_so_path: impl AsRef<Path>,
    linker_so_path: impl AsRef<Path>,
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

    let self_process = RawProcess::new(std::process::id() as i32);
    let traced_process = TracedProcess::attach(RawProcess::new(pid))?;
    tracing::info!("Successfully attached to the process");

    let mmap_remote_procedure = find_remote_procedure(
        &allocator_so_path,
        &self_process,
        &traced_process,
        libc::mmap as usize,
    )
    .ok_or(InjectorError::FindRemoteProcedure(
        "mmap".into(),
        allocator_so_path.as_ref().to_owned(),
    ))?;
    tracing::info!("Identified remote mmap procedure at {mmap_remote_procedure:x?}");

    let dlerror_remote_procedure = find_remote_procedure(
        &linker_so_path,
        &self_process,
        &traced_process,
        libc::dlerror as usize,
    )
    .ok_or(InjectorError::FindRemoteProcedure(
        "dlerror".into(),
        linker_so_path.as_ref().to_owned(),
    ))?;
    tracing::info!("Identified remote dlerror procedure at {dlerror_remote_procedure:x?}");

    let dlopen_remote_procedure = find_remote_procedure(
        &linker_so_path,
        &self_process,
        &traced_process,
        libc::dlopen as usize,
    )
    .ok_or(InjectorError::FindRemoteProcedure(
        "dlopen".into(),
        linker_so_path.as_ref().to_owned(),
    ))?;
    tracing::info!("Identified remote dlopen procedure at {dlopen_remote_procedure:x?}");

    // return address stuff if needed....
    let spoof_addr = find_mod_map(&spoof_so_path, &traced_process)
        .ok_or(InjectorError::ModMissing(spoof_so_path.as_ref().to_owned()))?
        .start();
    tracing::info!("Identified spoof module base address for return address: {spoof_addr:x?}");

    let frame = traced_process.next_frame()?;
    tracing::info!("Successfully waited for the mmap frame");

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
            tracing::warn!("Failed to execute mmap with return value: -1");
            return Err(InjectorError::ExecuteRemoteProcedure("mmap.".into()));
        }
        n => n as usize,
    };
    tracing::info!(
        "Mmap was successful created new mapping at {:x?} with size {:x?}",
        allocated_memory_addr,
        allocation_size,
    );

    let _bytes_written =
        frame.write_memory(allocated_memory_addr, payload_cstring.as_bytes_with_nul())?;
    tracing::info!(
        "Successfully wrote payload location to {:x?}",
        allocated_memory_addr
    );

    let dlopen_params: [usize; 2] = [
        allocated_memory_addr, // addr to a null terminated cstring of the target dl to open
        (libc::RTLD_LAZY | libc::RTLD_LOCAL) as usize, // the flags
    ];
    let (regs, frame) = frame.invoke_remote(dlopen_remote_procedure, spoof_addr, &dlopen_params)?;
    tracing::info!("Executed remote dlopen function");

    if regs.return_value() == 0 {
        tracing::error!(
            "Failed to execute dlopen in remote process return value was: {}",
            regs.return_value()
        );

        let (regs, mut frame) = frame.invoke_remote(dlerror_remote_procedure, spoof_addr, &[])?;
        tracing::info!("Last error is cstring at: {:x?}", regs.return_value());

        let error_string = frame.read_memory(regs.return_value(), page_size::get())?;
        let error_string = unsafe { std::ffi::CStr::from_ptr(error_string.as_ptr() as *const _) };
        tracing::error!("Last Dl Error was {error_string:?}");

        return Err(InjectorError::ExecuteRemoteProcedure("dlopen".into()));
    }
    tracing::info!("Successfully executed remote dlopen function");

    // drop frame

    Ok(())
}
/// Injects the payload pointed to by `payload_location` into `pid`.
/// Spoof path specifies a loaded module to feign calling from where the name is `spoof_so_path`
/// Memory allocation is expected to be provided by `allocater_so_path`: libc::mmap
/// Dl/So handling is expected to be provided by `linker_so_path`: libc::dlopen , libc::dlclose, libc::dlerror
pub fn eject(
    payload_location: impl AsRef<Path>,
    pid: impl Into<pid_t>,
    spoof_so_path: impl AsRef<Path>,
    allocator_so_path: impl AsRef<Path>,
    linker_so_path: impl AsRef<Path>,
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

    let self_process = RawProcess::new(std::process::id() as i32);
    let traced_process = TracedProcess::attach(RawProcess::new(pid))?;
    tracing::info!("Successfully attached to the process");

    let mmap_remote_procedure = find_remote_procedure(
        &allocator_so_path,
        &self_process,
        &traced_process,
        libc::mmap as usize,
    )
    .ok_or(InjectorError::FindRemoteProcedure(
        "mmap".into(),
        allocator_so_path.as_ref().to_owned(),
    ))?;
    tracing::info!("Identified remote mmap procedure at {mmap_remote_procedure:x?}");

    let dlerror_remote_procedure = find_remote_procedure(
        &linker_so_path,
        &self_process,
        &traced_process,
        libc::dlerror as usize,
    )
    .ok_or(InjectorError::FindRemoteProcedure(
        "dlerror".into(),
        linker_so_path.as_ref().to_owned(),
    ))?;
    tracing::info!("Identified remote dlerror procedure at {dlerror_remote_procedure:x?}");

    let dlopen_remote_procedure = find_remote_procedure(
        &linker_so_path,
        &self_process,
        &traced_process,
        libc::dlopen as usize,
    )
    .ok_or(InjectorError::FindRemoteProcedure(
        "dlopen".into(),
        linker_so_path.as_ref().to_owned(),
    ))?;
    tracing::info!("Identified remote dlopen procedure at {dlopen_remote_procedure:x?}");

    let dlclose_remote_procedure = find_remote_procedure(
        &linker_so_path,
        &self_process,
        &traced_process,
        libc::dlclose as usize,
    )
    .ok_or(InjectorError::FindRemoteProcedure(
        "dlclose".into(),
        linker_so_path.as_ref().to_owned(),
    ))?;
    tracing::info!("Identified remote dlclose procedure at {dlclose_remote_procedure:x?}");

    // return address stuff if needed....
    let spoof_addr = find_mod_map(&spoof_so_path, &traced_process)
        .ok_or(InjectorError::ModMissing(spoof_so_path.as_ref().to_owned()))?
        .start();
    tracing::info!("Identified spoof module base address for return address: {spoof_addr:x?}");

    let frame = traced_process.next_frame()?;
    tracing::info!("Successfully waited for the mmap frame");

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
            tracing::warn!("Failed to execute mmap with return value: -1");
            return Err(InjectorError::ExecuteRemoteProcedure("mmap.".into()));
        }
        n => n as usize,
    };
    tracing::info!(
        "Mmap was successful created new mapping at {:x?} with size {:x?}",
        allocated_memory_addr,
        allocation_size,
    );

    let _bytes_written =
        frame.write_memory(allocated_memory_addr, payload_cstring.as_bytes_with_nul())?;
    tracing::info!(
        "Successfully wrote payload location to {:x?}",
        allocated_memory_addr
    );

    let dlopen_params: [usize; 2] = [
        allocated_memory_addr, // addr to a null terminated cstring of the target dl to open
        (libc::RTLD_LAZY | libc::RTLD_NOLOAD) as usize, // the flags
    ];
    let (regs, frame) = frame.invoke_remote(dlopen_remote_procedure, spoof_addr, &dlopen_params)?;
    tracing::info!("Executed remote dlopen function");

    if regs.return_value() == 0 {
        tracing::error!(
            "Failed to execute dlopen in remote process return value was: {}",
            regs.return_value()
        );

        let (regs, mut frame) = frame.invoke_remote(dlerror_remote_procedure, spoof_addr, &[])?;
        tracing::info!("Last error is cstring at: {:x?}", regs.return_value());

        let error_string = frame.read_memory(regs.return_value(), page_size::get())?;
        let error_string = unsafe { std::ffi::CStr::from_ptr(error_string.as_ptr() as *const _) };
        tracing::error!("Last Dl Error was {error_string:?}");

        return Err(InjectorError::ExecuteRemoteProcedure("dlopen".into()));
    }
    tracing::info!("Successfully executed remote dlopen function");

    let raw_handle = regs.return_value();
    let (regs, frame) = frame.invoke_remote(dlclose_remote_procedure, spoof_addr, &[raw_handle])?;
    if regs.return_value() != 0 {
        tracing::error!(
            "Failed to execute dlclose in remote process return value was: {}",
            regs.return_value()
        );

        let (regs, mut frame) = frame.invoke_remote(dlerror_remote_procedure, spoof_addr, &[])?;
        tracing::info!("Last error is cstring at: {:x?}", regs.return_value());

        let error_string = frame.read_memory(regs.return_value(), page_size::get())?;
        let error_string = unsafe { std::ffi::CStr::from_ptr(error_string.as_ptr() as *const _) };
        tracing::error!("Last Dl Error was {error_string:?}");

        return Err(InjectorError::ExecuteRemoteProcedure("dlclose".into()));
    }
    tracing::info!("Successfully executed remote dlclose function");

    // we opened a handle our self so have to do two closes
    let (_regs, _frame) =
        frame.invoke_remote(dlclose_remote_procedure, spoof_addr, &[raw_handle])?;

    Ok(())
}
