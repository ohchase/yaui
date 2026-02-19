use std::fmt;
use std::fs;
use std::io;
use thiserror::Error;

/// Errors that can occur when checking ptrace scope or SELinux enforcement.
#[derive(Error, Debug)]
pub enum AccessError {
    #[error("Failed to read system config file: {0}")]
    ReadError(#[from] io::Error),

    #[error("Failed to parse system config value")]
    ParseError,

    #[error("Ptrace is restricted (scope={0}). Root privileges or capability adjustments may be required.")]
    Restricted(i32),

    #[error("SELinux enforcement level is {0}. This is an unknown flag option, expecting 0 or 1.")]
    SELinuxEnforcement(i32),

    #[error("Ptrace scope level is {0}. This is an unknown flag option, expecting 0-3.")]
    PtraceScope(i32),
}

/// Represents the enforcement level of SELinux.
pub enum SELinuxEnforcement {
    /// 0: Permissive - SELinux is enabled but does not enforce policies, only logs violations.
    Permissive,
    /// 1: Enforcing - SELinux is enabled and actively enforces policies, blocking unauthorized actions.
    Enforcing,
}

impl fmt::Display for SELinuxEnforcement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SELinuxEnforcement::Permissive => write!(f, "Permissive (0)"),
            SELinuxEnforcement::Enforcing => write!(f, "Enforcing (1)"),
        }
    }
}

/// Represents the ptrace scope level (Yama LSM).
///
/// Ptrace scope values control what processes can be traced.
pub enum PtraceScope {
    /// 0: Classic ptrace permissions - a process can ptrace any other process with the same uid
    Classic,
    /// 1: Restricted ptrace - only a parent process can ptrace its children
    Restricted,
    /// 2: Admin-only attach - only processes with CAP_SYS_PTRACE can use ptrace
    AdminOnly,
    /// 3: No attach - no processes can use PTRACE_ATTACH
    NoAttach,
}

impl fmt::Display for PtraceScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PtraceScope::Classic => write!(f, "Classic (0)"),
            PtraceScope::Restricted => write!(f, "Restricted (1)"),
            PtraceScope::AdminOnly => write!(f, "AdminOnly (2)"),
            PtraceScope::NoAttach => write!(f, "NoAttach (3)"),
        }
    }
}

/// Attempt to get the current ptrace scope value.
///
/// This is useful for diagnostics or when you want to know the exact scope level.
///
/// # Returns
/// - `Ok(Some(scope))` with the scope enum value
/// - `Ok(None)` if Yama LSM is not present (classic permissions)
/// - `Err(AccessError)` for read/parse errors
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn get_ptrace_scope() -> Result<Option<PtraceScope>, AccessError> {
    let ptrace_scope_path = "/proc/sys/kernel/yama/ptrace_scope";

    match fs::read_to_string(ptrace_scope_path) {
        Ok(content) => content
            .trim()
            .parse::<i32>()
            .map_err(|_| AccessError::ParseError)
            .and_then(|v| match v {
                0 => Ok(Some(PtraceScope::Classic)),
                1 => Ok(Some(PtraceScope::Restricted)),
                2 => Ok(Some(PtraceScope::AdminOnly)),
                3 => Ok(Some(PtraceScope::NoAttach)),
                v => Err(AccessError::PtraceScope(v)),
            }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // Yama LSM not present
            Ok(None)
        }
        Err(e) => Err(AccessError::ReadError(e)),
    }
}

/// Attempt to get the current enforcement flag for selinux.
/// This is useful for diagnostics or when you want to know the exact enforcement level.
///
/// # Returns
/// - `Ok(Some(flag))` with the flag value (0-1)
/// - `Ok(None)` if SELinux is not present
/// - `Err(AccessError)` for read/parse errors
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn get_selinux_enforcement() -> Result<Option<SELinuxEnforcement>, AccessError> {
    let selinux_enforce_path = "/sys/fs/selinux/enforce";

    match fs::read_to_string(selinux_enforce_path) {
        Ok(content) => content
            .trim()
            .parse::<i32>()
            .map_err(|_| AccessError::ParseError)
            .and_then(|v| match v {
                0 => Ok(Some(SELinuxEnforcement::Permissive)),
                1 => Ok(Some(SELinuxEnforcement::Enforcing)),
                v => Err(AccessError::SELinuxEnforcement(v)),
            }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            // SELinux not present
            Ok(None)
        }
        Err(e) => Err(AccessError::ReadError(e)),
    }
}
