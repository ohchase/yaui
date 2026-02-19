use anyhow::Result;
use libc::uid_t;
use yaui::{PtraceScope, SELinuxEnforcement};

fn main() -> Result<()> {
    tracing_subscriber::fmt().without_time().compact().init();

    let user_euid: uid_t = unsafe { libc::geteuid() };
    match user_euid {
        0 => tracing::info!("running as root"),
        _ => tracing::warn!("running as non-root user (euid={user_euid})"),
    }

    match yaui::get_ptrace_scope() {
        Ok(Some(scope)) => {
            tracing::debug!("ptrace scope: {scope}");
            match scope {
                PtraceScope::Classic => tracing::info!(
                    "ptrace scope is classic, no restrictions on ptrace permissions."
                ),
                PtraceScope::Restricted => {
                    tracing::warn!(
                        "ptrace scope is restricted, only parent processes can ptrace their children. Injection may fail if the target process is not a child of this injector."
                    );
                },
                PtraceScope::AdminOnly => {
                    tracing::warn!(
                        "ptrace scope is admin-only, only processes with CAP_SYS_PTRACE can use ptrace. Injection may fail if this injector is not running with CAP_SYS_PTRACE capability."
                    );
                },
                PtraceScope::NoAttach => tracing::error!(
                    "ptrace scope is no-attach, no processes can use ptrace."
                ),
            }
        }
        Ok(None) => tracing::info!(
            "ptrace scope not present. This means the kernel is not configured with Yama LSM, and ptrace permissions are determined by classic Unix permissions."
        ),
        Err(e) => tracing::error!("failed to get ptrace scope: {}", e),
    }

    match yaui::get_selinux_enforcement() {
        Ok(Some(enforce)) => {
            tracing::debug!("selinux enforcement: {enforce}");
            match enforce {
                SELinuxEnforcement::Permissive => tracing::info!(
                    "selinux is being permissive, this means selinux is enabled but not enforcing policies. Injection should work unless the target process is confined by selinux policies that prevent ptrace or memory access."
                ),
                SELinuxEnforcement::Enforcing => {
                    tracing::warn!(
                        "selinux is being enforcing, injection may fail if the target process is confined by selinux policies. Consider setting it to permissive mode for testing."
                    )
                }
            }
        }
        Ok(None) => tracing::info!(
            "selinux enforcement not present. This means SELinux is not enabled on this system."
        ),
        Err(e) => tracing::error!("failed to get selinux enforcement: {}", e),
    }

    Ok(())
}
