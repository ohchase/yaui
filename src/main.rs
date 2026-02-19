use anyhow::Result;
use clap::{arg, command, Parser, Subcommand};
use libc::{pid_t, uid_t};
use yaui::{PtraceScope, SELinuxEnforcement};

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    debug: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Gets health status of the current system relating to its ability to ptrace external processes
    Health,
    /// Checks if a process can be injected into
    Check {
        /// Identifier to target application to check
        #[arg(short, long)]
        target: pid_t,
    },
}

fn command_health() -> Result<()> {
    let user_euid: uid_t = unsafe { libc::geteuid() };
    match user_euid {
        0 => tracing::info!("running as root"),
        _ => tracing::warn!("running as non-root user (euid={user_euid})"),
    }

    // Check Yama ptrace scope.
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

    // Check SELinux enforcement.
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

fn main() -> Result<()> {
    tracing_subscriber::fmt().without_time().compact().init();

    let args = Cli::parse();

    match args.command {
        Some(_) => todo!(),
        None => todo!(),
    }

    Ok(())
}
