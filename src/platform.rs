//! Small operating-system helpers that read no secrets: the socket caller (R22, R23) and
//! process hardening (R3). Everything that differs between macOS and Linux at this level sits
//! here, behind `cfg`, so the rest of the crate stays platform-neutral.

use std::path::Path;

use crate::error::VaultError;

/// What the vault calls the machine it runs on, in messages: "Mac" or "machine".
#[cfg(target_os = "macos")]
pub const MACHINE: &str = "Mac";
#[cfg(not(target_os = "macos"))]
pub const MACHINE: &str = "machine";

/// SHA-256 of a file, as hex.
pub fn sha256_of(path: &Path) -> Result<String, VaultError> {
    use sha2::{Digest, Sha256};
    let data = std::fs::read(path)?;
    Ok(hex::encode(Sha256::digest(&data)))
}

/// Hardening at start (R3): refuse debugger attachment and never write a crash dump.
///
/// On macOS, `PT_DENY_ATTACH`. On Linux, `PR_SET_DUMPABLE` 0: no core dump, and no other
/// process of the same user may `ptrace` it or read its memory through `/proc` (only root can).
pub fn harden_process() {
    unsafe {
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &no_core);
        #[cfg(target_os = "macos")]
        {
            const PT_DENY_ATTACH: libc::c_int = 31;
            libc::ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
        #[cfg(target_os = "linux")]
        {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }
}

/// Who is on the other end of a socket connection.
pub struct Peer {
    pub uid: u32,
    pub pid: Option<i32>,
    pub program: Option<String>,
}

/// The connected peer's user ID and, as a hint (R23), its process and program.
pub fn peer_of(fd: std::os::fd::RawFd) -> Option<Peer> {
    let (uid, pid) = peer_credentials(fd)?;
    let program = pid.and_then(program_path);
    Some(Peer { uid, pid, program })
}

/// The connected peer's user ID only: what the command-line tool checks of the daemon (R22).
pub fn peer_uid(fd: std::os::fd::RawFd) -> Option<u32> {
    peer_credentials(fd).map(|(uid, _)| uid)
}

/// macOS: `getpeereid` for the user ID, `LOCAL_PEERPID` for the process.
#[cfg(target_os = "macos")]
fn peer_credentials(fd: std::os::fd::RawFd) -> Option<(u32, Option<i32>)> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return None;
    }
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 0x002;
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, (&mut pid as *mut libc::pid_t).cast(), &mut len)
    };
    Some((uid, (ok == 0 && pid > 0).then_some(pid)))
}

/// Linux: `SO_PEERCRED`, the credentials the kernel recorded when the peer connected (glibc has
/// no `getpeereid`).
#[cfg(target_os = "linux")]
fn peer_credentials(fd: std::os::fd::RawFd) -> Option<(u32, Option<i32>)> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ok = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len)
    };
    if ok != 0 || len as usize != std::mem::size_of::<libc::ucred>() {
        return None;
    }
    Some((cred.uid, (cred.pid > 0).then_some(cred.pid)))
}

#[cfg(target_os = "macos")]
fn program_path(pid: i32) -> Option<String> {
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    (len > 0).then(|| String::from_utf8_lossy(&buffer[..len as usize]).into_owned())
}

/// The program behind a process, from `/proc`. A process that made itself non-dumpable (the
/// `vault` command-line tool does, R3) hides it, so this is a hint only (R23).
#[cfg(target_os = "linux")]
fn program_path(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|path| path.display().to_string())
}

/// Whether this Linux machine was booted with systemd as its service manager (what
/// `sd_booted()` checks).
#[cfg(target_os = "linux")]
pub fn systemd_booted() -> bool {
    std::fs::symlink_metadata("/run/systemd/system").is_ok_and(|meta| meta.is_dir())
}
