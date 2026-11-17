//! Small operating-system helpers that read no secrets: the socket caller (R22, R23), whether
//! it is Volgenic for Mac's signed app (R37) and process hardening (R3). Everything that differs between macOS and Linux at this level sits
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

/// Volgenic's Developer ID team, which signs Volgenic for Mac (#7078).
pub const VOLGENIC_TEAM_ID: &str = "69CV53Q479";

/// Volgenic for Mac's bundle ids: the release, and the dev build people test fills with.
pub const VOLGENIC_APP_IDS: [&str; 2] = ["com.volgenic.desktop", "com.volgenic.desktop.v2dev"];

/// The code requirement a caller must meet to fill as Volgenic for Mac (#7689): signed with a
/// Developer ID Application certificate (Apple's anchor, the Developer ID intermediate's and leaf's
/// marker extensions) of Volgenic's team, as one of the app's bundle ids.
pub fn volgenic_app_requirement() -> String {
    let ids = VOLGENIC_APP_IDS.iter().map(|id| format!("identifier \"{id}\"")).collect::<Vec<_>>().join(" or ");
    format!(
        "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists \
         and certificate leaf[field.1.2.840.113635.100.6.1.13] exists \
         and certificate leaf[subject.OU] = \"{VOLGENIC_TEAM_ID}\" and ({ids})"
    )
}

/// Whether the process on the other end of `fd` is Volgenic for Mac, signed by Volgenic's team
/// with the hardened runtime, and still valid as it runs (#7689, R37). `Err` says why not.
pub fn peer_is_volgenic_app(fd: std::os::fd::RawFd) -> Result<(), String> {
    peer_meets(fd, &volgenic_app_requirement())
        .map_err(|why| format!("the caller isn't Volgenic for Mac signed with Volgenic's Developer ID ({VOLGENIC_TEAM_ID}): {why}"))
}

/// Whether the process on the other end of `fd` meets the code `requirement`, was signed with
/// the hardened runtime, and is still valid as it runs. The process is named by its audit token
/// (`LOCAL_PEERTOKEN`), not its pid, so a pid that is reused can't stand in for it. The hardened
/// runtime is what keeps another program of the owner's from loading its own code into it (no
/// `DYLD_INSERT_LIBRARIES`, no debugger). `Err` says why not, never a value.
#[cfg(target_os = "macos")]
pub fn peer_meets(fd: std::os::fd::RawFd, requirement: &str) -> Result<(), String> {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use security_framework::os::macos::code_signing::{Flags, GuestAttributes, SecCode, SecRequirement};

    unsafe extern "C" {
        static kSecCodeInfoFlags: core_foundation::string::CFStringRef;
        fn SecCodeCopySigningInformation(
            code: *const std::ffi::c_void,
            flags: u32,
            information: *mut core_foundation::dictionary::CFDictionaryRef,
        ) -> i32;
    }
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;
    const SIGNING_INFORMATION: u32 = 1 << 1; // kSecCSSigningInformation
    const RUNTIME: u32 = 0x10000; // kSecCodeSignatureRuntime

    let mut token = [0u32; 8]; // audit_token_t
    let mut len = std::mem::size_of_val(&token) as libc::socklen_t;
    let got = unsafe { libc::getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, token.as_mut_ptr().cast(), &mut len) };
    if got != 0 || len as usize != std::mem::size_of_val(&token) {
        return Err("the caller's audit token couldn't be read".into());
    }
    let bytes: Vec<u8> = token.iter().flat_map(|word| word.to_ne_bytes()).collect();
    let token = CFData::from_buffer(&bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token.as_concrete_TypeRef());
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|e| format!("the caller's code couldn't be found ({})", e.code()))?;
    let requirement: SecRequirement =
        requirement.parse().map_err(|e: security_framework::base::Error| format!("requirement: {}", e.code()))?;
    code.check_validity(Flags::NONE, &requirement)
        .map_err(|e| format!("its signature doesn't meet the requirement ({})", e.code()))?;
    let mut info = std::ptr::null();
    let status = unsafe { SecCodeCopySigningInformation(code.as_CFTypeRef(), SIGNING_INFORMATION, &mut info) };
    if status != 0 || info.is_null() {
        return Err(format!("the caller's signature couldn't be read ({status})"));
    }
    let info: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(info) };
    let flags = info
        .find(unsafe { CFString::wrap_under_get_rule(kSecCodeInfoFlags) })
        .and_then(|value| value.downcast::<CFNumber>())
        .and_then(|number| number.to_i64())
        .unwrap_or(0) as u32;
    if flags & RUNTIME == 0 {
        return Err("it wasn't signed with the hardened runtime".into());
    }
    Ok(())
}

/// No code signatures to check on Linux (and no Volgenic for Mac there).
#[cfg(not(target_os = "macos"))]
pub fn peer_meets(_fd: std::os::fd::RawFd, _requirement: &str) -> Result<(), String> {
    Err("code signatures are checked only on a Mac".into())
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
