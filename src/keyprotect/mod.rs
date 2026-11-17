//! Key protection: the vault key is 32 random bytes, made as a mode-0600 file next to the vault
//! file, in the owner's own folder, and then sealed to this machine's hardware when it has the
//! hardware: the Secure Enclave on a Mac, the TPM on Linux. Sealing checks the round trip before
//! it wipes the plain file, and the daemon unseals at every start with no prompt, so agents keep
//! working unattended. What it adds on both systems: a copy of the disk (a stolen drive, a Time
//! Machine or home-folder backup) can't open the vault on any other machine. What it doesn't:
//! anything running as the owner on this machine can have it unsealed, as it could read the plain
//! file. This module is the only code that touches where the key is kept.
//!
//! **On a Mac, wrapped by the Secure Enclave (#7689).** `seal` makes a P-256 key in this Mac's
//! Secure Enclave and wraps the vault key with it (`enclave`), into `vault.key.se`. The Enclave
//! key never leaves the Enclave: the file holds only the Enclave's encrypted handle to it, usable
//! by this Mac's Enclave alone, after the first unlock since boot, and never asks for a fingerprint
//! or a password. No Keychain item is made. On a Mac without a Secure Enclave (an Intel Mac without
//! a T2 chip) the key stays the 0600 file, and `vault status` says so.
//!
//! **On Linux, sealed to the TPM when there is one.** `seal` hands the key file to
//! `systemd-creds --user encrypt --with-key=host+tpm2` (systemd 256 or later, a TPM 2.0), which
//! writes `vault.key.cred`: the key encrypted to this machine's TPM and its host secret, and bound
//! to the owner's user. A user-scoped credential can't be `tpm2` alone: `systemd-creds` refuses
//! it ("Selected key not available in --uid= scoped mode"), because the user scoping is keyed off
//! the host secret.
//! The round trip is checked (decrypted again and compared) before the plain file is wiped. The
//! daemon unseals it at every start with `systemd-creds --user decrypt`, unattended, which is
//! what lets the vault come back after a reboot with nobody logged in. What it adds: a copy of
//! the disk (a stolen drive, a backup of the home folder) can't open the vault anywhere else.
//! What it doesn't: anything running as the owner on this machine can ask `systemd-creds` to
//! unseal it, just as it could read the plain file. Without `systemd-creds --user` or a TPM, the
//! key stays the 0600 file.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::error::VaultError;
use crate::secret::SecretValue;

/// The vault key, in the vault folder.
pub const KEY_FILE: &str = "vault.key";

/// The vault key sealed to the TPM by `systemd-creds` (Linux).
pub const SEALED_FILE: &str = "vault.key.cred";

/// The vault key wrapped by the Secure Enclave (macOS).
pub const ENCLAVE_FILE: &str = "vault.key.se";

#[cfg(target_os = "macos")]
mod enclave;

/// This system's sealed key file.
#[cfg(target_os = "macos")]
const SEALED: &str = ENCLAVE_FILE;
#[cfg(not(target_os = "macos"))]
const SEALED: &str = SEALED_FILE;

/// What sealed it, in `vault status`'s words.
#[cfg(target_os = "macos")]
const SEALED_BY: &str = "wrapped by this Mac's Secure Enclave";
#[cfg(not(target_os = "macos"))]
const SEALED_BY: &str = "sealed to this machine's TPM 2.0 by systemd-creds";

/// Why this machine can't seal the key, or nothing when it can.
fn seal_ready() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    return sealed::ready().map(|_| ());
    #[cfg(target_os = "macos")]
    return enclave::ready();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err("this system has nothing to seal the key to".into())
}

fn exists(dir: &Path, name: &str) -> bool {
    fs::symlink_metadata(dir.join(name)).is_ok()
}

/// Where the vault key is kept, for `vault status`.
pub fn describe(dir: &Path) -> String {
    match (exists(dir, SEALED), exists(dir, KEY_FILE)) {
        (true, false) => format!("{SEALED_BY} ({SEALED}); no plain copy"),
        (true, true) => format!(
            "{SEALED_BY} ({SEALED}), and a plain {KEY_FILE} is still there (an interrupted seal; `vault install` finishes it)"
        ),
        _ => "vault key in a mode-600 file next to the vault file, not sealed to this machine".into(),
    }
}

/// Where the vault key is kept, as plain values for `vault status --json`. Information only.
pub struct KeyState {
    /// `tpm2` (sealed by systemd-creds, Linux), `secure_enclave` (wrapped by the Secure Enclave,
    /// macOS), `file` (the 0600 key file) or `none` (no key).
    pub kind: &'static str,
    /// For `file`: why it isn't sealed (no TPM, no systemd-creds, no Secure Enclave).
    pub reason: Option<String>,
    /// A sealed key and a plain copy are both there (an interrupted seal).
    pub plain_copy_left: bool,
    /// For `file`: this machine could seal it now (`vault install` would).
    pub sealable: bool,
    /// `describe`, the sentence `vault status` prints.
    pub detail: String,
}

pub fn state(dir: &Path) -> KeyState {
    let plain = exists(dir, KEY_FILE);
    let detail = describe(dir);
    if exists(dir, SEALED) {
        let kind = if cfg!(target_os = "macos") { "secure_enclave" } else { "tpm2" };
        return KeyState { kind, reason: None, plain_copy_left: plain, sealable: false, detail };
    }
    if !plain {
        return KeyState { kind: "none", reason: None, plain_copy_left: false, sealable: false, detail: "no vault key".into() };
    }
    let (reason, sealable) = match seal_ready() {
        Ok(()) => ("not sealed yet, though this machine can seal it: `vault install` seals it".to_string(), true),
        Err(why) => (why, false),
    };
    KeyState { kind: "file", reason: Some(reason), plain_copy_left: false, sealable, detail }
}

pub fn key_exists(dir: &Path) -> bool {
    exists(dir, KEY_FILE) || exists(dir, SEALED_FILE) || exists(dir, ENCLAVE_FILE)
}

/// Writes a new vault key, mode 0600. Fails if one is already stored. The key-file call site
/// of `expose` in R1.
pub fn store_new(dir: &Path, key: &SecretValue) -> Result<(), VaultError> {
    if exists(dir, SEALED) {
        return Err(VaultError::AlreadyInitialized);
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dir.join(KEY_FILE))
        .map_err(|e| if e.kind() == std::io::ErrorKind::AlreadyExists { VaultError::AlreadyInitialized } else { e.into() })?;
    file.write_all(key.expose())?;
    file.sync_all()?;
    Ok(())
}

/// Refuses a key file that isn't a plain file of the running user's with no group or other bits.
fn check_own_file(path: &Path) -> Result<(), VaultError> {
    let meta = fs::symlink_metadata(path).map_err(|_| VaultError::KeyProtection)?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::getuid() } {
        return Err(VaultError::UnsafeVaultFolder(format!("{} must be a 0600 file of yours", path.display())));
    }
    Ok(())
}

fn load_file(dir: &Path) -> Result<SecretValue, VaultError> {
    let path = dir.join(KEY_FILE);
    check_own_file(&path)?;
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(32));
    fs::File::open(&path)?.read_to_end(&mut buf)?;
    if buf.len() != 32 {
        return Err(VaultError::KeyProtection);
    }
    Ok(SecretValue::from_vec(buf.to_vec()))
}

/// Reads the vault key: unsealed from the TPM (Linux) or the Secure Enclave (macOS) when it is
/// sealed, else from the key file, which must be the owner's and 0600.
pub fn load(dir: &Path) -> Result<SecretValue, VaultError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if exists(dir, SEALED) {
        #[cfg(target_os = "linux")]
        let unsealed = sealed::unseal(dir);
        #[cfg(target_os = "macos")]
        let unsealed = enclave::unseal(dir);
        match unsealed {
            Ok(key) => return Ok(key),
            // Both files exist only when a seal was interrupted before the plain file was wiped;
            // both then hold the same key.
            Err(_) if fs::symlink_metadata(dir.join(KEY_FILE)).is_ok() => return load_file(dir),
            Err(error) => return Err(error),
        }
    }
    load_file(dir)
}

/// Protects a vault key stored with `store_new` as well as this machine allows, and says how:
/// sealed to the TPM when `systemd-creds --user` and a TPM 2.0 are there (Linux), or wrapped by
/// the Secure Enclave when the Mac has one, the plain file wiped once the round trip checks out;
/// else left as the 0600 file.
pub fn protect(dir: &Path, key: &SecretValue) -> String {
    #[cfg(target_os = "linux")]
    let sealed = sealed::seal(dir, key);
    #[cfg(target_os = "macos")]
    let sealed = enclave::seal(dir, key);
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let sealed: Result<(), String> = {
        let _ = key;
        seal_ready()
    };
    match sealed {
        Ok(()) => format!("{SEALED_BY} ({SEALED}); the plain key file is wiped"),
        Err(why) => format!("mode-600 file ({why})"),
    }
}

/// The last steps of a seal, the same on both systems: `temp` holds the sealed key, already
/// decrypted again and compared. Puts it in place as `sealed`, then overwrites and deletes the
/// plain key (best effort on an SSD, as with the kit). Any failure before the rename removes
/// `temp` and leaves the plain file as it was.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn replace_plain(dir: &Path, temp: &Path, sealed: &str) -> Result<(), String> {
    if let Err(error) = fs::rename(temp, dir.join(sealed)) {
        let _ = fs::remove_file(temp);
        return Err(error.to_string());
    }
    if let Ok(folder) = fs::File::open(dir) {
        let _ = folder.sync_all();
    }
    let plain = dir.join(KEY_FILE);
    if let Ok(mut file) = OpenOptions::new().write(true).open(&plain) {
        let _ = file.write_all(&[0u8; 32]);
        let _ = file.sync_all();
    }
    fs::remove_file(&plain).map_err(|e| format!("sealed, but the plain key file wasn't removed: {e}"))
}

/// Removes the vault key, plain and sealed (only `vault reset`, after the recovery key is proven).
pub fn remove(dir: &Path) -> Result<(), VaultError> {
    for name in [SEALED_FILE, ENCLAVE_FILE, KEY_FILE] {
        match fs::remove_file(dir.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Sealing the key with `systemd-creds` (Linux only).
#[cfg(target_os = "linux")]
mod sealed {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use zeroize::Zeroizing;

    use super::{KEY_FILE, SEALED_FILE, check_own_file, replace_plain};
    use crate::error::VaultError;
    use crate::secret::SecretValue;

    /// The credential's name, bound into it: a credential made for something else won't open.
    const CREDENTIAL_NAME: &str = "volgenic-vault.key";

    /// `systemd-creds` at its fixed place, never found through `$PATH` (R15).
    fn tool() -> Option<PathBuf> {
        ["/usr/bin/systemd-creds", "/bin/systemd-creds"].into_iter().map(PathBuf::from).find(|path| path.is_file())
    }

    /// Why the key can't be sealed here, or the tool to seal it with.
    pub(super) fn ready() -> Result<PathBuf, String> {
        let tool = tool().ok_or("systemd-creds isn't installed")?;
        let out = Command::new(&tool)
            .arg("has-tpm2")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("systemd-creds didn't run: {e}"))?;
        if !out.status.success() {
            return Err("no usable TPM 2.0 (`systemd-creds has-tpm2`)".into());
        }
        Ok(tool)
    }

    /// Unseals the key to this process's memory, through a pipe (never an argument, the
    /// environment or a file, R2).
    fn decrypt(tool: &Path, sealed: &Path) -> Result<SecretValue, VaultError> {
        let mut child = Command::new(tool)
            .args(["--user", "decrypt", &format!("--name={CREDENTIAL_NAME}")])
            .arg(sealed)
            .arg("-")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| VaultError::SealedKey(format!("systemd-creds didn't run: {e}")))?;
        // Into a fixed buffer, wiped on drop: a growing Vec would leave copies behind (R1).
        let mut key = Zeroizing::new([0u8; 33]);
        let mut len = 0;
        if let Some(mut stdout) = child.stdout.take() {
            while len < key.len() {
                match stdout.read(&mut key[len..]) {
                    Ok(0) => break,
                    Ok(n) => len += n,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            // Drain anything past 33 bytes, so the child can finish; it can't be a 32-byte key.
            let mut rest = Zeroizing::new([0u8; 256]);
            while matches!(stdout.read(&mut rest[..]), Ok(n) if n > 0) {
                len = key.len();
            }
        }
        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }
        let status = child.wait().map_err(|e| VaultError::SealedKey(format!("systemd-creds didn't finish: {e}")))?;
        if !status.success() {
            return Err(VaultError::SealedKey(format!("systemd-creds couldn't unseal it: {}", stderr.trim())));
        }
        if len != 32 {
            return Err(VaultError::SealedKey("the unsealed key isn't 32 bytes".into()));
        }
        Ok(SecretValue::from_vec(key[..32].to_vec()))
    }

    pub fn unseal(dir: &Path) -> Result<SecretValue, VaultError> {
        let sealed = dir.join(SEALED_FILE);
        check_own_file(&sealed)?;
        let tool = tool().ok_or_else(|| VaultError::SealedKey("systemd-creds isn't installed".into()))?;
        decrypt(&tool, &sealed)
    }

    /// Seals the key file: encrypt it to the TPM, check the round trip gives back `key`, put the
    /// sealed file in place, then wipe the plain one. Any failure leaves the plain file as it was.
    pub fn seal(dir: &Path, key: &SecretValue) -> Result<(), String> {
        let plain = dir.join(KEY_FILE);
        if fs::symlink_metadata(&plain).is_err() {
            return Err("no plain key file to seal".into());
        }
        let tool = ready()?;
        let temp = dir.join(format!(".{SEALED_FILE}.tmp-{}", std::process::id()));
        let _ = fs::remove_file(&temp);
        let out = Command::new(&tool)
            // `host+tpm2`, not `tpm2`: in user scope `systemd-creds` allows only host-bound keys.
            .args(["--user", "encrypt", "--with-key=host+tpm2", &format!("--name={CREDENTIAL_NAME}")])
            .arg(&plain)
            .arg(&temp)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("systemd-creds didn't run: {e}"))?;
        let fail = |why: String| {
            let _ = fs::remove_file(&temp);
            why
        };
        if !out.status.success() {
            return Err(fail(format!(
                "systemd-creds --user encrypt --with-key=host+tpm2 failed (it needs systemd 256 or later): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).map_err(|e| fail(e.to_string()))?;
        match decrypt(&tool, &temp) {
            Ok(back) if back.same_as(key) => {}
            Ok(_) => return Err(fail("the sealed key didn't decrypt to the same key".into())),
            Err(error) => return Err(fail(error.to_string())),
        }
        replace_plain(dir, &temp, SEALED_FILE)
    }
}
