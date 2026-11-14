//! Key protection, kept simple on purpose: the vault key is 32 random bytes in a mode-0600 file
//! next to the vault file, in the owner's own folder. No Secure Enclave and no Keychain, so
//! nothing the vault does can ever raise a dialog. The bar is "better than plaintext secrets on
//! a server": the vault file is encrypted, and only the owner's account can read either file.
//! This module is the only code that touches where the key is kept.
//!
//! **On Linux, sealed to the TPM when there is one.** `seal` hands the key file to
//! `systemd-creds --user encrypt --with-key=tpm2` (systemd 256 or later, a TPM 2.0), which
//! writes `vault.key.cred`: the key encrypted to this machine's TPM and bound to the owner's user.
//! The round trip is checked (decrypted again and compared) before the plain file is wiped. The
//! daemon unseals it at every start with `systemd-creds --user decrypt`, unattended, which is
//! what lets the vault come back after a reboot with nobody logged in. What it adds: a copy of
//! the disk (a stolen drive, a backup of the home folder) can't open the vault anywhere else.
//! What it doesn't: anything running as the owner on this machine can ask `systemd-creds` to
//! unseal it, just as it could read the plain file. Without `systemd-creds --user` or a TPM, the
//! key stays the 0600 file, as on a Mac.

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

/// Where the vault key is kept, for `vault status`.
pub fn describe(dir: &Path) -> String {
    let plain = fs::symlink_metadata(dir.join(KEY_FILE)).is_ok();
    let sealed = fs::symlink_metadata(dir.join(SEALED_FILE)).is_ok();
    match (sealed, plain) {
        (true, false) => format!(
            "sealed to this machine's TPM 2.0 by systemd-creds ({SEALED_FILE}); no plain copy"
        ),
        (true, true) => format!(
            "sealed to the TPM ({SEALED_FILE}), and a plain {KEY_FILE} is still there (an interrupted seal; `vault install` finishes it)"
        ),
        _ => "vault key in a mode-600 file next to the vault file (no Secure Enclave, no Keychain)".into(),
    }
}

pub fn key_exists(dir: &Path) -> bool {
    fs::symlink_metadata(dir.join(KEY_FILE)).is_ok() || fs::symlink_metadata(dir.join(SEALED_FILE)).is_ok()
}

/// Writes a new vault key, mode 0600. Fails if one is already stored. The key-file call site
/// of `expose` in R1.
pub fn store_new(dir: &Path, key: &SecretValue) -> Result<(), VaultError> {
    if fs::symlink_metadata(dir.join(SEALED_FILE)).is_ok() {
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

/// Reads the vault key: unsealed from the TPM when it is sealed (Linux), else from the key file,
/// which must be the owner's and 0600.
pub fn load(dir: &Path) -> Result<SecretValue, VaultError> {
    #[cfg(target_os = "linux")]
    if fs::symlink_metadata(dir.join(SEALED_FILE)).is_ok() {
        match sealed::unseal(dir) {
            Ok(key) => return Ok(key),
            // Both files exist only when a seal was interrupted before the plain file was wiped;
            // both then hold the same key.
            Err(_) if fs::symlink_metadata(dir.join(KEY_FILE)).is_ok() => return load_file(dir),
            Err(error) => return Err(error),
        }
    }
    load_file(dir)
}

/// Protects a vault key just stored with `store_new` as well as this machine allows, and says
/// how: on Linux, sealed to the TPM when `systemd-creds --user` and a TPM 2.0 are there (the
/// plain file is wiped once the round trip checks out), else left as the 0600 file. On macOS the
/// file is the protection.
pub fn protect(dir: &Path, key: &SecretValue) -> String {
    #[cfg(target_os = "linux")]
    {
        match sealed::seal(dir, key) {
            Ok(()) => "sealed to this machine's TPM 2.0 (systemd-creds); the plain key file is wiped".into(),
            Err(why) => format!("mode-600 file ({why})"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dir, key);
        "mode-600 file".into()
    }
}

/// Removes the vault key, plain and sealed (only `vault reset`, after the recovery key is proven).
pub fn remove(dir: &Path) -> Result<(), VaultError> {
    for name in [SEALED_FILE, KEY_FILE] {
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
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    use zeroize::Zeroizing;

    use super::{KEY_FILE, SEALED_FILE, check_own_file};
    use crate::error::VaultError;
    use crate::secret::SecretValue;

    /// The credential's name, bound into it: a credential made for something else won't open.
    const CREDENTIAL_NAME: &str = "volgenic-vault.key";

    /// `systemd-creds` at its fixed place, never found through `$PATH` (R15).
    fn tool() -> Option<PathBuf> {
        ["/usr/bin/systemd-creds", "/bin/systemd-creds"].into_iter().map(PathBuf::from).find(|path| path.is_file())
    }

    /// Why the key can't be sealed here, or the tool to seal it with.
    fn ready() -> Result<PathBuf, String> {
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
        let out = Command::new(tool)
            .args(["--user", "decrypt", &format!("--name={CREDENTIAL_NAME}")])
            .arg(sealed)
            .arg("-")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| VaultError::SealedKey(format!("systemd-creds didn't run: {e}")))?;
        let bytes = Zeroizing::new(out.stdout);
        if !out.status.success() {
            return Err(VaultError::SealedKey(format!(
                "systemd-creds couldn't unseal it: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        if bytes.len() != 32 {
            return Err(VaultError::SealedKey("the unsealed key isn't 32 bytes".into()));
        }
        Ok(SecretValue::from_vec(bytes.to_vec()))
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
        let sealed = dir.join(SEALED_FILE);
        if fs::symlink_metadata(&plain).is_err() {
            return Err("no plain key file to seal".into());
        }
        let tool = ready()?;
        let temp = dir.join(format!(".{SEALED_FILE}.tmp-{}", std::process::id()));
        let _ = fs::remove_file(&temp);
        let out = Command::new(&tool)
            .args(["--user", "encrypt", "--with-key=tpm2", &format!("--name={CREDENTIAL_NAME}")])
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
                "systemd-creds --user encrypt failed (it needs systemd 256 or later): {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).map_err(|e| fail(e.to_string()))?;
        match decrypt(&tool, &temp) {
            Ok(back) if back.same_as(key) => {}
            Ok(_) => return Err(fail("the sealed key didn't decrypt to the same key".into())),
            Err(error) => return Err(fail(error.to_string())),
        }
        fs::rename(&temp, &sealed).map_err(|e| fail(e.to_string()))?;
        if let Ok(folder) = fs::File::open(dir) {
            let _ = folder.sync_all();
        }
        // Overwrite, then delete, the plain key (best effort on an SSD, as with the kit).
        if let Ok(mut file) = fs::OpenOptions::new().write(true).open(&plain) {
            let _ = file.write_all(&[0u8; 32]);
            let _ = file.sync_all();
        }
        fs::remove_file(&plain).map_err(|e| format!("sealed, but the plain key file wasn't removed: {e}"))?;
        Ok(())
    }
}
