//! Wrapping the vault key with this Mac's Secure Enclave (macOS only, #7689).
//!
//! The Enclave's half is CryptoKit, in `src/macos/security.swift`: a P-256 key made in the Enclave
//! (`SecureEnclave.P256.KeyAgreement`, access `privateKeyUsage` after the first unlock, this
//! device only), an ECDH with a one-time software key, HKDF-SHA256, then AES-GCM over the 32 bytes.
//! `vault.key.se` holds the Enclave's encrypted handle to its key, the one-time public key and the
//! sealed bytes; only this Mac's Enclave can open it. Here are the file's checks and the seal's
//! round trip, the same steps as the TPM's on Linux.
//!
//! The Enclave sits behind a trait so a `test-stubs` build can stand one in that never touches
//! the real Enclave (no check ever makes a key in this Mac's Enclave).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use zeroize::Zeroizing;

use super::{ENCLAVE_FILE, KEY_FILE, check_own_file, replace_plain};
use crate::error::VaultError;
use crate::secret::SecretValue;

/// The largest wrapped file: the Enclave's handle is a few hundred bytes.
const MAX_WRAPPED: usize = 8192;

/// What wraps and unwraps the vault key.
trait Enclave {
    /// Why it can't wrap here, or nothing when it can.
    fn ready(&self) -> Result<(), String>;
    fn wrap(&self, key: &SecretValue) -> Result<Vec<u8>, String>;
    fn unwrap(&self, wrapped: &[u8]) -> Result<SecretValue, String>;
}

/// This Mac's Secure Enclave, through CryptoKit. Not in a `test-stubs` build.
#[cfg(not(feature = "test-stubs"))]
struct Real;

#[cfg(not(feature = "test-stubs"))]
unsafe extern "C" {
    fn vault_se_available() -> i32;
    fn vault_se_wrap(key: *const u8, key_len: usize, out: *mut u8, out_cap: usize, out_len: *mut usize) -> i32;
    fn vault_se_unwrap(wrapped: *const u8, wrapped_len: usize, out: *mut u8) -> i32;
}

/// The Swift side's results (`security.swift`).
#[cfg(not(feature = "test-stubs"))]
fn result(code: i32) -> Result<(), String> {
    match code {
        0 => Ok(()),
        1 => Err("this Mac has no Secure Enclave".into()),
        4 => Err("the wrapped key file isn't one the vault wrote".into()),
        _ => Err("the Secure Enclave refused it (a key made on another Mac, or the Enclave was reset)".into()),
    }
}

#[cfg(not(feature = "test-stubs"))]
impl Enclave for Real {
    fn ready(&self) -> Result<(), String> {
        if unsafe { vault_se_available() } == 1 { Ok(()) } else { Err("this Mac has no Secure Enclave".into()) }
    }

    fn wrap(&self, key: &SecretValue) -> Result<Vec<u8>, String> {
        // The seal's call site of `expose` in R1: the key goes to the Enclave's seal, nowhere else.
        let key = key.expose();
        let mut out = vec![0u8; MAX_WRAPPED];
        let mut len = 0usize;
        result(unsafe { vault_se_wrap(key.as_ptr(), key.len(), out.as_mut_ptr(), out.len(), &mut len) })?;
        out.truncate(len);
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<SecretValue, String> {
        // Into a fixed buffer, wiped on drop (R1).
        let mut key = Zeroizing::new([0u8; 32]);
        result(unsafe { vault_se_unwrap(wrapped.as_ptr(), wrapped.len(), key.as_mut_ptr()) })?;
        Ok(SecretValue::from_vec(key.to_vec()))
    }
}

/// A `test-stubs` build's stand-in, never a release: wraps with XChaCha20-Poly1305 under the
/// 32-byte file `VAULT_TEST_ENCLAVE_KEY` names, the "Mac's" key. Another file is "another Mac".
#[cfg(feature = "test-stubs")]
struct Stub;

#[cfg(feature = "test-stubs")]
impl Stub {
    fn key(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let path = std::env::var_os("VAULT_TEST_ENCLAVE_KEY").ok_or("this Mac has no Secure Enclave (a test-stubs build without VAULT_TEST_ENCLAVE_KEY)")?;
        let key = Zeroizing::new(fs::read(path).map_err(|e| format!("the stand-in Enclave's key: {e}"))?);
        if key.len() != 32 {
            return Err("the stand-in Enclave's key isn't 32 bytes".into());
        }
        Ok(key)
    }
}

#[cfg(feature = "test-stubs")]
impl Enclave for Stub {
    fn ready(&self) -> Result<(), String> {
        self.key().map(|_| ())
    }

    fn wrap(&self, key: &SecretValue) -> Result<Vec<u8>, String> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&self.key()?).map_err(|e| e.to_string())?;
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
        let sealed = cipher.encrypt(&nonce.into(), key.expose()).map_err(|_| "the stand-in Enclave failed".to_string())?;
        Ok([b"VST1".as_slice(), &nonce, &sealed].concat())
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<SecretValue, String> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        if wrapped.len() < 28 || &wrapped[..4] != b"VST1" {
            return Err("the wrapped key file isn't one the vault wrote".into());
        }
        let cipher = chacha20poly1305::XChaCha20Poly1305::new_from_slice(&self.key()?).map_err(|e| e.to_string())?;
        let nonce: [u8; 24] = wrapped[4..28].try_into().map_err(|_| "short".to_string())?;
        let plain = Zeroizing::new(
            cipher
                .decrypt(&nonce.into(), &wrapped[28..])
                .map_err(|_| "the Secure Enclave refused it (a key made on another Mac, or the Enclave was reset)".to_string())?,
        );
        Ok(SecretValue::from_vec(plain.to_vec()))
    }
}

#[cfg(not(feature = "test-stubs"))]
fn enclave() -> impl Enclave {
    Real
}

#[cfg(feature = "test-stubs")]
fn enclave() -> impl Enclave {
    Stub
}

pub(super) fn ready() -> Result<(), String> {
    enclave().ready()
}

/// Reads `vault.key.se` (the owner's, 0600, not too large) and unwraps it.
fn read_and_unwrap(path: &Path) -> Result<SecretValue, VaultError> {
    check_own_file(path)?;
    let wrapped = fs::read(path)?;
    if wrapped.len() > MAX_WRAPPED {
        return Err(VaultError::SealedKey("the wrapped key file is too large to be one".into()));
    }
    let key = enclave().unwrap(&wrapped).map_err(VaultError::SealedKey)?;
    if key.len() != 32 {
        return Err(VaultError::SealedKey("the unwrapped key isn't 32 bytes".into()));
    }
    Ok(key)
}

/// Unwraps the vault key at the daemon's start: no prompt, no dialog.
pub fn unseal(dir: &Path) -> Result<SecretValue, VaultError> {
    read_and_unwrap(&dir.join(ENCLAVE_FILE))
}

/// Wraps the key file: a new Enclave key wraps `key`, the wrapped file is read back and
/// unwrapped, and only when that gives back `key` is it put in place and the plain file wiped.
/// Any failure leaves the plain file as it was.
pub fn seal(dir: &Path, key: &SecretValue) -> Result<(), String> {
    if fs::symlink_metadata(dir.join(KEY_FILE)).is_err() {
        return Err("no plain key file to seal".into());
    }
    let enclave = enclave();
    enclave.ready()?;
    let wrapped = enclave.wrap(key)?;
    let temp = dir.join(format!(".{ENCLAVE_FILE}.tmp-{}", std::process::id()));
    let _ = fs::remove_file(&temp);
    let fail = |why: String| {
        let _ = fs::remove_file(&temp);
        why
    };
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).map_err(|e| e.to_string())?;
    file.write_all(&wrapped).and_then(|()| file.sync_all()).map_err(|e| fail(e.to_string()))?;
    match read_and_unwrap(&temp) {
        Ok(back) if back.same_as(key) => {}
        Ok(_) => return Err(fail("the wrapped key didn't unwrap to the same key".into())),
        Err(error) => return Err(fail(error.to_string())),
    }
    replace_plain(dir, &temp, ENCLAVE_FILE)
}
