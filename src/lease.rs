//! Leases (#7446): the one way an app secret's value leaves the vault, sealed to one build's own
//! key, for at most a day. The decisions are pure functions here; the daemon (`server`) reads the
//! request, writes the audit lines and answers.
//!
//! A build or deploy job (run by the host's daemon, never by an agent) makes an age X25519 key of
//! its own, and the host asks the vault on its behalf:
//!
//! ```json
//! {"protocol":2,"op":"lease","job":"build:4812","recipient":"age1...","names":["NPM_TOKEN","DATABASE_URL"],
//!  "ttl_seconds":3600,"request_id":"..."}
//! ```
//!
//! For each name the vault holds as a leasable app secret it seals, with age to `recipient`:
//!
//! ```json
//! {"v":1,"lease":"build:4812","name":"NPM_TOKEN","value":"npm_...","expires_at":"2026-11-16T13:00:00Z"}
//! ```
//!
//! and answers only ciphertext: `{"ok":true,"sealed":[{"name","id","sealed_base64"}],
//! "missing":[names it holds nothing under],"expires_at","job"}`. The job binds what it opens to
//! what it asked for: it refuses a plaintext whose `v`, `lease` or `name` differ, or whose
//! `expires_at` has passed. The vault doesn't hold the job to the expiry (it can't reach the job);
//! the expiry says how long the job may use the value, inside the ciphertext, where no relay can
//! change it.
//!
//! **Only an app secret added as leasable** (`vault add --kind app_secret --leasable`, or
//! `"leasable":true` in `add_sealed`'s sealed object) can be leased. A request naming any other
//! secret it holds, of any kind, is refused whole (`not_leasable`, with those names), and nothing
//! is sealed.
//!
//! The values only ever sit in wiped buffers (R1): the plaintext is written by hand into one,
//! never through a formatter, then handed to age.

use std::io::Write;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::error::VaultError;
use crate::model::{self, Kind, Record, SecretRef, VaultDoc};
use crate::secret::{SecretValue, WipingBuf};

/// The shortest lease, in seconds.
pub const MIN_TTL_SECS: u64 = 60;
/// The longest lease: a day.
pub const MAX_TTL_SECS: u64 = 86_400;
/// The most secrets one lease names.
pub const MAX_SECRETS: usize = 64;
/// The longest job id.
pub const MAX_JOB_CHARS: usize = 128;

/// What every value of one lease is sealed with: the job, the key, the expiry.
pub struct Terms {
    pub job: String,
    recipient: age::x25519::Recipient,
    /// The recipient key's fingerprint (`backup::fingerprint`), for the audit log.
    pub fingerprint: String,
    pub ttl_seconds: u64,
    /// RFC 3339, UTC, to the second.
    pub expires_at: String,
}

impl Terms {
    /// How the audit log describes the lease: never a value.
    pub fn describe(&self) -> String {
        format!(
            "job {}, sealed to recipient {}, expires {} ({} s)",
            self.job, self.fingerprint, self.expires_at, self.ttl_seconds
        )
    }
}

fn bad(why: &str) -> VaultError {
    VaultError::BadRequest(why.into())
}

/// A job id: 1 to 128 printable ASCII characters, no spaces (`build:<id>`, `deploy:<id>`).
pub fn check_job(job: &str) -> Result<(), VaultError> {
    let ok = !job.is_empty() && job.len() <= MAX_JOB_CHARS && job.bytes().all(|b| (0x21..0x7f).contains(&b));
    if ok { Ok(()) } else { Err(bad("job is 1 to 128 printable characters, no spaces")) }
}

/// The lease's terms, from the request and the time now (Unix seconds).
pub fn terms(job: &str, recipient: &str, ttl_seconds: u64, now: u64) -> Result<Terms, VaultError> {
    check_job(job)?;
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl_seconds) {
        return Err(bad("ttl_seconds is 60 to 86400: a lease lasts at most a day"));
    }
    let recipient_text = recipient.trim();
    // Only an age X25519 key: a plugin or SSH recipient would run or trust more than a key.
    if !recipient_text.starts_with("age1") || recipient_text.len() > 100 {
        return Err(bad("recipient is an age X25519 public key (age1...)"));
    }
    let parsed = age::x25519::Recipient::from_str(recipient_text)
        .map_err(|_| bad("recipient is an age X25519 public key (age1...)"))?;
    let expires = time::OffsetDateTime::from_unix_timestamp((now + ttl_seconds) as i64)
        .map_err(|_| bad("the expiry is out of range"))?;
    let expires_at = expires
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| bad("the expiry is out of range"))?;
    Ok(Terms {
        job: job.to_string(),
        fingerprint: crate::backup::fingerprint(recipient_text),
        recipient: parsed,
        ttl_seconds,
        expires_at,
    })
}

/// The secrets a lease names: 1 to 64, each once, ids well formed.
pub fn check_secrets(secrets: &[SecretRef]) -> Result<(), VaultError> {
    if secrets.is_empty() || secrets.len() > MAX_SECRETS {
        return Err(bad("names: 1 to 64 secrets"));
    }
    for (index, secret) in secrets.iter().enumerate() {
        if let SecretRef::Id(id) = secret {
            model::validate_id(id)?;
        }
        if secrets[..index].contains(secret) {
            return Err(bad(&format!("names {} more than once", secret.label())));
        }
    }
    Ok(())
}

/// The records a lease seals, in the order named, and the names (or ids) the vault holds nothing
/// under. Refuses the whole lease when any secret it holds may not be leased (`not_leasable`,
/// with their names), or when a name and an id are the same secret.
pub(crate) fn choose<'a>(doc: &'a VaultDoc, secrets: &[SecretRef]) -> Result<(Vec<&'a Record>, Vec<String>), VaultError> {
    let mut chosen: Vec<&Record> = Vec::new();
    let mut missing = Vec::new();
    let mut refused = Vec::new();
    for secret in secrets {
        let Some(record) = doc.find_ref(secret) else {
            missing.push(match secret {
                SecretRef::Name(name) | SecretRef::Id(name) => name.clone(),
            });
            continue;
        };
        if chosen.iter().any(|seen| seen.id == record.id) {
            return Err(bad(&format!("names {:?} more than once (by name and by id)", record.name)));
        }
        if !record.may_lease() {
            refused.push(record.name.clone());
        }
        chosen.push(record);
    }
    if !refused.is_empty() {
        return Err(VaultError::NotLeasable(refused));
    }
    Ok((chosen, missing))
}

/// An app secret's value is text a build reads (an environment variable, a config line): valid
/// UTF-8 with no NUL. Any other character, line breaks included, is kept as it was given.
pub(crate) fn validate_value(value: &SecretValue) -> Result<(), VaultError> {
    let text = std::str::from_utf8(value.expose())
        .map_err(|_| VaultError::InvalidSecret("an app secret's value is UTF-8 text".into()))?;
    if text.contains('\0') {
        return Err(VaultError::InvalidSecret("an app secret's value has a NUL character".into()));
    }
    Ok(())
}

/// The sealed plaintext for one record, written straight into a wiped buffer.
fn plaintext(record: &Record, terms: &Terms) -> SecretValue {
    let mut out = WipingBuf::with_capacity(record.value.len() * 6 + record.name.len() + terms.job.len() + 128);
    out.extend_from_slice(b"{\"v\":1,");
    crate::details::write_field(&mut out, "lease", terms.job.as_bytes());
    out.extend_from_slice(b",");
    crate::details::write_field(&mut out, "name", record.name.as_bytes());
    out.extend_from_slice(b",");
    crate::details::write_field(&mut out, "value", record.value.expose());
    out.extend_from_slice(b",");
    crate::details::write_field(&mut out, "expires_at", terms.expires_at.as_bytes());
    out.extend_from_slice(b"}");
    out.into_secret()
}

/// Seals one leasable app secret to the lease's key: base64 of a binary age file. Refuses any
/// other record, whatever the caller checked before.
pub(crate) fn seal(record: &Record, terms: &Terms) -> Result<String, VaultError> {
    if !record.may_lease() || record.kind != Kind::AppSecret {
        return Err(VaultError::NotLeasable(vec![record.name.clone()]));
    }
    let failed = || VaultError::Io("sealing the lease failed".into());
    let plain = plaintext(record, terms);
    let encryptor = age::Encryptor::with_recipients(std::iter::once(&terms.recipient as &dyn age::Recipient))
        .map_err(|_| failed())?;
    let mut sealed = Vec::with_capacity(plain.len() + 512);
    let mut writer = encryptor.wrap_output(&mut sealed).map_err(|_| failed())?;
    writer.write_all(plain.expose()).map_err(|_| failed())?;
    writer.finish().map_err(|_| failed())?;
    drop(plain);
    Ok(BASE64.encode(sealed))
}
