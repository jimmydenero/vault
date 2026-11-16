//! Personal details (work item #7435): a person's real name, address, birthday and phone, for the
//! few sites that need the real person. Pure functions over plain values, no I/O.
//!
//! v1 kept them on Volgenic's server as one encrypted JSON object (`personal_details.ciphertext`,
//! brennancheung/platform-ops `SiteAccounts.save_details/2`): the four fields, each trimmed and at
//! most 500 characters, an empty string for one not filled. **What is given** (the sealed
//! object's `value`, or `vault add --kind personal_details`) is that object, as v1 wrote it:
//!
//! ```json
//! {"name":"Ada Lovelace","address":"12 St James's Square, London","birthday":"December 10, 1815","phone":""}
//! ```
//!
//! Any field may be missing, `null` or empty; at least one must be filled; no other key is taken.
//! **What the vault stores** is its own small object with the filled fields only, written and
//! read only here: `{"v":1,"name":"...","address":"..."}`. The names of the filled fields (never
//! their values) are kept on the record too, so `list` can say which a form may use.
//!
//! Each field is text, as a person typed it: valid UTF-8, no control characters but a line break
//! (an address may have several lines). Nothing reads a date out of `birthday` or digits out of
//! `phone`; a form-filling agent gets the text as it was saved. Values only ever sit in wiped
//! buffers (R1); they are written into the stored object by hand, never through a formatter.
//!
//! Stored and listed only, for now: a way for a form-filling agent to use one field without
//! Volgenic's server seeing it is a later step.

use serde::Deserialize;

use crate::error::VaultError;
use crate::model::secret_bytes;
use crate::secret::{SecretValue, WipingBuf};

/// The fields, in the order v1's page shows them and the stored object writes them.
pub const FIELDS: [&str; 4] = ["name", "address", "birthday", "phone"];

/// The most characters a field holds (v1's own limit).
pub const MAX_FIELD_CHARS: usize = 500;

/// The site a personal-details secret gets when none is given: it isn't for one site.
pub const DEFAULT_SITE: &str = "personal";

/// What is given, and what is stored (with `v`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    #[serde(default)]
    v: Option<u32>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    name: Option<SecretValue>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    address: Option<SecretValue>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    birthday: Option<SecretValue>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    phone: Option<SecretValue>,
}

fn invalid(why: &str) -> VaultError {
    VaultError::InvalidSecret(why.into())
}

/// The filled fields of a details object, trimmed and checked, in `FIELDS` order.
fn read(text: &SecretValue, stored: bool) -> Result<Vec<(&'static str, SecretValue)>, VaultError> {
    // Fixed messages only: serde's own could quote a value (R2).
    let wire: Wire = serde_json::from_slice(text.expose()).map_err(|_| {
        if stored {
            invalid("the stored personal details are damaged")
        } else {
            invalid("personal details are a JSON object with name, address, birthday and phone, each a string")
        }
    })?;
    match (stored, wire.v) {
        (true, Some(1)) | (false, None | Some(1)) => {}
        (true, _) => return Err(invalid("the stored personal details are a newer form")),
        (false, _) => return Err(invalid("unknown personal details version")),
    }
    let mut filled = Vec::new();
    for (field, value) in FIELDS.into_iter().zip([wire.name, wire.address, wire.birthday, wire.phone]) {
        if let Some(value) = value {
            if let Some(value) = check_field(field, &value)? {
                filled.push((field, value));
            }
        }
    }
    if filled.is_empty() {
        return Err(invalid("personal details need at least one of name, address, birthday and phone"));
    }
    Ok(filled)
}

/// One field's text, trimmed, or None when it is empty.
fn check_field(field: &str, value: &SecretValue) -> Result<Option<SecretValue>, VaultError> {
    let text = std::str::from_utf8(value.expose()).map_err(|_| invalid(&format!("the {field} isn't UTF-8 text")))?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    if text.chars().any(|c| (c.is_control() && c != '\n') || c == '\u{7f}') {
        return Err(invalid(&format!("the {field} has a control character (only a line break is allowed)")));
    }
    if text.chars().count() > MAX_FIELD_CHARS {
        return Err(invalid(&format!("the {field} is over {MAX_FIELD_CHARS} characters")));
    }
    let mut buf = WipingBuf::with_capacity(text.len());
    buf.extend_from_slice(text.as_bytes());
    Ok(Some(buf.into_secret()))
}

/// Writes `"field":"<value>"` with the value escaped as a JSON string, straight into a wiped
/// buffer: `"` and `\` escaped, a control character as `\uXXXX`.
fn write_field(out: &mut WipingBuf, field: &str, value: &[u8]) {
    out.extend_from_slice(b"\"");
    out.extend_from_slice(field.as_bytes());
    out.extend_from_slice(b"\":\"");
    for &byte in value {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            0x00..=0x1f => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(byte >> 4)]);
                out.push(HEX[usize::from(byte & 0xf)]);
            }
            _ => out.push(byte),
        }
    }
    out.extend_from_slice(b"\"");
}

fn write_object(version: bool, fields: &[(&str, &SecretValue)]) -> SecretValue {
    let size: usize = fields.iter().map(|(_, value)| value.len() * 2 + 16).sum();
    let mut out = WipingBuf::with_capacity(size + 16);
    out.extend_from_slice(if version { &b"{\"v\":1"[..] } else { &b"{"[..] });
    for (index, (field, value)) in fields.iter().enumerate() {
        if version || index > 0 {
            out.extend_from_slice(b",");
        }
        write_field(&mut out, field, value.expose());
    }
    out.extend_from_slice(b"}");
    out.into_secret()
}

/// Turns what was given into the stored object, and the names of its filled fields.
pub(crate) fn intake(given: &SecretValue) -> Result<(SecretValue, Vec<String>), VaultError> {
    let filled = read(given, false)?;
    let names = filled.iter().map(|(field, _)| field.to_string()).collect();
    let fields: Vec<(&str, &SecretValue)> = filled.iter().map(|(field, value)| (*field, value)).collect();
    Ok((write_object(true, &fields), names))
}

/// Checks a stored details object.
pub(crate) fn validate(stored: &SecretValue) -> Result<(), VaultError> {
    read(stored, true).map(|_| ())
}

/// The object to give the vault, from fields a person typed one at a time (`vault add`): the
/// empty ones left out. The vault checks it again when it stores it.
pub fn given_from_fields(fields: &[(&str, SecretValue)]) -> SecretValue {
    let filled: Vec<(&str, &SecretValue)> =
        fields.iter().filter(|(_, value)| !value.is_empty()).map(|(field, value)| (*field, value)).collect();
    write_object(false, &filled)
}
