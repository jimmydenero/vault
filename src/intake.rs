//! Sealed intake (R40): a value typed in Volgenic's app, or a plan token from a sign-in, reaches
//! the vault through Volgenic's server without the server being able to read it. The app
//! encrypts it with age to the vault's intake public key (`vault status --json`, `intake`); only
//! the vault holds the private half.
//!
//! What is sealed is a small JSON object, not the bare value, so that what decides where a value
//! may go (its name, kind, site and an API key's rule) is sealed with it:
//!
//! ```json
//! {"v":1,"name":"main","kind":"claude_plan","site":"api.anthropic.com","value":"sk-ant-oat01-..."}
//! {"v":1,"name":"openai","kind":"api-key","rule":{"host":"api.openai.com","methods":["POST"],
//!  "path":"/v1","header":"Authorization: Bearer {key}"},"value":"sk-..."}
//! {"v":1,"name":"v1-details","kind":"personal_details",
//!  "value":"{\"name\":\"Ada Lovelace\",\"address\":\"...\",\"birthday\":\"\",\"phone\":\"\"}"}
//! {"v":1,"name":"shop-npm-token","kind":"app_secret","app":"shop","leasable":true,"value":"npm_..."}
//! ```
//!
//! An app secret (#7446) names its `app`, and may be leased to builds only when its sealed object
//! says `"leasable":true` (`lease`). Both are read only from inside the ciphertext, and only an
//! app secret may carry them. A sealed app secret is added under a new name only: like an API
//! key, it can't replace a stored one (R40), since anyone can seal to the intake key and a build
//! would then run with the sealer's value.
//!
//! A value whose kind has a stored form of its own (a login's `auth.json`, personal details'
//! object) is carried as a string and read into that form when it is stored (`kinds`, `details`).
//!
//! A server that relays the ciphertext can't read the value, and can't change the rule, the kind
//! or the name it is stored under: the request's own `name` and `kind`, which the server and the
//! host can see, must match the sealed ones. What it can do is accepted in the threat model:
//! swap the public key the app encrypts to (until pairing), drop or replay a sealed value, or
//! seal a value of its own.

use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::backup;
use crate::error::VaultError;
use crate::model::{Kind, secret_bytes};
use crate::protocol::RuleInput;
use crate::secret::SecretValue;

/// The largest sealed value `add_sealed` takes, as base64.
pub const MAX_SEALED_BASE64: usize = 64 * 1024;

/// What a sealed value holds, once opened.
pub struct Sealed {
    pub name: String,
    pub kind: Kind,
    pub site: Option<String>,
    pub rule: Option<RuleInput>,
    pub username: Option<String>,
    pub app: Option<String>,
    pub leasable: bool,
    pub value: SecretValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedWire {
    #[serde(default)]
    v: Option<u32>,
    name: String,
    kind: Kind,
    #[serde(default)]
    site: Option<String>,
    #[serde(default)]
    rule: Option<RuleInput>,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    app: Option<String>,
    #[serde(default)]
    leasable: bool,
    /// A JSON string or an array of bytes; read straight into a wiping buffer (R1).
    #[serde(deserialize_with = "secret_bytes::deserialize")]
    value: SecretValue,
}

/// The intake key's public half and its fingerprint (the same 12-digit form as the recovery
/// key's), for `vault status`.
pub fn public_of(identity: &SecretValue) -> Option<(String, String)> {
    let identity = backup::parse_identity(identity).ok()?;
    let public = backup::public_of(&identity);
    let fingerprint = backup::fingerprint(&public);
    Some((public, fingerprint))
}

/// Opens a sealed value (base64 of a binary age file) with the intake key, and checks it names
/// `name` and `kind`, as the request does. The plaintext only ever sits in wiped buffers.
pub fn open(identity: &SecretValue, sealed_base64: &str, name: &str, kind: Kind) -> Result<Sealed, VaultError> {
    let invalid = |why: &str| VaultError::SealedInvalid(why.into());
    if sealed_base64.len() > MAX_SEALED_BASE64 {
        return Err(invalid("over 64 KiB"));
    }
    let data = BASE64.decode(sealed_base64.trim()).map_err(|_| invalid("not base64"))?;
    let identity = backup::parse_identity(identity).map_err(|_| invalid("the vault's intake key is damaged"))?;
    let decryptor = age::Decryptor::new_buffered(&data[..]).map_err(|_| invalid("not an age file"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| invalid("not sealed to this vault's intake key"))?;
    let mut plain = Zeroizing::new(Vec::with_capacity(data.len()));
    reader.read_to_end(&mut plain).map_err(|_| invalid("the sealed value is damaged"))?;
    // A fixed message: serde's own could quote the value (R2).
    let wire: SealedWire =
        serde_json::from_slice(&plain).map_err(|_| invalid("its contents aren't the sealed JSON object"))?;
    if wire.v.is_some_and(|v| v != 1) {
        return Err(invalid("unknown sealed version"));
    }
    if wire.name != name || wire.kind != kind {
        return Err(invalid("the request's name or kind isn't the one sealed"));
    }
    Ok(Sealed {
        name: wire.name,
        kind: wire.kind,
        site: wire.site,
        rule: wire.rule,
        username: wire.username,
        app: wire.app,
        leasable: wire.leasable,
        value: wire.value,
    })
}
