//! The kinds that make HTTPS calls for a caller with a credential of their own, and what each
//! allows (R5, R7, R9, R39). Pure data and pure functions, no I/O.
//!
//! A kind's entry decides everything a call may do: the upstream hosts, methods and paths, the
//! headers the vault sets and where their values come from, the caller headers it refuses, how an
//! upstream reply says the credential works or not, and whether the vault renews the credential
//! itself (`refresher`). The caller names a secret and sends a request; it never chooses a host
//! outside the list or a header value the vault sets. A new kind (Codex, Grok: work item #7380) is
//! one more entry here, a `Kind` variant and, when its tokens expire, a refresher.

use serde::{Deserialize, Serialize};

use crate::error::VaultError;
use crate::model::Kind;
use crate::secret::SecretValue;

/// Where a header's value comes from. Never from the caller.
#[derive(Clone, Copy, Debug)]
pub enum HeaderSource {
    /// The stored credential itself (the token).
    Token,
    // A kind with more than one stored field (#7380: Codex's ChatGPT account id, from its id
    // token) adds `Field(&'static str)` here, read from the record.
}

/// A header the vault sets on every call of a kind: `name: {prefix}{value}{suffix}`.
#[derive(Clone, Copy, Debug)]
pub struct SetHeader {
    /// Lower-case.
    pub name: &'static str,
    pub prefix: &'static str,
    pub suffix: &'static str,
    pub source: HeaderSource,
}

/// What an upstream reply says about the credential.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Not used since it was stored (or replaced), or no reply said yet.
    Unknown,
    /// The last reply that said anything about the credential accepted it.
    Works,
    /// Upstream said the credential has expired: the person signs in again.
    Expired,
    /// Upstream refused the credential (revoked, invalid, not allowed): the person signs in again.
    Refused,
}

impl HealthState {
    pub fn label(self) -> &'static str {
        match self {
            HealthState::Unknown => "unknown",
            HealthState::Works => "works",
            HealthState::Expired => "expired",
            HealthState::Refused => "refused",
        }
    }
}

/// A credential renewed by its refresher.
pub struct Renewed {
    pub value: SecretValue,
    /// When the new credential stops working, in Unix seconds.
    pub expires_at: Option<u64>,
}

/// The per-kind hook through which the vault keeps a credential working by itself (token
/// upkeep). The daemon's upkeep pass asks `due` for every record of the kind, and for each one
/// due, writes an audit line, calls `renew` and stores the result as a new version of the same
/// secret. A refresher makes only HTTPS calls to its kind's own `hosts` (R39).
#[derive(Clone, Copy)]
pub struct Refresher {
    /// Whether a credential with this expiry is due for renewal at `now` (Unix seconds). Pure.
    pub due: fn(expires_at: Option<u64>, now: u64) -> bool,
    /// Renews the credential. `Err(VaultError::CredentialRefused)` means the provider refused
    /// it and the person must sign in again; any other error is tried again at the next pass.
    pub renew: fn(client: &reqwest::blocking::Client, current: &SecretValue) -> Result<Renewed, VaultError>,
}

/// One kind's entry.
pub struct KindSpec {
    pub kind: Kind,
    /// The site a secret of this kind gets when none is given.
    pub default_site: &'static str,
    /// The exact upstream host names the vault may call with it, port 443, HTTPS only. The
    /// first is the default when the request doesn't name one.
    pub hosts: &'static [&'static str],
    /// Upper-case.
    pub methods: &'static [&'static str],
    /// Path prefixes, matched on whole segments (`rules::path_within`).
    pub path_prefixes: &'static [&'static str],
    /// The headers the vault sets. A caller may not send any of them.
    pub set_headers: &'static [SetHeader],
    /// More headers a caller may not send, besides `rules::REFUSED_HEADERS` and the ones above:
    /// another way of carrying a credential the upstream would read.
    pub refused_headers: &'static [&'static str],
    /// What a reply says about the credential: its status, and the first bytes of its body.
    pub classify: fn(status: u16, body: &[u8]) -> Option<HealthState>,
    /// Checks a value before it is stored.
    pub validate: fn(value: &SecretValue) -> Result<(), VaultError>,
    /// Token upkeep, for a kind whose credential expires and can be renewed. None: the vault
    /// never renews it, and `health` says so.
    pub refresher: Option<Refresher>,
}

/// A Claude plan: a `claude setup-token` token (`sk-ant-oat01-...`, scoped `user:inference`, valid
/// for a year), exactly what the host's model proxy store keeps today (volgenic/host
/// `fleet/model_gateway/store.mjs`): one string, no refresh token, no expiry. It goes to
/// `api.anthropic.com` (the proxy's `DEFAULT_UPSTREAM`) as `Authorization: Bearer <token>`, in
/// place of whatever the client sent (`claude_upstream.mjs`). There is nothing to renew: a new
/// sign-in replaces the token (`add_sealed` with `replace`, or `import_plan`).
pub const CLAUDE_PLAN: KindSpec = KindSpec {
    kind: Kind::ClaudePlan,
    default_site: "api.anthropic.com",
    hosts: &["api.anthropic.com"],
    methods: &["GET", "POST"],
    // Messages, count_tokens and models are all under /v1.
    path_prefixes: &["/v1"],
    set_headers: &[SetHeader { name: "authorization", prefix: "Bearer ", suffix: "", source: HeaderSource::Token }],
    refused_headers: &["x-api-key", "cookie"],
    classify: classify_anthropic,
    validate: validate_token,
    refresher: None,
};

/// Every kind with an entry.
pub const TABLE: &[&KindSpec] = &[&CLAUDE_PLAN];

/// The entry for `kind`, if it has one.
pub fn spec(kind: Kind) -> Option<&'static KindSpec> {
    TABLE.iter().copied().find(|spec| spec.kind == kind)
}

/// Whether any kind renews its own credentials (the daemon starts its upkeep pass only then).
pub fn any_refresher() -> bool {
    TABLE.iter().any(|spec| spec.refresher.is_some())
}

/// Anthropic's replies: a 2xx accepts the token; a 401 refuses it, as expired when its error
/// says so (`"OAuth token has expired"`); a 403 `permission_error` about OAuth or the token
/// refuses it. A 429, a 5xx or another 4xx says nothing about the token.
pub fn classify_anthropic(status: u16, body: &[u8]) -> Option<HealthState> {
    let says = |word: &str| memchr::memmem::find(&body.to_ascii_lowercase(), word.as_bytes()).is_some();
    match status {
        200..=299 => Some(HealthState::Works),
        401 if says("expired") => Some(HealthState::Expired),
        401 => Some(HealthState::Refused),
        403 if says("oauth") || says("token") => Some(HealthState::Refused),
        _ => None,
    }
}

/// A bearer token: 1 to 4096 printable ASCII characters with no spaces, so it can only ever be
/// one header value.
pub fn validate_token(value: &SecretValue) -> Result<(), VaultError> {
    let ok = !value.is_empty() && value.len() <= 4096 && value.expose().iter().all(u8::is_ascii_graphic);
    if ok {
        Ok(())
    } else {
        Err(VaultError::InvalidSecret("a token is 1 to 4096 printable ASCII characters, no spaces".into()))
    }
}
