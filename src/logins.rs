//! Codex and Grok logins (work item #7380): the tokens of a ChatGPT sign-in (Codex) and of a
//! grok.com sign-in (Grok Build), which the vault holds and is the only one to renew. Pure
//! functions over plain values, no I/O: reading what the host's `auth.json` holds, the form the
//! vault stores, the renewal request to the provider's token server, and what its reply means.
//!
//! **What the host's files hold** (volgenic/host `fleet/codex_login.mjs`, `fleet/grok_login.mjs`):
//!
//! ```json
//! Codex, ~/.codex/auth.json (and each account's CODEX_HOME):
//! {"auth_mode":"chatgpt","OPENAI_API_KEY":null,"last_refresh":"2026-11-15T10:00:00Z",
//!  "tokens":{"id_token":"<JWT>","access_token":"<JWT>","refresh_token":"<token>","account_id":"<uuid>"}}
//!
//! Grok, ~/.grok/auth.json, one entry per sign-in scope:
//! {"https://auth.x.ai::<client id>":{"key":"<access token>","refresh_token":"<token>",
//!  "expires_at":"2026-11-15T12:00:00Z","auth_mode":"oidc","user_id":"..."}}
//! ```
//!
//! Every other field is skipped without being kept (an `OPENAI_API_KEY` included). **What the
//! vault stores** is its own small JSON object, the same for both kinds, written and read only
//! here, so a formatting change in the host's file never reads as a new login:
//!
//! ```json
//! {"v":1,"access_token":"...","refresh_token":"...","id_token":"...","account_id":"...",
//!  "client_id":"...","user_id":"...","expires_at":1763208000}
//! ```
//!
//! Tokens are printable ASCII with no quote or backslash (JWTs and opaque OAuth tokens are), so
//! they are written into that object as they are, never through a formatter that could leave an
//! unwiped copy (R1).
//!
//! **Renewal.** Codex renews at `auth.openai.com/oauth/token` with a JSON body (Codex's own client
//! id, `grant_type=refresh_token`, the refresh token, scope `openid profile email`); Grok at
//! `auth.x.ai/oauth2/token` with a form body (the client id from its sign-in's scope). Both
//! providers rotate the refresh token: the reply's new one replaces the old, which is dead from
//! then on. A 400, 401 or 403 from the token server means the login is gone (revoked, reused,
//! expired): the person signs in again. Anything else is tried again later.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::VaultError;
use crate::model::{Kind, secret_bytes};
use crate::secret::{SecretValue, WipingBuf};

/// Codex's own OAuth client id (the one in the Codex binary), which its refresh request names.
pub const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const CODEX_REFRESH_HOST: &str = "auth.openai.com";
pub const CODEX_REFRESH_PATH: &str = "/oauth/token";
const CODEX_SCOPE: &str = "openid profile email";
/// Codex's rule for an access token with no readable expiry: renew when the last renewal is
/// older than this.
const CODEX_NO_EXPIRY_SECS: u64 = 8 * 86_400;

/// The grok.com sign-in's issuer; its scope in `auth.json` is `<issuer>::<client id>`.
pub const GROK_ISSUER: &str = "https://auth.x.ai";
pub const GROK_REFRESH_HOST: &str = "auth.x.ai";
pub const GROK_REFRESH_PATH: &str = "/oauth2/token";

/// The largest token reply the vault reads.
pub const MAX_REFRESH_REPLY: usize = 64 * 1024;

/// One login's tokens, as the vault keeps them.
pub(crate) struct Login {
    pub access_token: SecretValue,
    pub refresh_token: SecretValue,
    /// Codex: the id token, kept as the sign-in gave it (never sent anywhere).
    pub id_token: Option<SecretValue>,
    /// Codex: the ChatGPT account id, sent as `chatgpt-account-id`. Not a secret.
    pub account_id: Option<String>,
    /// Grok: the OAuth client id from the sign-in's scope, for its renewals.
    pub client_id: Option<String>,
    /// Grok: the user id the sign-in named, for a person reading the audit log. Not a secret.
    pub user_id: Option<String>,
    /// When the access token stops working, in Unix seconds, when known.
    pub expires_at: Option<u64>,
}

/// A renewal request: one HTTPS POST to the kind's token server.
pub struct RefreshCall {
    pub host: &'static str,
    pub path: &'static str,
    pub content_type: &'static str,
    pub body: Zeroizing<Vec<u8>>,
}

fn invalid(why: &str) -> VaultError {
    VaultError::InvalidSecret(why.into())
}

/// A token: 1 to 8192 printable ASCII characters, no spaces, quotes or backslashes, so it can go
/// into a header and into the stored JSON object as it is.
fn check_token(value: &SecretValue, what: &str) -> Result<(), VaultError> {
    let ok = !value.is_empty()
        && value.len() <= 8192
        && value.expose().iter().all(|b| b.is_ascii_graphic() && *b != b'"' && *b != b'\\');
    if ok { Ok(()) } else { Err(invalid(&format!("the {what} isn't a token (printable ASCII, no spaces)"))) }
}

/// A short label (an account, client or user id): 1 to 200 printable ASCII characters.
fn check_label(value: &str, what: &str) -> Result<(), VaultError> {
    let ok = !value.is_empty() && value.len() <= 200 && value.bytes().all(|b| b.is_ascii_graphic());
    if ok { Ok(()) } else { Err(invalid(&format!("the {what} isn't a plain id"))) }
}

fn copy_secret(value: &SecretValue) -> SecretValue {
    let mut buf = WipingBuf::with_capacity(value.len());
    buf.extend_from_slice(value.expose());
    buf.into_secret()
}

/// What a JWT's claims say, read from its middle part in a wiped buffer. None when it isn't one.
fn jwt_claims<T: serde::de::DeserializeOwned>(token: &SecretValue) -> Option<T> {
    let raw = token.expose();
    let mut parts = raw.split(|b| *b == b'.');
    let (_, payload, _) = (parts.next()?, parts.next()?, parts.next()?);
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload.strip_suffix(b"=").unwrap_or(payload)).ok()?);
    serde_json::from_slice(&decoded).ok()
}

fn jwt_exp(token: &SecretValue) -> Option<u64> {
    #[derive(Deserialize)]
    struct Exp {
        exp: Option<f64>,
    }
    jwt_claims::<Exp>(token).and_then(|claims| claims.exp).filter(|exp| *exp > 0.0).map(|exp| exp as u64)
}

/// Codex's account id, from its id token's `https://api.openai.com/auth` claim.
fn codex_account_from_id_token(id_token: &SecretValue) -> Option<String> {
    #[derive(Deserialize)]
    struct Auth {
        chatgpt_account_id: Option<String>,
    }
    #[derive(Deserialize)]
    struct Claims {
        #[serde(rename = "https://api.openai.com/auth")]
        auth: Option<Auth>,
    }
    jwt_claims::<Claims>(id_token)?.auth?.chatgpt_account_id
}

fn rfc3339_to_unix(text: &str) -> Option<u64> {
    let at = time::OffsetDateTime::parse(text.trim(), &time::format_description::well_known::Rfc3339).ok()?;
    u64::try_from(at.unix_timestamp()).ok()
}

/// `expires_at` as Grok may write it: an RFC 3339 time, or a Unix time in seconds or milliseconds.
fn grok_expiry(value: &serde_json::Value) -> Option<u64> {
    let from_number = |n: f64| if n > 1e12 { (n / 1000.0) as u64 } else { n as u64 };
    match value {
        serde_json::Value::Number(n) => n.as_f64().filter(|n| *n > 0.0).map(from_number),
        serde_json::Value::String(text) if text.trim().bytes().all(|b| b.is_ascii_digit()) && !text.trim().is_empty() => {
            text.trim().parse::<f64>().ok().map(from_number)
        }
        serde_json::Value::String(text) => rfc3339_to_unix(text),
        _ => None,
    }
}

// ---- the host's auth.json ----

#[derive(Deserialize)]
struct CodexAuthWire {
    #[serde(default)]
    auth_mode: Option<String>,
    #[serde(default)]
    tokens: Option<CodexTokensWire>,
    #[serde(default)]
    last_refresh: Option<String>,
}

#[derive(Deserialize)]
struct CodexTokensWire {
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    id_token: Option<SecretValue>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    access_token: Option<SecretValue>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    refresh_token: Option<SecretValue>,
    #[serde(default)]
    account_id: Option<String>,
}

/// Reads a Codex `auth.json` (a ChatGPT sign-in). Fixed messages only: serde's own could quote a
/// token (R2).
fn codex_from_auth_json(text: &SecretValue) -> Result<Login, VaultError> {
    let wire: CodexAuthWire =
        serde_json::from_slice(text.expose()).map_err(|_| invalid("this isn't a Codex auth.json (a JSON object)"))?;
    if wire.auth_mode.as_deref().is_some_and(|mode| !mode.eq_ignore_ascii_case("chatgpt")) {
        return Err(invalid("this Codex auth.json isn't a ChatGPT sign-in (an API key has nothing to renew)"));
    }
    let tokens = wire.tokens.ok_or_else(|| invalid("this Codex auth.json has no ChatGPT sign-in (no tokens)"))?;
    let access_token = tokens.access_token.ok_or_else(|| invalid("this Codex auth.json has no access token"))?;
    let refresh_token = tokens
        .refresh_token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| invalid("this Codex auth.json has no refresh token (a container's copy can't be imported)"))?;
    let id_token = tokens.id_token.ok_or_else(|| invalid("this Codex auth.json has no id token"))?;
    check_token(&access_token, "access token")?;
    check_token(&refresh_token, "refresh token")?;
    check_token(&id_token, "id token")?;
    let account_id = tokens
        .account_id
        .filter(|id| !id.is_empty())
        .or_else(|| codex_account_from_id_token(&id_token))
        .ok_or_else(|| invalid("this Codex auth.json names no ChatGPT account id"))?;
    check_label(&account_id, "account id")?;
    let last_refresh = wire.last_refresh.as_deref().and_then(rfc3339_to_unix);
    let expires_at = jwt_exp(&access_token).or_else(|| last_refresh.map(|at| at + CODEX_NO_EXPIRY_SECS));
    Ok(Login {
        access_token,
        refresh_token,
        id_token: Some(id_token),
        account_id: Some(account_id),
        client_id: None,
        user_id: None,
        expires_at,
    })
}

#[derive(Deserialize)]
struct GrokEntryWire {
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    key: Option<SecretValue>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    refresh_token: Option<SecretValue>,
    #[serde(default)]
    expires_at: Option<serde_json::Value>,
    #[serde(default)]
    auth_mode: Option<String>,
    #[serde(default)]
    user_id: Option<serde_json::Value>,
}

/// The first grok.com scope of a Grok `auth.json`; every other entry is skipped unread.
struct GrokAuthWire(Option<(String, GrokEntryWire)>);

impl<'de> Deserialize<'de> for GrokAuthWire {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entries;
        impl<'de> Visitor<'de> for Entries {
            type Value = GrokAuthWire;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a Grok auth.json object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<GrokAuthWire, A::Error> {
                let mut found = None;
                let prefix = format!("{GROK_ISSUER}::");
                while let Some(scope) = map.next_key::<String>()? {
                    if found.is_none() && scope.starts_with(&prefix) {
                        found = Some((scope, map.next_value::<GrokEntryWire>()?));
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(GrokAuthWire(found))
            }
        }
        deserializer.deserialize_map(Entries)
    }
}

/// Reads a Grok `auth.json` (a grok.com sign-in).
fn grok_from_auth_json(text: &SecretValue) -> Result<Login, VaultError> {
    let wire: GrokAuthWire =
        serde_json::from_slice(text.expose()).map_err(|_| invalid("this isn't a Grok auth.json (a JSON object of sign-ins)"))?;
    let (scope, entry) = wire.0.ok_or_else(|| invalid("this Grok auth.json has no grok.com sign-in (https://auth.x.ai::...)"))?;
    if entry.auth_mode.as_deref().is_some_and(|mode| mode.eq_ignore_ascii_case("api_key")) {
        return Err(invalid("this Grok auth.json holds an API key, not a grok.com sign-in"));
    }
    let client_id = scope.split_once("::").map(|(_, id)| id.to_string()).unwrap_or_default();
    check_label(&client_id, "client id")?;
    let access_token = entry.key.ok_or_else(|| invalid("this Grok sign-in has no access token (key)"))?;
    let refresh_token = entry
        .refresh_token
        .filter(|token| !token.is_empty())
        .ok_or_else(|| invalid("this Grok sign-in has no refresh token (a container's copy can't be imported)"))?;
    check_token(&access_token, "access token")?;
    check_token(&refresh_token, "refresh token")?;
    let user_id = match entry.user_id {
        Some(serde_json::Value::String(id)) if !id.is_empty() => Some(id),
        Some(serde_json::Value::Number(id)) => Some(id.to_string()),
        _ => None,
    };
    if let Some(id) = &user_id {
        check_label(id, "user id")?;
    }
    let expires_at = entry.expires_at.as_ref().and_then(grok_expiry).or_else(|| jwt_exp(&access_token));
    Ok(Login {
        access_token,
        refresh_token,
        id_token: None,
        account_id: None,
        client_id: Some(client_id),
        user_id,
        expires_at,
    })
}

/// Reads what the host gives for a login of `kind` (its `auth.json`, whole) into the form the
/// vault stores, and when its access token expires.
pub(crate) fn intake(kind: Kind, text: &SecretValue) -> Result<(SecretValue, Option<u64>), VaultError> {
    let login = match kind {
        Kind::CodexLogin => codex_from_auth_json(text)?,
        Kind::GrokLogin => grok_from_auth_json(text)?,
        _ => return Err(VaultError::WrongKind),
    };
    let expires_at = login.expires_at;
    Ok((login.to_value(), expires_at))
}

pub(crate) fn intake_codex(text: &SecretValue) -> Result<(SecretValue, Option<u64>), VaultError> {
    intake(Kind::CodexLogin, text)
}

pub(crate) fn intake_grok(text: &SecretValue) -> Result<(SecretValue, Option<u64>), VaultError> {
    intake(Kind::GrokLogin, text)
}

// ---- the stored form ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredWire {
    v: u32,
    #[serde(deserialize_with = "secret_bytes::deserialize")]
    access_token: SecretValue,
    #[serde(deserialize_with = "secret_bytes::deserialize")]
    refresh_token: SecretValue,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    id_token: Option<SecretValue>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    #[serde(default)]
    expires_at: Option<u64>,
}

impl Login {
    /// Reads a stored login.
    pub(crate) fn read(kind: Kind, stored: &SecretValue) -> Result<Login, VaultError> {
        let wire: StoredWire = serde_json::from_slice(stored.expose()).map_err(|_| invalid("the stored login is damaged"))?;
        if wire.v != 1 {
            return Err(invalid("the stored login is a newer form"));
        }
        let login = Login {
            access_token: wire.access_token,
            refresh_token: wire.refresh_token,
            id_token: wire.id_token,
            account_id: wire.account_id,
            client_id: wire.client_id,
            user_id: wire.user_id,
            expires_at: wire.expires_at,
        };
        login.check(kind)?;
        Ok(login)
    }

    fn check(&self, kind: Kind) -> Result<(), VaultError> {
        check_token(&self.access_token, "access token")?;
        check_token(&self.refresh_token, "refresh token")?;
        if let Some(id_token) = &self.id_token {
            check_token(id_token, "id token")?;
        }
        match kind {
            Kind::CodexLogin => check_label(self.account_id.as_deref().unwrap_or(""), "account id"),
            Kind::GrokLogin => check_label(self.client_id.as_deref().unwrap_or(""), "client id"),
            _ => Err(VaultError::WrongKind),
        }
    }

    /// The stored form, written straight into a wiped buffer (R1). Its tokens were checked to
    /// need no escaping; the ids go through the JSON encoder, as they aren't secrets.
    pub(crate) fn to_value(&self) -> SecretValue {
        let tokens = self.access_token.len() + self.refresh_token.len() + self.id_token.as_ref().map_or(0, SecretValue::len);
        let mut out = WipingBuf::with_capacity(tokens + 1024);
        out.extend_from_slice(b"{\"v\":1,\"access_token\":\"");
        out.extend_from_slice(self.access_token.expose());
        out.extend_from_slice(b"\",\"refresh_token\":\"");
        out.extend_from_slice(self.refresh_token.expose());
        out.extend_from_slice(b"\"");
        if let Some(id_token) = &self.id_token {
            out.extend_from_slice(b",\"id_token\":\"");
            out.extend_from_slice(id_token.expose());
            out.extend_from_slice(b"\"");
        }
        for (field, value) in [("account_id", &self.account_id), ("client_id", &self.client_id), ("user_id", &self.user_id)] {
            if let Some(value) = value {
                let encoded = serde_json::to_string(value).unwrap_or_else(|_| "\"\"".into());
                out.extend_from_slice(format!(",\"{field}\":{encoded}").as_bytes());
            }
        }
        if let Some(expires_at) = self.expires_at {
            out.extend_from_slice(format!(",\"expires_at\":{expires_at}").as_bytes());
        }
        out.extend_from_slice(b"}");
        out.into_secret()
    }
}

/// A fingerprint of a stored login, kept inside the vault file only, so an import repeated with
/// the same `auth.json` is recognised after the vault has renewed the login. Never returned.
pub(crate) fn digest(stored: &SecretValue) -> String {
    hex::encode(Sha256::digest(stored.expose()))
}

/// Checks a stored login of `kind` (the kind table's `validate`).
pub(crate) fn validate_codex(stored: &SecretValue) -> Result<(), VaultError> {
    Login::read(Kind::CodexLogin, stored).map(|_| ())
}

pub(crate) fn validate_grok(stored: &SecretValue) -> Result<(), VaultError> {
    Login::read(Kind::GrokLogin, stored).map(|_| ())
}

// ---- renewal ----

/// The renewal request for a stored Codex login.
pub(crate) fn codex_refresh_call(stored: &SecretValue) -> Result<RefreshCall, VaultError> {
    let login = Login::read(Kind::CodexLogin, stored)?;
    let mut body = Zeroizing::new(Vec::with_capacity(login.refresh_token.len() + 256));
    body.extend_from_slice(format!("{{\"client_id\":\"{CODEX_CLIENT_ID}\",\"grant_type\":\"refresh_token\",\"refresh_token\":\"").as_bytes());
    body.extend_from_slice(login.refresh_token.expose());
    body.extend_from_slice(format!("\",\"scope\":\"{CODEX_SCOPE}\"}}").as_bytes());
    Ok(RefreshCall { host: CODEX_REFRESH_HOST, path: CODEX_REFRESH_PATH, content_type: "application/json", body })
}

/// The renewal request for a stored Grok login: a standard OAuth refresh, form-encoded.
pub(crate) fn grok_refresh_call(stored: &SecretValue) -> Result<RefreshCall, VaultError> {
    let login = Login::read(Kind::GrokLogin, stored)?;
    let client_id = login.client_id.as_deref().unwrap_or("");
    let mut body = Zeroizing::new(Vec::with_capacity(login.refresh_token.len() * 3 + 256));
    body.extend_from_slice(b"grant_type=refresh_token&client_id=");
    for piece in url::form_urlencoded::byte_serialize(client_id.as_bytes()) {
        body.extend_from_slice(piece.as_bytes());
    }
    body.extend_from_slice(b"&refresh_token=");
    for piece in url::form_urlencoded::byte_serialize(login.refresh_token.expose()) {
        body.extend_from_slice(piece.as_bytes());
    }
    Ok(RefreshCall {
        host: GROK_REFRESH_HOST,
        path: GROK_REFRESH_PATH,
        content_type: "application/x-www-form-urlencoded",
        body,
    })
}

#[derive(Deserialize)]
struct TokenReplyWire {
    #[serde(deserialize_with = "secret_bytes::deserialize")]
    access_token: SecretValue,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    refresh_token: Option<SecretValue>,
    #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
    id_token: Option<SecretValue>,
    #[serde(default)]
    expires_in: Option<f64>,
}

/// What the token server's reply means for a stored login: the renewed login's stored form and
/// expiry, `CredentialRefused` (sign in again), or another error (try again later).
fn renewed(kind: Kind, stored: &SecretValue, status: u16, body: &[u8], now: u64) -> Result<(SecretValue, Option<u64>), VaultError> {
    match status {
        200..=299 => {}
        400 | 401 | 403 => return Err(VaultError::CredentialRefused),
        other => return Err(VaultError::UpstreamFailed(format!("the token server answered {other}"))),
    }
    let old = Login::read(kind, stored)?;
    let reply: TokenReplyWire = serde_json::from_slice(body)
        .map_err(|_| VaultError::UpstreamFailed("the token server's reply had no access token".into()))?;
    check_token(&reply.access_token, "renewed access token")?;
    let refresh_token = match reply.refresh_token.filter(|token| !token.is_empty()) {
        Some(token) => {
            check_token(&token, "renewed refresh token")?;
            token
        }
        // The provider kept the refresh token as it was.
        None => copy_secret(&old.refresh_token),
    };
    let id_token = match (reply.id_token.filter(|token| !token.is_empty()), &old.id_token) {
        (Some(token), _) if check_token(&token, "renewed id token").is_ok() => Some(token),
        (_, Some(old)) => Some(copy_secret(old)),
        (_, None) => None,
    };
    let expires_at = jwt_exp(&reply.access_token)
        .or_else(|| reply.expires_in.filter(|secs| *secs > 0.0).map(|secs| now + secs as u64))
        .or(if kind == Kind::CodexLogin { Some(now + CODEX_NO_EXPIRY_SECS) } else { None });
    let login = Login {
        access_token: reply.access_token,
        refresh_token,
        id_token,
        account_id: old.account_id,
        client_id: old.client_id,
        user_id: old.user_id,
        expires_at,
    };
    login.check(kind)?;
    Ok((login.to_value(), expires_at))
}

pub(crate) fn codex_renewed(stored: &SecretValue, status: u16, body: &[u8], now: u64) -> Result<(SecretValue, Option<u64>), VaultError> {
    renewed(Kind::CodexLogin, stored, status, body, now)
}

pub(crate) fn grok_renewed(stored: &SecretValue, status: u16, body: &[u8], now: u64) -> Result<(SecretValue, Option<u64>), VaultError> {
    renewed(Kind::GrokLogin, stored, status, body, now)
}

/// The access token and the account id a stored login sends upstream.
pub(crate) fn access(kind: Kind, stored: &SecretValue) -> Result<(SecretValue, SecretValue, Option<String>), VaultError> {
    let login = Login::read(kind, stored)?;
    Ok((login.access_token, login.refresh_token, login.account_id))
}
