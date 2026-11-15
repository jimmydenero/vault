//! The local socket's protocol: one JSON request per connection, one JSON reply line back.
//!
//! The daemon accepts connections only from the owner's own user ID, not root (R22). Every
//! agent on the machine runs as the owner, so every request here is open to every agent.
//!
//! **Versions and request ids (protocol 2).** A request may carry `"protocol": 2` and a
//! `"request_id"` (a string of at most 128 printable ASCII characters, or a whole number). Every
//! reply, errors included, carries `"protocol"` (the daemon's version, `PROTOCOL_VERSION`) and
//! echoes the `request_id` exactly as sent. A request with no `protocol` is protocol 1 and is
//! served the same way: everything protocol 2 added is optional on the way in and extra fields
//! on the way out. A request for a newer protocol than the daemon's is refused with
//! `unsupported_protocol`.
//!
//! **Naming a secret.** `totp`, `proxy`, `delete` and `rename` take `"name"` or `"id"` (the
//! secret's stable id from `list`), exactly one of them.
//!
//! For agents:
//!   {"op":"list"}
//!   {"op":"totp","name":"github-2fa"}                  (or "id":"<32 hex digits>")
//!   {"op":"proxy","name":"openai","method":"GET","path":"/v1/models",
//!    "headers":{"accept":"application/json"},"body":"..."}            (or "body_base64")
//!
//! For the host daemon's agent browser (the browser on this machine, over DevTools on
//! 127.0.0.1; see `fill`):
//!   {"op":"fill","name":"shopify","cdp":{"port":9222,"target_id":"<tab>"},
//!    "fields":{"username":<backendNodeId>,"password":<backendNodeId>},"expect_site":"shopify.com"}
//!   {"op":"generate-login","name":"shopify","site":"shopify.com","username":"jo@example.com",
//!    "length":20?}
//!
//! For the command-line tool (R13: only the daemon changes the vault; R26):
//!   status, audit, add, delete, rename, confirm-kit, reset, restore,
//!   backup         write this generation's backup if it isn't written yet, and verify it
//!   verify-backup  decrypt the newest backup with the check key and compare it
//!   read-backup    the newest backup's encrypted bytes, for checks with the recovery key
//!                  that the command-line tool makes itself
//!
//! For the owner's mirror agent (R32): mirror-plan, mirror-report.
//!
//! `restore` with a file sends the file's bytes right after its request line, as they are.
//!
//! `add`, `confirm-kit`, `reset` and `restore` carry a typed value or the recovery key. The
//! command-line tool sends them only after checking that the socket and the process behind it
//! are its own user's (R22, R27).
//!
//! No reply type has a field that could carry a secret value (R4): `SecretValue` doesn't
//! implement `Serialize`, so it can't appear in any of them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::audit::AuditLine;
use crate::error::VaultError;
use crate::model::{self, BackupStatus, Kind, MirrorState, SecretRef, SecretSummary, secret_bytes};
use crate::secret::SecretValue;

pub const MAX_REQUEST_LINE: usize = 2 * 1024 * 1024;

/// The protocol this build speaks. 1 is the protocol of pull requests #2 to #4 (no version, no
/// request id, secrets by name only); 2 adds the version, request ids, secret ids and `rename`.
pub const PROTOCOL_VERSION: u32 = 2;

/// What every request carries besides its operation: its protocol version and request id.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// 1 when the request didn't say.
    pub protocol: u32,
    /// Exactly as the caller sent it, to echo back.
    pub request_id: Option<serde_json::Value>,
}

impl Default for Envelope {
    fn default() -> Self {
        Envelope { protocol: 1, request_id: None }
    }
}

impl Envelope {
    /// The request id as the audit log records it.
    pub fn request_id_text(&self) -> Option<String> {
        match &self.request_id {
            Some(serde_json::Value::String(text)) => Some(text.clone()),
            Some(other) => Some(other.to_string()),
            None => None,
        }
    }
}

/// Reads the envelope alone; every other field is skipped without being kept (R1). Returns the
/// envelope even when it is unacceptable, so the refusal can still echo an acceptable request id.
pub fn parse_envelope(line: &[u8]) -> (Envelope, Result<(), VaultError>) {
    #[derive(Deserialize)]
    struct Wire {
        #[serde(default)]
        protocol: Option<serde_json::Value>,
        #[serde(default)]
        request_id: Option<serde_json::Value>,
    }
    let Ok(wire) = serde_json::from_slice::<Wire>(line) else {
        return (Envelope::default(), Err(VaultError::BadRequest("not a JSON object".into())));
    };
    let request_id = wire.request_id.filter(|value| !value.is_null());
    let id_ok = match &request_id {
        None => true,
        Some(serde_json::Value::String(text)) => {
            !text.is_empty() && text.len() <= 128 && text.bytes().all(|b| (0x20..0x7f).contains(&b))
        }
        Some(serde_json::Value::Number(number)) => number.is_u64(),
        Some(_) => false,
    };
    // No `protocol` is protocol 1; anything but a whole number from 1 is malformed (`None`).
    let protocol = match &wire.protocol {
        None => Some(1),
        Some(value) => value.as_u64().and_then(|v| u32::try_from(v).ok()).filter(|v| *v >= 1),
    };
    let envelope = Envelope { protocol: protocol.unwrap_or(1), request_id: request_id.filter(|_| id_ok) };
    let result = match protocol {
        _ if !id_ok => Err(VaultError::BadRequest(
            "request_id is a string of 1 to 128 printable ASCII characters, or a whole number".into(),
        )),
        None => Err(VaultError::BadRequest("protocol is a whole number from 1".into())),
        Some(version) if version > PROTOCOL_VERSION => Err(VaultError::UnsupportedProtocol(version)),
        Some(_) => Ok(()),
    };
    (envelope, result)
}

/// A reply as it goes on the wire: the reply's own fields, plus the protocol version and the
/// request's id.
#[derive(Serialize)]
pub struct Framed<'a, T: Serialize> {
    #[serde(flatten)]
    pub body: &'a T,
    pub protocol: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<&'a serde_json::Value>,
}

/// What the command-line tool reads of every reply before the reply itself.
#[derive(Deserialize)]
pub struct ReplyFrame {
    #[serde(default)]
    pub protocol: Option<u32>,
    #[serde(default)]
    pub request_id: Option<serde_json::Value>,
}

/// An API key's rule as the person typed it. The daemon parses and checks it (R7); it never
/// takes a ready-made rule from a caller.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RuleInput {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    pub methods: Vec<String>,
    pub path: String,
    pub header: String,
}

/// A request, as `parse_request` reads it.
#[derive(Debug)]
pub enum Request {
    List,
    Totp {
        secret: SecretRef,
    },
    Proxy {
        secret: SecretRef,
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: Option<String>,
        body_base64: Option<String>,
    },
    Fill {
        name: String,
        request: crate::fill::FillRequest,
    },
    GenerateLogin {
        name: String,
        site: String,
        username: String,
        length: Option<usize>,
    },
    Status,
    Audit {
        all: bool,
    },
    Add {
        name: String,
        kind: Kind,
        site: String,
        rule: Option<RuleInput>,
        username: Option<String>,
        value: SecretValue,
    },
    Delete {
        secret: SecretRef,
    },
    Rename {
        secret: SecretRef,
        new_name: String,
    },
    ConfirmKit {
        recovery_key: SecretValue,
    },
    Reset {
        recovery_key: Option<SecretValue>,
    },
    Restore {
        recovery_key: SecretValue,
        /// The size of a backup file the person named (`vault restore FILE`). Its bytes follow
        /// the request line as they are, up to `backup::MAX_BACKUP_BYTES`. Without it, the
        /// restore point `vault reset` kept.
        backup_len: Option<usize>,
        source: Option<String>,
    },
    Backup,
    VerifyBackup,
    ReadBackup,
    MirrorPlan,
    MirrorReport {
        ok: bool,
        newest_file: Option<String>,
        newest_generation: Option<u64>,
        copied: usize,
        already_there: usize,
        detail: String,
    },
}

/// Parses one request line (R1). Serde's `#[serde(tag = "op")]` enums first copy every field
/// into an intermediate buffer of their own, which nothing wipes, so a typed value or recovery
/// key would be left behind in freed memory. Instead this reads `op` alone (skipping the other
/// fields without keeping them), then deserializes the line again straight into that
/// operation's own struct, whose secret fields go directly into wiping buffers.
pub fn parse_request(line: &[u8]) -> Result<Request, serde_json::Error> {
    use serde::de::Error;

    #[derive(Deserialize)]
    struct Op {
        op: String,
    }

    #[derive(Deserialize)]
    struct Named {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        id: Option<String>,
    }

    #[derive(Deserialize)]
    struct RenameWire {
        new_name: String,
    }

    #[derive(Deserialize)]
    struct ProxyWire {
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        id: Option<String>,
        method: String,
        path: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        body: Option<String>,
        #[serde(default)]
        body_base64: Option<String>,
    }

    #[derive(Deserialize)]
    struct CdpWire {
        port: u16,
        target_id: String,
    }

    #[derive(Deserialize)]
    struct FieldsWire {
        username: u64,
        password: u64,
    }

    #[derive(Deserialize)]
    struct FillWire {
        name: String,
        cdp: CdpWire,
        fields: FieldsWire,
        expect_site: String,
    }

    #[derive(Deserialize)]
    struct GenerateLoginWire {
        name: String,
        site: String,
        username: String,
        #[serde(default)]
        length: Option<usize>,
    }

    #[derive(Deserialize)]
    struct AuditWire {
        #[serde(default)]
        all: bool,
    }

    #[derive(Deserialize)]
    struct AddWire {
        name: String,
        kind: Kind,
        site: String,
        #[serde(default)]
        rule: Option<RuleInput>,
        #[serde(default)]
        username: Option<String>,
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        value: SecretValue,
    }

    #[derive(Deserialize)]
    struct ConfirmKitWire {
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        recovery_key: SecretValue,
    }

    #[derive(Deserialize)]
    struct ResetWire {
        #[serde(default, deserialize_with = "secret_bytes::deserialize_opt")]
        recovery_key: Option<SecretValue>,
    }

    #[derive(Deserialize)]
    struct RestoreWire {
        #[serde(deserialize_with = "secret_bytes::deserialize")]
        recovery_key: SecretValue,
        #[serde(default)]
        backup_len: Option<usize>,
        #[serde(default)]
        source: Option<String>,
    }

    #[derive(Deserialize)]
    struct MirrorReportWire {
        ok: bool,
        #[serde(default)]
        newest_file: Option<String>,
        #[serde(default)]
        newest_generation: Option<u64>,
        #[serde(default)]
        copied: usize,
        #[serde(default)]
        already_there: usize,
        #[serde(default)]
        detail: String,
    }

    /// Exactly one of `name` and `id`.
    fn secret_ref(name: Option<String>, id: Option<String>) -> Result<SecretRef, serde_json::Error> {
        match (name, id) {
            (Some(name), None) => Ok(SecretRef::Name(name)),
            (None, Some(id)) => {
                model::validate_id(&id).map_err(|_| serde_json::Error::custom("an id is 32 lower-case hex digits"))?;
                Ok(SecretRef::Id(id))
            }
            _ => Err(serde_json::Error::custom("give name or id, exactly one")),
        }
    }
    let named = |line: &[u8]| -> Result<SecretRef, serde_json::Error> {
        let w: Named = serde_json::from_slice(line)?;
        secret_ref(w.name, w.id)
    };

    let op = serde_json::from_slice::<Op>(line)?.op;
    Ok(match op.as_str() {
        "list" => Request::List,
        "status" => Request::Status,
        "backup" => Request::Backup,
        "verify-backup" => Request::VerifyBackup,
        "read-backup" => Request::ReadBackup,
        "mirror-plan" => Request::MirrorPlan,
        "totp" => Request::Totp { secret: named(line)? },
        "delete" => Request::Delete { secret: named(line)? },
        "rename" => Request::Rename {
            secret: named(line)?,
            new_name: serde_json::from_slice::<RenameWire>(line)?.new_name,
        },
        "proxy" => {
            let w: ProxyWire = serde_json::from_slice(line)?;
            Request::Proxy {
                secret: secret_ref(w.name, w.id)?,
                method: w.method,
                path: w.path,
                headers: w.headers,
                body: w.body,
                body_base64: w.body_base64,
            }
        }
        "fill" => {
            let w: FillWire = serde_json::from_slice(line)?;
            Request::Fill {
                name: w.name,
                request: crate::fill::FillRequest {
                    port: w.cdp.port,
                    target_id: w.cdp.target_id,
                    username: w.fields.username,
                    password: w.fields.password,
                    expect_site: w.expect_site,
                },
            }
        }
        "generate-login" => {
            let w: GenerateLoginWire = serde_json::from_slice(line)?;
            Request::GenerateLogin {
                name: w.name,
                site: w.site,
                username: w.username,
                length: w.length,
            }
        }
        "audit" => Request::Audit { all: serde_json::from_slice::<AuditWire>(line)?.all },
        "add" => {
            let w: AddWire = serde_json::from_slice(line)?;
            Request::Add { name: w.name, kind: w.kind, site: w.site, rule: w.rule, username: w.username, value: w.value }
        }
        "confirm-kit" => Request::ConfirmKit { recovery_key: serde_json::from_slice::<ConfirmKitWire>(line)?.recovery_key },
        "reset" => Request::Reset { recovery_key: serde_json::from_slice::<ResetWire>(line)?.recovery_key },
        "restore" => {
            let w: RestoreWire = serde_json::from_slice(line)?;
            Request::Restore { recovery_key: w.recovery_key, backup_len: w.backup_len, source: w.source }
        }
        "mirror-report" => {
            let w: MirrorReportWire = serde_json::from_slice(line)?;
            Request::MirrorReport {
                ok: w.ok,
                newest_file: w.newest_file,
                newest_generation: w.newest_generation,
                copied: w.copied,
                already_there: w.already_there,
                detail: w.detail,
            }
        }
        other => return Err(serde_json::Error::custom(format!("unknown op {other:?}"))),
    })
}

/// The requests that carry a secret, as the command-line tool sends them (inside `Outgoing`).
/// Built only in `client`, which checks the daemon first (R27).
#[derive(Serialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub(crate) enum SecretRequest<'a> {
    Add {
        name: &'a str,
        kind: Kind,
        site: &'a str,
        rule: Option<&'a RuleInput>,
        username: Option<&'a str>,
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        value: &'a SecretValue,
    },
    ConfirmKit {
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        recovery_key: &'a SecretValue,
    },
    Reset {
        #[serde(serialize_with = "secret_bytes::serialize_opt_ref")]
        recovery_key: Option<&'a SecretValue>,
    },
    Restore {
        #[serde(serialize_with = "secret_bytes::serialize_ref")]
        recovery_key: &'a SecretValue,
        backup_len: Option<usize>,
        source: Option<String>,
    },
}

/// A request as the command-line tool sends it: its own fields, plus the protocol version and a
/// request id. Serializing it writes straight into the caller's (wiped) buffer; flattening
/// keeps no copy of its own.
#[derive(Serialize)]
pub(crate) struct Outgoing<'a, T: Serialize> {
    #[serde(flatten)]
    pub request: &'a T,
    pub protocol: u32,
    pub request_id: &'a str,
}

#[derive(Serialize, Deserialize)]
pub struct OkReply {
    pub ok: bool,
}

#[derive(Serialize, Deserialize)]
pub struct ListReply {
    pub ok: bool,
    pub secrets: Vec<SecretSummary>,
}

#[derive(Serialize)]
pub struct TotpReply {
    pub ok: bool,
    pub id: String,
    pub name: String,
    pub code: String,
    pub seconds_left: u64,
}

/// What `fill` typed: the fields' names, never their values (R4).
#[derive(Serialize)]
pub struct FillReply {
    pub ok: bool,
    pub filled: Vec<&'static str>,
}

/// A login `generate-login` made: its name. The password it made isn't here and can't be (R4):
/// it is typed into a page with `fill`.
#[derive(Serialize)]
pub struct GenerateLoginReply {
    pub ok: bool,
    pub name: String,
}

#[derive(Serialize)]
pub struct ProxyReplyOut {
    pub ok: bool,
    pub status: u16,
    pub headers: Vec<[String; 2]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body_base64: Option<String>,
}

/// What `vault status` shows from the daemon's side. Information only; no values.
#[derive(Serialize, Deserialize)]
pub struct StatusReply {
    pub ok: bool,
    pub version: String,
    /// The vault-file format this daemon writes.
    #[serde(default)]
    pub format: u32,
    pub pid: u32,
    pub uid: u32,
    pub key_protection: String,
    pub local_backups: String,
    pub restore_point: bool,
    pub vault: Option<OpenedStatus>,
    pub mirror: Option<MirrorState>,
}

#[derive(Serialize, Deserialize)]
pub struct OpenedStatus {
    /// This copy of the vault; a restore makes a new one.
    pub vault_id: String,
    /// The vault's stable identity, the same after every restore (`model::vault_identity`).
    #[serde(default)]
    pub vault_identity: String,
    /// The vault file's format.
    #[serde(default)]
    pub format: u32,
    pub created_at: String,
    pub recovery_fingerprint: String,
    pub kit_confirmed: bool,
    pub kit_path: Option<String>,
    pub mirror_dir: String,
    pub generation: u64,
    pub secrets: usize,
    pub by_kind: Vec<(Kind, usize)>,
    pub last_backup: Option<BackupStatus>,
    /// The audit log's line count when its chain is intact, or what is wrong with it.
    pub audit_lines: Option<usize>,
    pub audit_problem: Option<String>,
    pub recent_changes: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AuditReply {
    pub ok: bool,
    pub total: usize,
    pub lines: Vec<AuditLine>,
    pub problem: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AddReply {
    pub ok: bool,
    pub secret: SecretSummary,
    pub backup: BackupStatus,
}

#[derive(Serialize, Deserialize)]
pub struct RenameReply {
    pub ok: bool,
    pub secret: SecretSummary,
    pub backup: BackupStatus,
}

#[derive(Serialize, Deserialize)]
pub struct BackupReply {
    pub ok: bool,
    pub backup: BackupStatus,
}

#[derive(Serialize, Deserialize)]
pub struct ConfirmKitReply {
    pub ok: bool,
    /// The kit file `vault install` wrote, for the command-line tool to delete: it is the
    /// owner's file, which the daemon's account can't touch.
    pub kit_path: Option<String>,
    pub backup: BackupStatus,
}

#[derive(Serialize, Deserialize)]
pub struct ResetReply {
    pub ok: bool,
    /// True when the vault never held a secret and went without the recovery key.
    pub unused: bool,
    pub newest_file: Option<String>,
    pub kit_path: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct RestoreReply {
    pub ok: bool,
    pub vault_id: String,
    #[serde(default)]
    pub vault_identity: String,
    pub from_vault_id: String,
    #[serde(default)]
    pub from_format: u32,
    pub from_generation: u64,
    pub secrets: Vec<SecretSummary>,
    pub backup: BackupStatus,
}

/// The check of the newest backup that the daemon makes for `verify-backup`. No values.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BackupCheck {
    pub file: String,
    pub generation: u64,
    pub written_at: String,
    pub secrets: usize,
    pub matches_vault: bool,
}

#[derive(Serialize, Deserialize)]
pub struct VerifyBackupReply {
    pub ok: bool,
    pub check: BackupCheck,
}

/// The newest backup as it sits in the folder: age ciphertext, readable only with the recovery
/// key or the vault's own check key.
#[derive(Serialize, Deserialize)]
pub struct ReadBackupReply {
    pub ok: bool,
    pub file: String,
    pub data_base64: String,
}

/// What the mirror needs: where the backups are, and where they go.
#[derive(Serialize, Deserialize)]
pub struct MirrorPlanReply {
    pub ok: bool,
    pub local_dir: String,
    pub mirror_dir: String,
    pub vault_id: String,
    pub generation: u64,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorReply {
    pub ok: bool,
    pub error: String,
    pub message: String,
}

impl ErrorReply {
    pub fn from(error: &VaultError) -> Self {
        ErrorReply { ok: false, error: error.code().into(), message: error.to_string() }
    }
}
