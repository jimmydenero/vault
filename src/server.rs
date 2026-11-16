//! `vault daemon`: the vault's background part, run as the owner by the LaunchAgent
//! `com.volgenic.vault` in his login (macOS) or the systemd user service `volgenic-vault.service`,
//! which lingering starts at boot (Linux). It reads the vault key, opens the socket and serves.
//! It is the only process that reads or changes the vault (R13), and the only one that writes
//! the local backups (R32). Callers must be the owner's own user ID (R22): `getpeereid` on
//! macOS, `SO_PEERCRED` on Linux (`platform::peer_of`).

use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use zeroize::Zeroizing;

use crate::audit::{self, AuditEvent};
use crate::backup;
use crate::secret::WipingBuf;
use crate::error::VaultError;
use crate::health::HealthBook;
use crate::keyprotect;
use crate::kinds::{self, HealthState};
use crate::model::{Kind, MirrorState, Record, SecretRef, VaultDoc};
use crate::platform::{self, Peer};
use crate::protocol::{
    self, AddReply, AddSealedReply, AuditReply, BackupReply, ConfirmKitReply, Envelope, ErrorReply, Framed, HealthReply,
    ImportReply, ImportedPlan, ListReply, MirrorPlanReply, OkReply, ProxyReplyOut, ReadBackupReply, RenameReply,
    Request, ResetReply, RestoreReply, StatusReply, TotpReply, VerifyBackupReply,
};
use crate::proxy::{self, ProxyRequest};
use crate::rules;
use crate::store::{self, OwnerPaths, Paths};
use crate::stream::{self, Streamer};
use crate::vault::{self, ImportOutcome, NewSecret, Vault};
use crate::intake;

/// Streamed model calls hold their connection for minutes, so there is room for many at once.
const MAX_CONNECTIONS: usize = 128;

struct Server {
    paths: Paths,
    owner_uid: u32,
    /// The mirror folder a restored-from-file vault gets: the owner's iCloud Drive on macOS.
    default_mirror_dir: PathBuf,
    /// The open vault, or none (before a restore). Every change and backup holds this lock, so
    /// changes happen one at a time (R13).
    vault: Mutex<Option<Vault>>,
    /// A read-only copy for agents' requests (list, 2FA, proxy), replaced after every change.
    snapshot: RwLock<Option<Arc<VaultDoc>>>,
    client: reqwest::blocking::Client,
    /// The async client and runtime for `stream` (R39).
    streamer: Streamer,
    /// What upstream replies said about each credential (`health`).
    health: Mutex<HealthBook>,
    /// How far the audit chain has been checked (R29), so `vault status`, which the host polls,
    /// checks only the lines written since. Taken after `vault`, never before it.
    audit_check: Mutex<audit::Checkpoint>,
    active: AtomicUsize,
}

fn log(message: &str) {
    eprintln!("{} vault daemon: {message}", crate::now_rfc3339());
}

pub fn run() -> Result<(), VaultError> {
    let owner_uid = unsafe { libc::getuid() };
    if owner_uid == 0 {
        return Err(VaultError::Io("the vault runs as its owner, never as root".into()));
    }
    let paths = Paths::current();
    unsafe {
        libc::umask(0o077);
        // R11, R15: no environment variable changes which certificates the proxy trusts. On
        // Linux the system's root certificates are read by rustls-native-certs, which would
        // otherwise honour these two. Nothing else runs yet, so changing the environment is safe.
        std::env::remove_var("SSL_CERT_FILE");
        std::env::remove_var("SSL_CERT_DIR");
    }
    // On Linux systemd makes the socket's folder (`RuntimeDirectory=volgenic`, 0700) before it
    // starts the daemon. Run any other way (by hand, or with no systemd), the daemon makes it.
    #[cfg(not(target_os = "macos"))]
    if fs::symlink_metadata(&paths.socket_dir).is_err() {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&paths.socket_dir)?;
    }
    for dir in [&paths.dir, &paths.local_backups, &paths.socket_dir] {
        store::check_dir(dir, owner_uid, 0o077)?;
    }
    let opened = if store::vault_exists(&paths) {
        let (vault, migrated) = Vault::open(&paths)?;
        if let Some(note) = migrated {
            log(&note);
        }
        Some(vault)
    } else {
        None
    };
    let default_mirror_dir = OwnerPaths::for_uid(owner_uid)?.default_mirror_dir();

    let client = proxy::client()?;
    let streamer = Streamer::new()?;
    let health = fs::read(&paths.health_state).map(|bytes| HealthBook::from_json(&bytes)).unwrap_or_default();
    match fs::symlink_metadata(&paths.socket) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(&paths.socket)?,
        Ok(_) => {
            return Err(VaultError::UnsafeVaultFolder(format!(
                "{} exists and isn't a socket",
                paths.socket.display()
            )));
        }
        Err(_) => {}
    }
    let listener = UnixListener::bind(&paths.socket)?;
    // Only the owner can reach it: the folder is 0700, and every caller is checked (R22).
    log(&format!("vault key: {}", keyprotect::describe(&paths.dir)));
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;

    let snapshot = match &opened {
        Some(vault) => Some(Arc::new(vault.read_copy()?)),
        None => None,
    };
    // The full check of the audit chain, across every rotated file, once at the start; from
    // here on `status` and `audit` check only what was written since (`audit::check`).
    let mut audit_check = audit::Checkpoint::default();
    let started = std::time::Instant::now();
    match audit::check(&paths.audit_log, &mut audit_check, opened.as_ref().map(Vault::audit_head)) {
        Ok(()) => log(&format!(
            "audit log: {} lines in {} file(s), hash chain intact (checked in {} ms)",
            audit_check.lines(),
            audit_check.files(),
            started.elapsed().as_millis()
        )),
        Err(error) => log(&format!("AUDIT LOG PROBLEM: {error}")),
    }
    let server = Arc::new(Server {
        paths: paths.clone(),
        owner_uid,
        default_mirror_dir,
        vault: Mutex::new(opened),
        snapshot: RwLock::new(snapshot),
        client,
        streamer,
        health: Mutex::new(health),
        audit_check: Mutex::new(audit_check),
        active: AtomicUsize::new(0),
    });
    let mut event = AuditEvent::new("daemon", "started");
    event.detail = Some(format!(
        "pid {}, as user ID {}, vault {}, socket {}",
        std::process::id(),
        owner_uid,
        if server.snapshot.read().map(|s| s.is_some()).unwrap_or(false) { "open" } else { "absent" },
        paths.socket.display()
    ));
    audit::append(&paths.audit_log, event)?;
    log(&format!("serving on {}", paths.socket.display()));

    // A vault just made by `vault install`, or one whose last backup failed: back it up now.
    let _ = server.with_vault(|vault| {
        if let Some(status) = vault.backup_if_needed() {
            log(&format!("backup of generation {}: {}", status.generation, if status.ok { "ok" } else { "FAILED" }));
        }
        Ok(())
    });

    // Token upkeep (R39): only kinds with a refresher need it, and a Claude plan has none.
    if kinds::any_refresher() {
        let server = Arc::clone(&server);
        std::thread::spawn(move || {
            loop {
                server.upkeep();
                std::thread::sleep(Duration::from_secs(60));
            }
        });
    }

    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let server = Arc::clone(&server);
        if server.active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            server.active.fetch_sub(1, Ordering::SeqCst);
            let mut stream = stream;
            let _ = reply(&mut stream, &Envelope::default(), &ErrorReply::from(&VaultError::Busy));
            continue;
        }
        std::thread::spawn(move || {
            server.handle(stream);
            server.active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}


/// Reads one request line straight into a buffer that is wiped when dropped, through a chunk
/// that is wiped too: no ordinary buffer ever holds a request, which may carry a typed value or
/// the recovery key (R1, R27). Returns the line and any bytes read past it.
fn read_request_line(stream: &mut UnixStream) -> Result<(WipingBuf, Vec<u8>), VaultError> {
    let too_long = || VaultError::BadRequest("unreadable or over 2 MiB".into());
    let mut data = WipingBuf::with_capacity(64 * 1024);
    let mut chunk = Zeroizing::new(vec![0u8; 16 * 1024]);
    loop {
        let n = match stream.read(&mut chunk[..]) {
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(too_long()),
        };
        if n == 0 {
            return Err(VaultError::BadRequest("the request ended without a newline".into()));
        }
        let start = data.len();
        data.extend_from_slice(&chunk[..n]);
        if let Some(index) = memchr::memchr(b'\n', &chunk[..n]) {
            let end = start + index;
            if end > protocol::MAX_REQUEST_LINE {
                return Err(too_long());
            }
            let rest = data.as_slice()[end + 1..].to_vec();
            let mut line = WipingBuf::with_capacity(end);
            line.extend_from_slice(&data.as_slice()[..end]);
            return Ok((line, rest));
        }
        if data.len() > protocol::MAX_REQUEST_LINE {
            return Err(too_long());
        }
    }
}

/// Reads the bytes that follow a request line: a `restore`'s backup file (ciphertext, at most
/// `backup::MAX_BACKUP_BYTES`) or a `stream`'s request body (at most `stream::MAX_BODY`):
/// exactly `len` bytes. Neither holds a stored value, so an ordinary buffer is fine.
fn read_payload(stream: &mut UnixStream, mut data: Vec<u8>, len: usize, max: usize) -> Result<Vec<u8>, VaultError> {
    if len > max {
        return Err(VaultError::BadRequest(if max == backup::MAX_BACKUP_BYTES {
            format!("the backup is over {} MiB, larger than any backup the vault writes", max / (1024 * 1024))
        } else {
            format!("the body is over {} MiB", max / (1024 * 1024))
        }));
    }
    if data.len() > len {
        data.truncate(len);
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(60)));
    let have = data.len();
    data.resize(len, 0);
    stream
        .read_exact(&mut data[have..])
        .map_err(|_| VaultError::BadRequest("the bytes after the request line ended early".into()))?;
    Ok(data)
}

/// Writes one reply line: the reply's fields plus this daemon's protocol version and the
/// request's id, echoed as it came (protocol 2).
fn reply<T: serde::Serialize>(stream: &mut UnixStream, envelope: &Envelope, value: &T) -> std::io::Result<()> {
    let framed = Framed { body: value, protocol: protocol::PROTOCOL_VERSION, request_id: envelope.request_id.as_ref() };
    let mut line = serde_json::to_vec(&framed).unwrap_or_else(|_| b"{\"ok\":false,\"error\":\"encoding\"}".to_vec());
    line.push(b'\n');
    stream.write_all(&line)?;
    stream.flush()
}

/// Who sent a request: the peer (R22, R23) and the request's envelope (its protocol version and
/// request id).
/// A `stream` request, read.
struct StreamCall {
    secret: SecretRef,
    host: Option<String>,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    idle: u64,
}

struct Caller {
    peer: Peer,
    envelope: Envelope,
}

fn with_peer(mut event: AuditEvent, caller: &Caller) -> AuditEvent {
    event.peer_pid = caller.peer.pid;
    event.peer_program = caller.peer.program.clone();
    event.request_id = caller.envelope.request_id_text();
    event
}

fn error_reply(stream: &mut UnixStream, caller: &Caller, error: &VaultError) -> std::io::Result<()> {
    reply(stream, &caller.envelope, &ErrorReply::from(error))
}

impl Server {
    fn snapshot(&self) -> Result<Arc<VaultDoc>, VaultError> {
        let snapshot = self.snapshot.read().map_err(|_| VaultError::Busy)?;
        snapshot.as_ref().map(Arc::clone).ok_or(VaultError::NotInitialized)
    }

    /// Runs `f` on the open vault under the change lock, then refreshes the agents' snapshot.
    fn with_vault<T>(&self, f: impl FnOnce(&mut Vault) -> Result<T, VaultError>) -> Result<T, VaultError> {
        let mut guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
        let vault = guard.as_mut().ok_or(VaultError::NotInitialized)?;
        let result = f(vault);
        self.publish(&guard);
        result
    }

    fn publish(&self, guard: &Option<Vault>) {
        let fresh = guard.as_ref().and_then(|vault| vault.read_copy().ok()).map(Arc::new);
        if let Ok(mut snapshot) = self.snapshot.write() {
            *snapshot = fresh;
        }
    }

    /// The audit log for `vault audit`, its chain checked up to the head the vault file records
    /// (R29): the last lines from the checkpoint, or with `all` every line and a full check of
    /// every file, which also renews the checkpoint. Lines hold no values (R28).
    fn audit_report(&self, all: bool) -> AuditReply {
        let recorded = self.snapshot().ok().map(|doc| doc.audit_head.clone());
        let recorded = recorded.as_deref();
        let log = &self.paths.audit_log;
        let result = if all {
            audit::read_all(log, recorded).map(|(lines, checkpoint)| {
                let total = checkpoint.lines();
                *self.audit_check.lock().unwrap_or_else(|e| e.into_inner()) = checkpoint;
                (total, lines)
            })
        } else {
            let mut checkpoint = self.audit_check.lock().unwrap_or_else(|e| e.into_inner());
            audit::check(log, &mut checkpoint, recorded).map(|()| (checkpoint.lines(), checkpoint.tail()))
        };
        match result {
            Ok((total, lines)) => AuditReply { ok: true, total, lines, problem: None },
            Err(error) => AuditReply { ok: true, total: 0, lines: Vec::new(), problem: Some(error.to_string()) },
        }
    }

    /// Best effort, for refusals and for lines after a use that is already recorded: not waited
    /// onto the disk, so a call's outcome line doesn't hold up the next call's line (R28 needs
    /// the line before a use on disk, which `record` flushes).
    fn audit(&self, event: AuditEvent) {
        if let Err(error) = audit::append_unsynced(&self.paths.audit_log, event) {
            log(&format!("couldn't write the audit log: {}", error.code()));
        }
    }

    /// Records a use before it happens (R28). If the line can't be written, the use doesn't
    /// happen: the caller gets `audit_unavailable`.
    fn record(&self, event: AuditEvent) -> Result<(), VaultError> {
        audit::append(&self.paths.audit_log, event).map(|_| ()).map_err(|error| {
            log(&format!("couldn't write the audit log ({}); refusing the request", error.code()));
            VaultError::AuditUnavailable
        })
    }

    /// Audits a command's outcome, best effort, and turns it into the reply.
    fn finish<T: serde::Serialize>(
        &self,
        stream: &mut UnixStream,
        peer: &Caller,
        op: &str,
        name: Option<&str>,
        result: Result<T, VaultError>,
    ) -> std::io::Result<()> {
        match result {
            Ok(value) => reply(stream, &peer.envelope, &value),
            Err(error) => {
                let mut event = AuditEvent::new(op, &format!("denied: {}", error.code()));
                event.name = name.map(str::to_string);
                if let VaultError::BackupFailed(why) | VaultError::InvalidRule(why) | VaultError::InvalidSecret(why) = &error {
                    event.detail = Some(why.clone());
                }
                self.audit(with_peer(event, peer));
                error_reply(stream, peer, &error)
            }
        }
    }

    fn handle(&self, mut stream: UnixStream) {
        // R22: only the owner's user ID. R23: the caller's pid and program are a hint.
        let Some(peer) = platform::peer_of(stream.as_raw_fd()) else { return };
        let mut peer = Caller { peer, envelope: Envelope::default() };
        if peer.peer.uid != self.owner_uid {
            let mut event = AuditEvent::new("connect", "denied: not the owner's user ID");
            event.detail = Some(format!("uid {}", peer.peer.uid));
            self.audit(with_peer(event, &peer));
            return;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let (line, rest) = match read_request_line(&mut stream) {
            Ok(read) => read,
            Err(error) => {
                self.audit(with_peer(AuditEvent::new("request", &format!("denied: {}", error.code())), &peer));
                let _ = error_reply(&mut stream, &peer, &error);
                return;
            }
        };
        let (envelope, accepted) = protocol::parse_envelope(line.as_slice());
        peer.envelope = envelope;
        if let Err(error) = accepted {
            self.audit(with_peer(AuditEvent::new("request", &format!("denied: {}", error.code())), &peer));
            let _ = error_reply(&mut stream, &peer, &error);
            return;
        }
        let request: Request = match protocol::parse_request(line.as_slice()) {
            Ok(request) => request,
            Err(_) => {
                // A fixed message: serde's own can quote a field's value, which may be a secret (R2).
                let error = VaultError::BadRequest("not a valid request; see the protocol in the README".into());
                self.audit(with_peer(AuditEvent::new("request", "denied: bad_request"), &peer));
                let _ = error_reply(&mut stream, &peer, &error);
                return;
            }
        };
        drop(line);
        // `restore FILE` sends the backup's bytes after the line (ciphertext only).
        let following = match &request {
            Request::Restore { backup_len: Some(len), .. } => Some(("restore", *len, backup::MAX_BACKUP_BYTES)),
            Request::Stream { body_len, .. } if *body_len > 0 => Some(("stream", *body_len, stream::MAX_BODY)),
            _ => None,
        };
        let payload = match following {
            Some((op, len, max)) => match read_payload(&mut stream, rest, len, max) {
                Ok(data) => Some(data),
                Err(error) => {
                    self.audit(with_peer(AuditEvent::new(op, &format!("denied: {}", error.code())), &peer));
                    let _ = error_reply(&mut stream, &peer, &error);
                    return;
                }
            },
            None => None,
        };
        let _ = self.dispatch(&mut stream, &peer, request, payload);
    }

    fn dispatch(
        &self,
        stream: &mut UnixStream,
        peer: &Caller,
        request: Request,
        payload: Option<Vec<u8>>,
    ) -> std::io::Result<()> {
        match request {
            Request::List => {
                let result = self.snapshot().and_then(|doc| {
                    self.record(with_peer(AuditEvent::new("list", "ok"), peer))?;
                    Ok(ListReply { ok: true, secrets: doc.summaries() })
                });
                self.finish(stream, peer, "list", None, result)
            }
            Request::Totp { secret } => {
                let result = self.snapshot().and_then(|doc| {
                    let (code, record) = vault::totp_code(&doc, &secret)?;
                    let mut event = AuditEvent::named("totp", &record.name, "ok");
                    event.secret_id = Some(record.id.clone());
                    self.record(with_peer(event, peer))?;
                    Ok(TotpReply {
                        ok: true,
                        id: record.id.clone(),
                        name: record.name.clone(),
                        code: code.code,
                        seconds_left: code.seconds_left,
                    })
                });
                self.finish(stream, peer, "totp", Some(&secret.label()), result)
            }
            Request::Proxy { secret, method, path, headers, body, body_base64 } => {
                match self.snapshot() {
                    Ok(doc) => match self.proxy(&doc, &secret, method, path, headers, body, body_base64, peer) {
                        Ok(out) => reply(stream, &peer.envelope, &out),
                        Err(error) => error_reply(stream, peer, &error),
                    },
                    Err(error) => self.finish::<OkReply>(stream, peer, "proxy", Some(&secret.label()), Err(error)),
                }
            }
            Request::Stream { secret, host, method, path, headers, body_len: _, idle_timeout_secs } => {
                let idle = idle_timeout_secs.unwrap_or(stream::DEFAULT_IDLE_SECS).clamp(1, stream::MAX_IDLE_SECS);
                let call = StreamCall { secret, host, method, path, headers, body: payload.unwrap_or_default(), idle };
                self.stream(stream, peer, call)
            }
            Request::Health => {
                let result = self.snapshot().and_then(|doc| {
                    self.record(with_peer(AuditEvent::new("health", "ok"), peer))?;
                    let book = self.health.lock().unwrap_or_else(|e| e.into_inner());
                    Ok(HealthReply { ok: true, credentials: book.report(&doc) })
                });
                self.finish(stream, peer, "health", None, result)
            }
            Request::AddSealed { name, kind, sealed_base64, replace } => {
                let result = (|| {
                    // R40: a sealed value may replace a stored one only for a kind whose hosts and
                    // headers the kind table fixes (`claude_plan`). Anyone can seal to the intake
                    // key, so replacing an API key's value would also replace its rule and could
                    // send that name's agent traffic to another host.
                    if replace && kinds::spec(kind).is_none() {
                        return Err(VaultError::SealedInvalid(format!(
                            "a sealed value can't replace a stored {}; only a kind with fixed hosts (claude_plan) can be replaced this way",
                            kind.label()
                        )));
                    }
                    let doc = self.snapshot()?;
                    let identity = doc
                        .intake_identity
                        .as_ref()
                        .ok_or_else(|| VaultError::SealedInvalid("this vault has no intake key".into()))?;
                    let sealed = intake::open(identity, &sealed_base64, &name, kind)?;
                    drop(doc);
                    let rule = match (kind, &sealed.rule) {
                        (Kind::ApiKey, Some(input)) => Some(rules::parse_rule(
                            &input.host,
                            input.port,
                            &input.methods,
                            &input.path,
                            &input.header,
                        )?),
                        (Kind::ApiKey, None) => return Err(VaultError::InvalidRule("an API key needs a rule".into())),
                        _ => None,
                    };
                    let site = match (sealed.site, &rule) {
                        (Some(site), _) => site,
                        (None, Some(rule)) => rule.host.clone(),
                        (None, None) => String::new(),
                    };
                    let new = NewSecret { name: sealed.name, kind, site, rule, username: sealed.username, value: sealed.value };
                    self.with_vault(|vault| vault.put(new, replace))
                        .map(|(secret, backup, replaced)| AddSealedReply { ok: true, secret, replaced, backup })
                })();
                self.finish(stream, peer, "add_sealed", Some(&name), result)
            }
            Request::ImportPlan { plans } => {
                let result = self.with_vault(|vault| vault.import_plans(plans)).map(|(results, backup)| {
                    let plans = results
                        .into_iter()
                        .map(|(name, outcome)| match outcome {
                            ImportOutcome::Done(version) => ImportedPlan {
                                name,
                                result: "done".into(),
                                version: Some(version),
                                error: None,
                                message: None,
                            },
                            ImportOutcome::Unchanged(version) => ImportedPlan {
                                name,
                                result: "unchanged".into(),
                                version: Some(version),
                                error: None,
                                message: None,
                            },
                            ImportOutcome::Failed(error) => ImportedPlan {
                                name,
                                result: "failed".into(),
                                version: None,
                                error: Some(error.code().into()),
                                message: Some(error.to_string()),
                            },
                        })
                        .collect();
                    ImportReply { ok: true, plans, backup }
                });
                self.finish(stream, peer, "import_plan", None, result)
            }
            Request::Status => {
                let guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
                let opened = guard.as_ref().map(|vault| {
                    let mut checkpoint = self.audit_check.lock().unwrap_or_else(|e| e.into_inner());
                    match audit::check(&self.paths.audit_log, &mut checkpoint, Some(vault.audit_head())) {
                        Ok(()) => vault.status(Ok(&checkpoint)),
                        Err(error) => vault.status(Err(error.to_string())),
                    }
                });
                drop(guard);
                let mirror = fs::read(&self.paths.mirror_state)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<MirrorState>(&bytes).ok());
                self.audit(with_peer(AuditEvent::new("status", "ok"), peer));
                reply(
                    stream,
                    &peer.envelope,
                    &StatusReply {
                        ok: true,
                        version: crate::VERSION.into(),
                        format: crate::model::VAULT_FORMAT,
                        pid: std::process::id(),
                        uid: unsafe { libc::getuid() },
                        key_protection: keyprotect::describe(&self.paths.dir),
                        local_backups: self.paths.local_backups.display().to_string(),
                        restore_point: vault::has_restore_point(&self.paths),
                        vault: opened,
                        mirror,
                    },
                )
            }
            Request::Audit { all } => {
                let report = self.audit_report(all);
                self.audit(with_peer(AuditEvent::new("audit", "ok"), peer));
                reply(stream, &peer.envelope, &report)
            }
            Request::Add { name, kind, site, rule, username, value } => {
                let result = (|| {
                    let rule = match (kind, rule) {
                        (Kind::ApiKey, Some(input)) => Some(rules::parse_rule(
                            &input.host,
                            input.port,
                            &input.methods,
                            &input.path,
                            &input.header,
                        )?),
                        (Kind::ApiKey, None) => return Err(VaultError::InvalidRule("an API key needs a rule".into())),
                        _ => None,
                    };
                    let new = NewSecret { name: name.clone(), kind, site, rule, username, value };
                    self.with_vault(|vault| vault.add(new))
                        .map(|(secret, backup)| AddReply { ok: true, secret, backup })
                })();
                self.finish(stream, peer, "add", Some(&name), result)
            }
            Request::Delete { secret } => {
                let result = self.with_vault(|vault| vault.delete(&secret)).map(|backup| BackupReply { ok: true, backup });
                self.finish(stream, peer, "delete", Some(&secret.label()), result)
            }
            Request::Rename { secret, new_name } => {
                let result = self
                    .with_vault(|vault| vault.rename(&secret, &new_name))
                    .map(|(secret, backup)| RenameReply { ok: true, secret, backup });
                self.finish(stream, peer, "rename", Some(&secret.label()), result)
            }
            Request::ConfirmKit { recovery_key } => {
                let result = self
                    .with_vault(|vault| vault.confirm_kit(recovery_key))
                    .map(|(backup, kit_path)| ConfirmKitReply { ok: true, kit_path, backup });
                self.finish(stream, peer, "confirm-kit", None, result)
            }
            Request::Reset { recovery_key } => {
                let result = (|| {
                    let mut guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
                    let vault = guard.as_mut().ok_or(VaultError::NotInitialized)?;
                    let outcome = vault.reset(recovery_key);
                    if outcome.is_ok() {
                        *guard = None;
                    }
                    self.publish(&guard);
                    let outcome = outcome?;
                    Ok(ResetReply {
                        ok: true,
                        unused: outcome.unused,
                        newest_file: outcome.newest_file,
                        kit_path: outcome.kit_path,
                    })
                })();
                self.finish(stream, peer, "reset", None, result)
            }
            Request::Restore { recovery_key, backup_len: _, source } => {
                let result = (|| {
                    let file = payload.map(|data| (source.unwrap_or_else(|| "a file the person named".into()), data));
                    let mut guard = self.vault.lock().unwrap_or_else(|e| e.into_inner());
                    if guard.is_some() {
                        return Err(VaultError::AlreadyInitialized);
                    }
                    let (mut restored, report) =
                        vault::restore(&self.paths, file, &self.default_mirror_dir, recovery_key)?;
                    // The vault is on disk now: hold it even if its first backup fails, so the
                    // daemon and the disk agree (the failure is the alarm of R19).
                    let backup = restored.backup();
                    *guard = Some(restored);
                    self.publish(&guard);
                    let backup = backup?;
                    Ok(RestoreReply {
                        ok: true,
                        vault_id: report.vault_id,
                        vault_identity: report.vault_identity,
                        from_vault_id: report.from_vault_id,
                        from_format: report.from_format,
                        from_generation: report.from_generation,
                        secrets: report.secrets,
                        backup,
                    })
                })();
                self.finish(stream, peer, "restore", None, result)
            }
            Request::Backup => {
                let result = self.with_vault(Vault::backup).map(|backup| BackupReply { ok: true, backup });
                self.finish(stream, peer, "backup-request", None, result)
            }
            Request::VerifyBackup => {
                let result = self.with_vault(|vault| vault.check_newest());
                if let Ok(check) = &result {
                    let mut event = AuditEvent::new("verify-backup", if check.matches_vault { "ok" } else { "differs from vault" });
                    event.detail = Some(format!("{} (generation {})", check.file, check.generation));
                    self.audit(with_peer(event, peer));
                }
                let result = result.map(|check| VerifyBackupReply { ok: true, check });
                self.finish(stream, peer, "verify-backup", None, result)
            }
            Request::ReadBackup => {
                let result = self.with_vault(|vault| vault.read_newest()).and_then(|(file, data)| {
                    let mut event = AuditEvent::new("read-backup", "ok");
                    event.detail = Some(file.display().to_string());
                    self.record(with_peer(event, peer))?;
                    Ok(ReadBackupReply { ok: true, file: file.display().to_string(), data_base64: BASE64.encode(data) })
                });
                self.finish(stream, peer, "read-backup", None, result)
            }
            Request::MirrorPlan => {
                let result = self.with_vault(|vault| {
                    Ok(MirrorPlanReply {
                        ok: true,
                        local_dir: self.paths.local_backups.display().to_string(),
                        mirror_dir: vault.mirror_dir().to_string(),
                        vault_id: vault.vault_id().to_string(),
                        generation: vault.generation(),
                    })
                });
                self.finish(stream, peer, "mirror-plan", None, result)
            }
            Request::MirrorReport { ok, newest_file, newest_generation, copied, already_there, detail } => {
                let result = self.with_vault(|vault| {
                    let detail: String = detail.chars().filter(|c| !c.is_control()).take(500).collect();
                    let state = MirrorState {
                        at: crate::now_rfc3339(),
                        ok,
                        mirror_dir: vault.mirror_dir().to_string(),
                        newest_file: newest_file.map(|f| f.chars().take(300).collect()),
                        newest_generation,
                        copied,
                        already_there,
                        detail: detail.clone(),
                    };
                    let bytes = serde_json::to_vec(&state).map_err(|_| VaultError::Io("mirror state encoding".into()))?;
                    store::write_atomic(&self.paths.mirror_state, &bytes)?;
                    let mut event = AuditEvent::new("mirror-report", if ok { "ok" } else { "FAILED" });
                    event.detail = Some(format!(
                        "copied {copied}, already there {already_there}, newest generation {}{}",
                        newest_generation.map_or("none".into(), |g| g.to_string()),
                        if detail.is_empty() { String::new() } else { format!(": {detail}") }
                    ));
                    self.audit(with_peer(event, peer));
                    Ok(OkReply { ok: true })
                });
                self.finish(stream, peer, "mirror-report", None, result)
            }
        }
    }

    /// `stream` (R39): checks, the audit line before the credential leaves the vault (R28), the
    /// call, and the line after it with what happened.
    fn stream(&self, out: &mut UnixStream, peer: &Caller, call: StreamCall) -> std::io::Result<()> {
        let doc = match self.snapshot() {
            Ok(doc) => doc,
            Err(error) => return self.finish::<OkReply>(out, peer, "stream", Some(&call.secret.label()), Err(error)),
        };
        let logged_path: String = call.path.split(['?', '#']).next().unwrap_or("").chars().take(200).collect();
        let record = doc.find_ref(&call.secret);
        let mut event = AuditEvent::named("stream", &record.map_or_else(|| call.secret.label(), |r| r.name.clone()), "");
        event.secret_id = record.map(|r| r.id.clone());
        event.method = Some(call.method.chars().take(16).collect());
        event.path = Some(logged_path);
        let mut event = with_peer(event, peer);
        let refuse = |error: VaultError, mut event: AuditEvent, out: &mut UnixStream| {
            event.outcome = format!("denied: {}", error.code());
            if let VaultError::RuleMismatch(why) | VaultError::BadRequest(why) = &error {
                event.detail = Some(why.clone());
            }
            self.audit(event);
            error_reply(out, peer, &error)
        };
        let Some(record) = record else {
            return refuse(call.secret.not_found(), event, out);
        };
        let plan = match stream::plan(record, call.host.as_deref(), &call.method, &call.path, &call.headers) {
            Ok(plan) => plan,
            Err(error) => return refuse(error, event, out),
        };
        event.host = Some(plan.host.clone());
        // R28: the use is on disk before the credential leaves the vault. No line, no request.
        let mut attempt = event.clone();
        attempt.outcome = "sending".into();
        if let Err(error) = self.record(attempt) {
            return error_reply(out, peer, &error);
        }
        let outcome = self.streamer.run(&plan, &record.value, call.body, Duration::from_secs(call.idle), out, &peer.envelope);
        event.status = outcome.status;
        event.outcome = match (&outcome.error, outcome.head_sent, outcome.end) {
            (_, true, "complete") => "ok".into(),
            (_, true, end) => format!("ended: {end}"),
            (Some(error), false, _) => format!("denied: {}", error.code()),
            (None, false, end) => format!("ended: {end}"),
        };
        event.detail = Some(format!(
            "{} body bytes, head after {}, {} ms in all{}",
            outcome.bytes,
            outcome.head_after.map_or("none".into(), |d| format!("{} ms", d.as_millis())),
            outcome.took.as_millis(),
            match &outcome.error {
                Some(VaultError::UpstreamFailed(why)) => format!("; {why}"),
                _ => String::new(),
            }
        ));
        self.audit(event);
        if let Some(state) = outcome.health {
            self.observe(record, state, outcome.status);
        }
        match (outcome.head_sent, &outcome.error) {
            (false, Some(error)) if outcome.end != "cancelled" => error_reply(out, peer, error),
            _ => Ok(()),
        }
    }

    /// Records what a reply said about a credential, and writes the book when the state changed.
    fn observe(&self, record: &Record, state: HealthState, status: Option<u16>) {
        let mut book = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if book.observe(&record.id, record.version, state, status, crate::now_rfc3339()) {
            if let Ok(doc) = self.snapshot() {
                book.prune(&doc);
            }
            if let Err(error) = store::write_atomic(&self.paths.health_state, &book.to_json()) {
                log(&format!("couldn't write the health book: {}", error.code()));
            }
            log(&format!("credential {} is now {}", record.name, state.label()));
        }
    }

    /// Token upkeep (R39): renews every credential whose kind's refresher says it is due, and
    /// stores the result as a new version. A refusal marks it refused, for the person to sign in
    /// again; any other failure is tried again at the next pass.
    fn upkeep(&self) {
        let Ok(doc) = self.snapshot() else { return };
        let now = crate::now_unix();
        for record in &doc.records {
            let Some(refresher) = kinds::spec(record.kind).and_then(|spec| spec.refresher) else { continue };
            if !(refresher.due)(record.expires_at, now) {
                continue;
            }
            let mut event = AuditEvent::named("renew", &record.name, "sending");
            event.secret_id = Some(record.id.clone());
            if self.record(event.clone()).is_err() {
                return;
            }
            match (refresher.renew)(&self.client, &record.value) {
                Ok(renewed) => match self.with_vault(|vault| vault.renew(&record.id, renewed)) {
                    Ok((summary, _)) => {
                        let mut book = self.health.lock().unwrap_or_else(|e| e.into_inner());
                        book.observe(&summary.id, summary.version, HealthState::Works, None, crate::now_rfc3339());
                    }
                    Err(error) => log(&format!("couldn't store the renewed {}: {}", record.name, error.code())),
                },
                Err(VaultError::CredentialRefused) => {
                    event.outcome = "denied: credential_refused".into();
                    self.audit(event);
                    self.observe(record, HealthState::Refused, None);
                }
                Err(error) => {
                    event.outcome = format!("failed: {}", error.code());
                    self.audit(event);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn proxy(
        &self,
        doc: &VaultDoc,
        secret: &SecretRef,
        method: String,
        path: String,
        headers: std::collections::BTreeMap<String, String>,
        body: Option<String>,
        body_base64: Option<String>,
        peer: &Caller,
    ) -> Result<ProxyReplyOut, VaultError> {
        let logged_path: String = path.split(['?', '#']).next().unwrap_or("").chars().take(200).collect();
        let record = doc.find_ref(secret);
        let mut event = AuditEvent::named("proxy", &record.map_or_else(|| secret.label(), |r| r.name.clone()), "");
        event.secret_id = record.map(|r| r.id.clone());
        event.method = Some(method.chars().take(16).collect());
        event.path = Some(logged_path);
        let event = with_peer(event, peer);
        let fail = |error: VaultError, mut event: AuditEvent| {
            event.outcome = format!("denied: {}", error.code());
            if let VaultError::RuleMismatch(why) | VaultError::BadRequest(why) = &error {
                event.detail = Some(why.clone());
            }
            self.audit(event);
            error
        };

        let Some(record) = record else {
            return Err(fail(secret.not_found(), event));
        };
        if record.kind != Kind::ApiKey {
            return Err(fail(VaultError::WrongKind, event)); // R5
        }
        let Some(rule) = &record.rule else {
            return Err(fail(VaultError::InvalidRule("this key has no rule".into()), event));
        };
        let mut event = event;
        event.host = Some(rule.host.clone());
        let body = match (body, body_base64) {
            (Some(_), Some(_)) => {
                return Err(fail(VaultError::BadRequest("send body or body_base64, not both".into()), event));
            }
            (Some(text), None) => text.into_bytes(),
            (None, Some(encoded)) => match BASE64.decode(encoded) {
                Ok(bytes) => bytes,
                Err(_) => return Err(fail(VaultError::BadRequest("body_base64 isn't base64".into()), event)),
            },
            (None, None) => Vec::new(),
        };
        let request = ProxyRequest {
            method,
            path_and_query: path,
            headers: headers.into_iter().collect(),
            body,
        };
        if let Err(error) = proxy::check(rule, &request) {
            return Err(fail(error, event));
        }
        // R28: the use is on disk before the key leaves the vault. No line, no request.
        let mut attempt = event.clone();
        attempt.outcome = "sending".into();
        self.record(attempt)?;
        match proxy::send(&self.client, rule, &record.value, &request) {
            Ok(response) => {
                event.outcome = "ok".into();
                event.status = Some(response.status);
                self.audit(event);
                let (body, body_base64) = match String::from_utf8(response.body) {
                    Ok(text) => (Some(text), None),
                    Err(error) => (None, Some(BASE64.encode(error.into_bytes()))),
                };
                Ok(ProxyReplyOut {
                    ok: true,
                    status: response.status,
                    headers: response.headers.into_iter().map(|(k, v)| [k, v]).collect(),
                    body,
                    body_base64,
                })
            }
            Err(error) => {
                if let VaultError::UpstreamFailed(why) = &error {
                    event.detail = Some(why.clone());
                }
                Err(fail(error, event))
            }
        }
    }
}
