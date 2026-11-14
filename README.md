# volgenic/vault

Volgenic's vault keeps your agents' secrets (API keys, website logins and 2FA seeds) on your own
machine (a Mac, or a Linux box such as the always-on primary host), and lets agents **use** them
without ever **seeing** them. An agent asks the vault to make
an API call and gets the API's reply; the vault adds the key on the way out. An agent asks for a
2FA code and gets the six digits, never the seed. Nothing the vault returns, to an agent or on
the command line, can carry a secret value.

- Design: [Volgenic v2 secret store](https://volgenic.com/pages/1f495021-effc-4fd2-9160-24cbcd73dbe3)
- Threat model, with the numbered rules (R1, R2, ...) every change is reviewed against:
  [Vault threat model](https://volgenic.com/pages/4171d207-a31e-4d38-b659-60ceed9ee5fd)

**macOS and Linux.** The core is the library crate; what differs between the two sits behind
`cfg` in a few small modules (see `AGENTS.md`). On Linux the vault comes back by itself after a
reboot or a power cut, with nobody logged in.

Deliberately simple: the bar is "better than plaintext secrets on a server", not an enterprise
security system. The vault keeps secrets out of agents' normal path (they use them without
seeing them), not out of reach of code running as you: the key file and the vault file are
yours. The threat model's "Current design" block says what that accepts.

## How it runs on macOS

Everything is yours, under `~/Library/Application Support/Volgenic/` (folders 0700):

| Part | Where |
|---|---|
| The program | `bin/vault` |
| Vault file (encrypted, XChaCha20-Poly1305), vault key (`vault.key`, 32 random bytes, 0600), audit log | `vault/` |
| Local backups (age files, ciphertext) | `vault-backups/` |
| The socket | `socket/vault.sock` |
| The daemon's job, `com.volgenic.vault` | `~/Library/LaunchAgents/com.volgenic.vault.plist` |
| The daemon's log | `~/Library/Logs/Volgenic/vault.log` |
| The Recovery Kit (the key that opens backups) | `~/Volgenic Vault Recovery Kit.txt`, 0600 |

- **No sudo, no role account, no code signing, no Secure Enclave, no Keychain:** nothing the
  vault does can show a dialog or ask for a password.
- **The daemon is a LaunchAgent in your login.** It reads the key file, opens the socket and
  serves; only your own user ID may connect.
- **No gates.** Secrets can be stored right after install. Stash the Recovery Kit whenever you
  like (`vault confirm-kit` is optional and deletes the file once you've pasted it back).
- **Backups after every change** to the local folder, encrypted to the recovery key; `vault
  install-mirror` optionally copies them to another folder.

## How it runs on Linux

Everything is yours, under `~/.local/share/volgenic/` (folders 0700), with the same folders as on
a Mac:

| Part | Where |
|---|---|
| The program | `bin/vault` |
| Vault file, vault key, audit log | `vault/`: the key is `vault.key.cred`, sealed to the TPM, when the machine has one; else `vault.key`, 32 random bytes, 0600 |
| Local backups | `vault-backups/` |
| The socket | `/run/user/<uid>/volgenic/vault.sock` (systemd's `RuntimeDirectory`, 0700); `~/.local/share/volgenic/socket/` on a machine without systemd |
| The daemon's job, `volgenic-vault.service` | `~/.config/systemd/user/volgenic-vault.service` |
| The daemon's log | `~/.local/state/volgenic/vault.log` |
| The Recovery Kit | `~/Volgenic Vault Recovery Kit.txt`, 0600 |

- **A systemd user service with lingering.** `vault install` writes the unit, turns lingering on
  for you (`loginctl enable-linger`), enables the service and starts it. Lingering starts your
  service manager at boot, so the vault serves after a reboot or a power cut with nobody logged
  in, and `Restart=always` brings it back whenever it stops. If your distribution doesn't let you
  turn lingering on yourself, `vault install` prints the one `sudo loginctl enable-linger` to run.
- **Why not a system service under its own account:** that needs root to install and update,
  and is the separate-account design the owner retired. A user service keeps everything yours,
  exactly as on a Mac: the same threat model, the same caller check, no sudo.
- **The vault key is sealed to the TPM** when the machine has a TPM 2.0 and systemd 256 or later
  (`systemd-creds --user encrypt --with-key=tpm2`). The daemon unseals it at each start,
  unattended. A copy of the disk can't open the vault on another machine; code running as you on
  this machine still can, as with the key file. Otherwise the key stays a 0600 file, as on a Mac;
  `vault status` says which. Running `vault install` again seals a key file that can now be sealed.
- **The caller check** uses `SO_PEERCRED`: only your own user ID may connect.
- **The proxy** checks certificates against the system's root certificates (rustls), and ignores
  `SSL_CERT_FILE`, `SSL_CERT_DIR` and proxy settings.
- **The backup mirror** (`vault install-mirror`) is macOS only for now.

## Install and update

```sh
cargo build --release
target/release/vault install
```

No questions, no password, on either system. Running it again with a new build replaces the
program and restarts the daemon, and keeps the vault. On a new machine: `vault install
--for-restore`, then `vault restore <backup file>`.

On Linux, build with a Rust toolchain (`rustup`); nothing else is needed (no OpenSSL headers).

**Moving a Mac vault to Linux:** copy `vault/` and `vault-backups/` from
`~/Library/Application Support/Volgenic/` into `~/.local/share/volgenic/`, then `vault install`.
Or restore a backup: `vault install --for-restore`, then `vault restore FILE`.

## Stable ids and versions

- **Every secret has an id**: 32 random hex digits, given when it is added. It never changes:
  `vault rename` keeps it, and restores keep it. Each secret also has a `version` (1 when
  added, plus one for each change, a rename today) and an `updated_at`.
- **The vault has a stable identity**: the first 128 bits of the SHA-256 of its recovery public
  key, shown by `vault status`. It survives restores and moves to another machine, because the
  recovery key does, and never names a machine. Its first 12 digits are the recovery-key
  fingerprint on the kit. The `vault_id` is the copy: new at every restore, and the prefix of
  the backup files' names.
- **The vault file and backups are format 2.** A format-1 vault file (written before ids) is
  migrated at the daemon's first start: every secret gets an id, the file is written again in
  format 2, and the migration is audited and backed up as a change of its own. A format-1
  backup restores too; its secrets get their ids at the restore. An older build can't open a
  format-2 file or backup (it refuses it as damaged), so don't go back to an older build after
  upgrading.

## Commands

The `vault` tool can't print a secret, so it is safe for any agent on the machine to run.

| Command | What it does |
|---|---|
| `vault install [--for-restore]` | Installs or updates the vault for your user. |
| `vault add NAME --kind api-key --host HOST --method GET --path /v1 --header "Authorization: Bearer {key}"` | Adds an API key with its rule. The value is read at a hidden prompt, or from standard input with `--yes`. |
| `vault add NAME --kind login --site SITE --username USER` | Adds a login. Stored and listed only, for now. |
| `vault add NAME --kind 2fa --site SITE` | Adds a 2FA seed: base32, or an `otpauth://` link. |
| `vault delete NAME` | Deletes a secret. Earlier backups keep it. |
| `vault rename NAME NEW` | Renames a secret; its id, rule and value stay, its version goes up. |
| `vault list` | Ids, names, kinds, versions and sites. |
| `vault status` | The program, the daemon, backups and the audit chain. |
| `vault audit [--all]` | The audit log, with its hash chain checked. |
| `vault verify-backup [--with-recovery-key]` | Checks the newest backup decrypts and matches the vault. |
| `vault backup` | Writes (or re-checks) the current backup now. |
| `vault confirm-kit` | Optional: paste the recovery key back; deletes the kit file. |
| `vault reset` / `vault restore [FILE]` | Remove the vault (with the recovery key) and restore a backup into an empty one. |
| `vault install-mirror` | Optional, macOS: a LaunchAgent that copies backups to a mirror folder. |

## For agents: the socket

`~/Library/Application Support/Volgenic/socket/vault.sock` on macOS,
`/run/user/<uid>/volgenic/vault.sock` on Linux. Send one JSON line, read one JSON line back:

```sh
S="$HOME/Library/Application Support/Volgenic/socket/vault.sock"   # Linux: S=/run/user/$(id -u)/volgenic/vault.sock
echo '{"op":"list","protocol":2,"request_id":"r1"}' | nc -U "$S"
echo '{"op":"totp","name":"github-2fa"}' | nc -U "$S"
echo '{"op":"totp","id":"c92f14b1c738a77ebeb59e609414c927"}' | nc -U "$S"
echo '{"op":"proxy","name":"openai","method":"GET","path":"/v1/models"}' | nc -U "$S"
```

- **Protocol 2.** A request may carry `"protocol": 2` and a `"request_id"` (a string of 1 to 128
  printable ASCII characters, or a whole number). Every reply, errors included, carries
  `"protocol": 2` and echoes the `request_id` as sent. A request without `protocol` is protocol 1
  and is served the same way. A newer protocol is refused with `unsupported_protocol`.
- **Naming a secret:** `totp`, `proxy`, `delete` and `rename` take `"name"` or `"id"`, one of them.
- `list` returns `{"ok":true,"secrets":[{"id","name","kind","site","version"}]}`.
- `totp` returns `{"ok":true,"id":"...","name":"github-2fa","code":"123456","seconds_left":17}`.
- `proxy` takes `method`, `path` (with query), optional `headers` (an object) and `body` or
  `body_base64`. It returns `{"ok":true,"status":200,"headers":[[name,value]],"body":"..."}`.
  The key goes only into the header its rule names, only to the rule's host, method and path.
  Redirects come back to you unfollowed. A reply that contains the key is withheld
  (`echo_blocked`).
- The other requests (`status`, `audit`, `add`, `delete`, `rename`, `confirm-kit`, `reset`, `restore`,
  `backup`, `verify-backup`, `read-backup`, `mirror-plan`, `mirror-report`) are what the
  command-line tool and the mirror send; `src/protocol.rs` lists them.
- Errors are `{"ok":false,"error":"rule_mismatch","message":"..."}`.

## Build

A Rust (Cargo) project with no native shim: `cargo build` is the gate, on macOS or Linux.

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. See `AGENTS.md`. The gate is that
`cargo build` succeeds, plus a terminal recording of anything a person can see.
