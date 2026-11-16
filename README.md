# volgenic/vault

Volgenic's vault keeps your agents' secrets (API keys, website logins, 2FA seeds, Claude plan
tokens, Codex and Grok logins, your personal details, and your applications' build and deploy
secrets) on your own
machine (a Mac, or a Linux box such as the always-on primary host), and lets agents **use** them
without ever **seeing** them. An agent asks the vault to make
an API call and gets the API's reply; the vault adds the key on the way out. An agent asks for a
2FA code and gets the six digits, never the seed. The host's model proxy sends a model call
naming a Claude plan, and the vault adds the plan's token and streams the reply back as it
arrives. Nothing the vault returns, to an agent or on the command line, can carry a secret value,
with one exception: a build's `lease`, an app secret's value sealed to that build's own key for at
most a day ("App secrets and leases" below).

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
  (`systemd-creds --user encrypt --with-key=host+tpm2`: a user-scoped credential must also be
  bound to the host secret, so `tpm2` alone is refused). The daemon unseals it at each start,
  unattended. A copy of the disk can't open the vault on another machine; code running as you on
  this machine still can, as with the key file. Otherwise the key stays a 0600 file, as on a Mac;
  `vault status` says which. Running `vault install` again seals a key file that can now be sealed.
- **The caller check** uses `SO_PEERCRED`: only your own user ID may connect.
- **The proxy** checks certificates against the system's root certificates (rustls), and ignores
  `SSL_CERT_FILE`, `SSL_CERT_DIR` and proxy settings.
- **The backup mirror** (`vault install-mirror`) is macOS only for now.

## Install and update

From a release, with no Rust toolchain (the Linux builds are static; see
[docs/releasing.md](docs/releasing.md) for every target and how releases are made):

```sh
curl -fsSLO https://github.com/volgenic/vault/releases/download/v0.3.0/vault-0.3.0-x86_64-unknown-linux-musl.tar.gz
curl -fsSLO https://github.com/volgenic/vault/releases/download/v0.3.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
tar xzf vault-0.3.0-x86_64-unknown-linux-musl.tar.gz && vault-0.3.0-x86_64-unknown-linux-musl/vault install
```

Or from source:

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
- **The vault file and backups are format 6** (format 2 plus the `claude_plan` kind and the
  intake key in format 3, the `codex_login` and `grok_login` kinds and a login's handover
  state in format 4, the `personal_details` kind in format 5, and the `app_secret` kind with its
  application and lease flag in format 6). An older vault file is migrated at the daemon's first start, as a change of
  its own (audited and backed up): a format-1 file's secrets get their ids, and a format-2 file
  gets its intake key. Older backups restore too. An older build refuses a newer file or backup
  as newer (`newer_format`); don't go back to an older build after upgrading.

## Commands

The `vault` tool can't print a secret, so it is safe for any agent on the machine to run.

| Command | What it does |
|---|---|
| `vault install [--for-restore] [--json]` | Installs or updates the vault for your user. `--json`: one JSON object instead of prose, for a program ([docs/json.md](docs/json.md)). |
| `vault add NAME --kind api-key --host HOST --method GET --path /v1 --header "Authorization: Bearer {key}"` | Adds an API key with its rule. The value is read at a hidden prompt, or from standard input with `--yes`. |
| `vault add NAME --kind login --site SITE --username USER` | Adds a login. Stored and listed only, for now. |
| `vault add NAME --kind 2fa --site SITE` | Adds a 2FA seed: base32, or an `otpauth://` link. |
| `vault add NAME --kind claude_plan` | Adds a Claude plan's token (from `claude setup-token`). Used only by `stream`, only to `api.anthropic.com`. The host's daemon normally stores plans itself (`import_plan`, `add_sealed`). |
| `vault add NAME --kind codex_login --yes < auth.json` | Adds a Codex login (its `auth.json`, whole), which the vault alone renews from then on. Used only by `stream`, only to `chatgpt.com`. `grok_login` likewise for Grok Build, to `cli-chat-proxy.grok.com`. The host's daemon normally hands logins over itself (`import_login` and `claim_refresh`, or `add_sealed`). |
| `vault add NAME --kind personal_details` | Adds your real details (name, address, birthday, phone), asked one field at a time; leave any empty. Or `--yes` with v1's JSON object on standard input (`{"name","address","birthday","phone"}`). Stored and listed only, for now: `list` says which fields are filled, never what they say. See "Personal details" below. |
| `vault add NAME --kind app_secret --app APP [--leasable]` | Adds one of an application's build or deploy secrets (an npm token, a database URL). With `--leasable` a build may lease it, sealed to the build's own key for at most a day; without it, it is stored and listed only. Set only when it is added. See "App secrets and leases" below. |
| `vault delete NAME` | Deletes a secret. Earlier backups keep it. |
| `vault rename NAME NEW` | Renames a secret; its id, rule and value stay, its version goes up. |
| `vault list` | Ids, names, kinds, versions and sites; for personal details, which fields are filled; for app secrets, the application and whether builds may lease it. |
| `vault health` | For each Claude plan, Codex login and Grok login, by name: whether it works, has expired or was refused (sign in again), and who renews it. |
| `vault status [--json]` | The program, the daemon, backups and the audit chain. `--json`: one JSON object for a program, with a `problems` list and the command for each ([docs/json.md](docs/json.md)); no secret names. |
| `vault --version` | The version, the commit it was built from and the target. |
| `vault audit [--all]` | The audit log's last 25 lines (`--all`: every line), with its hash chain checked. Past 4 MiB `audit.log` moves to `audit.log.<n>` and the chain carries on in a new file; all are kept. `status` and `audit` check the lines written since the daemon last checked; `--all` and the daemon's start check every file from the first line. |
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
- `list` returns `{"ok":true,"secrets":[{"id","name","kind","site","version"}]}`; a
  `personal_details` secret also has `"fields":["name","address",...]`, the filled ones, and an
  `app_secret` has `"app"` and `"leasable"`.
- `totp` returns `{"ok":true,"id":"...","name":"github-2fa","code":"123456","seconds_left":17}`.
- `proxy` takes `method`, `path` (with query), optional `headers` (an object) and `body` or
  `body_base64`. It returns `{"ok":true,"status":200,"headers":[[name,value]],"body":"..."}`.
  The key goes only into the header its rule names, only to the rule's host, method and path.
  You may also name the destination you meant, `host` and `port` (443 if left out): when it
  isn't the key's rule's (the host compared case-insensitively), the call is refused
  `rule_mismatch` before anything is sent, and the refusal is audited. Without them, the call
  goes to the rule's host, as before:
  `{"op":"proxy","name":"openai","host":"api.openai.com","port":443,"method":"GET","path":"/v1/models"}`.
  Redirects come back to you unfollowed. A reply that contains the key is withheld
  (`echo_blocked`).
- **`stream`** is the streaming proxy, for model calls (the host's model proxy sends it). It
  names a secret whose kind (`claude_plan`, `codex_login`, `grok_login`; the table is
  `src/kinds.rs`) or rule (an API key) decides the upstream host, methods and paths, and which
  headers the vault sets: you never choose those. A Codex login goes to `chatgpt.com` under
  `/backend-api/codex` (and `/backend-api/wham/usage`) with `authorization: Bearer <access token>`
  and `chatgpt-account-id`; a Grok login to `cli-chat-proxy.grok.com` under `/v1` with
  `authorization: Bearer <access token>` (your `x-xai-token-auth` and `x-grok-*` headers pass
  through). For a login the vault renews, a call that finds it due renews it first, and a 401
  from the upstream is held back: the vault renews the login and makes the call once more, so
  you see the second reply only. **A login's 401 never reaches you as a 401** (Codex fails the
  turn on one, Grok retries it four times): when no renewal can fix it, the call ends with one
  error line instead, `credential_refused` (the provider refused the renewal, the login was
  refused already, or a fresh token got a 401 too: sign in again) or `login_awaiting_claim` (an
  imported login the host's daemon hasn't claimed yet, which the vault may not renew). The
  host's proxy answers either as 503, never 401. The request line is followed by exactly `body_len` raw body bytes (up to 32 MiB):

  ```json
  {"op":"stream","name":"main","method":"POST","path":"/v1/messages?beta=true",
   "headers":[["anthropic-version","2023-06-01"],["anthropic-beta","oauth-2025-04-20"],["content-type","application/json"]],
   "body_len":1234,"idle_timeout_secs":300}
  ```

  The reply is a head line (`{"ok":true,"status":200,"headers":[[name,value],...]}`), then the body
  as it arrives in chunks, each `<length in decimal>\n<bytes>`, then `0\n` and a trailer line:
  `{"ok":true,"end":"complete","bytes":N}`, or `"ok":false` with `end` `idle_timeout`,
  `upstream_failed` or `echo_blocked` for a reply cut short. A refusal (or a failure before the
  reply's head) is one error line instead. There is no overall time or size limit; the upstream
  must send something at least every `idle_timeout_secs` (300 by default, at most 900). Close
  your socket to cancel: the vault drops the upstream connection within a fraction of a second.
  Keep your side open until the trailer (on macOS a half-close reads as hanging up). Don't send
  `authorization`, `x-api-key`, `accept-encoding`, `host`, `content-length` or hop-by-hop
  headers: they are refused (`header_not_allowed`). The reply is unencoded (the vault asks for
  `identity`), and a reply that would carry the token is stopped before it does (`echo_blocked`).
- **`health`** returns `{"ok":true,"credentials":[{"id","name","kind","version","state","checked_at","status","refresh","expires_at"}]}`
  for every Claude plan, Codex login and Grok login, by name only: `state` is `works`, `expired`
  (also: past its expiry and not renewed), `refused` (sign in again) or `unknown` (not used since
  it was stored), from the last reply that said; `refresh` is `never` (a plan's token lasts a year,
  and a new sign-in replaces it), `by_vault` (the vault alone renews it) or `awaiting_claim` (an
  imported login the host's daemon hasn't handed over yet; the vault uses it but doesn't renew it).
- **`add_sealed`** stores a value that reached this machine sealed to the vault's intake key (in
  `vault status --json`, `intake`), so Volgenic's server could carry it without reading it:
  `{"op":"add_sealed","name":"main","kind":"claude_plan","sealed_base64":"<base64 of an age file>","replace":true}`.
  What is sealed is `{"v":1,"name","kind","site"?,"rule"?,"username"?,"value"}`; `name` and `kind`
  must match the request's, and the rule is read only from inside it. `replace` replaces a stored
  secret of that name and kind (same id, version up), for a `claude_plan`, `codex_login` or
  `grok_login` only, whose hosts the vault fixes; a sealed login's `value` is its `auth.json`,
  whole, and it is the vault's alone to renew from the start (a new sign-in); a sealed API key can only be added under a new name, never replace a stored one
  (`sealed_invalid`), since that would let whoever sealed it change where the key is sent. Delete with `delete` by name, as for any secret.
  Sealed personal details carry v1's object as a JSON string in `value`
  (`{"v":1,"name":"v1-details","kind":"personal_details","value":"{\"name\":\"...\",\"address\":\"...\"}"}`);
  they are added under a new name only, like an API key (whoever seals could otherwise change
  the address a form is filled with): delete, then add, to change them.
  A sealed app secret carries its `app` and, to be leasable, `"leasable":true`
  (`{"v":1,"name":"shop-npm","kind":"app_secret","app":"shop","leasable":true,"value":"npm_..."}`);
  only an `app_secret` may carry either, and it too is added under a new name only.
- **`lease`** seals app secrets to a build's own key (host only; "App secrets and leases" below).
- **`import_plan`** is the upgrade's move of the host's existing plan tokens into the vault:
  `{"op":"import_plan","plans":[{"name":"main","value":"sk-ant-oat01-..."}]}` returns each plan's
  `result` by name: `done` (added, or a different value replaced, version up), `unchanged` (already
  there with that value) or `failed` (with `error`). Safe to repeat. The host reads its own token
  files and Keychain items and hands them over; the vault never reads the Keychain.
- **`import_login`** and **`claim_refresh`** hand the host's existing Codex and Grok logins to the
  vault, in the order below ("Handing over a Codex or Grok login").
  `{"op":"import_login","logins":[{"name":"codex","kind":"codex_login","auth_json":"<the file's text>"}]}`
  returns each login's `result` by name (`done`, `unchanged` or `failed` with `error`), its
  `version` and whether it is `claimed`; `{"op":"claim_refresh","name":"codex","version":1}`
  returns `{"ok":true,"secret":{...},"claimed":true,"already":false}`.
- The other requests (`status`, `audit`, `add`, `delete`, `rename`, `confirm-kit`, `reset`, `restore`,
  `backup`, `verify-backup`, `read-backup`, `mirror-plan`, `mirror-report`) are what the
  command-line tool and the mirror send; `src/protocol.rs` lists them.
- Errors are `{"ok":false,"error":"rule_mismatch","message":"..."}`; `not_leasable` adds
  `"names"`.

## Handing over a Codex or Grok login

Codex and Grok both rotate the refresh token at every renewal, and the old one is dead from then
on. So exactly one party may renew a login at any moment: the host's daemon until it hands the
login over, the vault after. The vault never renews an imported login until the daemon says it
has stopped. For each login (`~/.codex/auth.json`, each account's `CODEX_HOME`, `~/.grok/auth.json`):

0. **On every start, before renewing anything**, the daemon asks `health`. A login listed with
   `refresh: "by_vault"` is the vault's: the daemon never renews it again and never hands its
   file's refresh token to anyone. One with `awaiting_claim` is part way through: carry on at 2.
1. **Stop renewing it**, and record that durably (a marker the daemon reads at start), then wait
   for a renewal already running to finish (the keeper's `exclusive` chain; Grok's own lock).
2. **Read the file whole** (`readWholeLogin`) and send it: `import_login`. Take the reply's
   `version`. `failed`: the login stays the daemon's; nothing about it changed in the vault.
   `unchanged` with `claimed: true`: it was handed over already; you're done.
3. **Claim it**: `claim_refresh` with that name and `version`. From the reply on, only the vault
   renews it. `version_mismatch` means the vault holds another import of it than yours: go back
   to 2.
4. **Record the claim** with the marker, and don't let anything renew the file again: its refresh
   token is the vault's to spend. Model traffic goes through `stream`; a container gets the
   placeholder `auth.json` (no real token), as the scout page on pointing Codex and Grok at the
   proxy describes. A Codex or Grok run on the host itself with the original file would renew it
   and retire the vault's token, so blank the file's refresh token (or move the file aside).

A crash anywhere is safe: before 3 the vault hasn't renewed anything, and importing the same file
again changes nothing (`unchanged`, same version); after 3, step 0 finds `by_vault`. Importing a
different file for a claimed login fails with `login_claimed` and changes nothing: only a new
sign-in replaces it, sealed (`add_sealed` with `replace`, whose `value` is the new `auth.json`).
A renewal stores the new tokens, the rotated refresh token with them, in the vault file before any
call uses the new access token. Two calls that find a login due at once wait for one renewal
between them, so the same refresh token is never sent twice. Renewals go to `auth.openai.com`
and `auth.x.ai` only, which no caller can reach through `stream`.

## Personal details

A `personal_details` secret holds a person's real name, address, birthday and phone, for the few
sites that need the real person (work item #7435). v1 kept them on Volgenic's server
(`personal_details.ciphertext`, one JSON object); core hands them to their owner's vault with
`add_sealed`, as it does v1's logins.

- **Given** as v1's object: `{"name","address","birthday","phone"}`, each a string; any may be
  missing, `null` or empty, at least one filled, no other key. Each field is trimmed text of at
  most 500 characters, with no control character but a line break. Nothing parses the birthday
  or the phone: they are kept as typed.
- **Stored** as the vault's own object with the filled fields only (`src/details.rs`). The
  record also names its filled fields, which `list`, `add`'s reply and the audit line show;
  never a value.
- **Used** by nothing yet: no request gives a value back, `proxy`, `stream` and `totp` refuse it
  (`wrong_kind`). A way for a form-filling agent to fill one field without Volgenic's server
  seeing it is a later step. Today: add, list, rename, delete.

## App secrets and leases

An `app_secret` is one of an application's build or deploy secrets (an npm token, a database URL),
in its owner's vault, for the application it names (work item #7446). A build can't run without
them, so this is **the one kind whose value leaves the vault**, and only one way: a **lease**,
sealed to one build's own key, for at most a day, audited. It is for jobs the host's daemon runs
(builds and deploys), never for an agent.

- **Added** with `vault add NAME --kind app_secret --app APP [--leasable]`, or sealed
  (`add_sealed`, with `app` and `leasable` inside the sealed object). The value is UTF-8 text
  without a NUL, kept exactly as given. **Only a secret added as leasable can be leased**; nothing
  changes the flag later (delete and add again).
- **Listed** with its application and whether it is leasable, never its value.
- **Used only by `lease`.** `stream`, `proxy` and `totp` refuse it (`wrong_kind`).

The build makes an age X25519 key of its own, and the host's daemon asks:

```json
{"protocol":2,"op":"lease","job":"build:4812","recipient":"age1...","names":["shop-npm","shop-db"],
 "ttl_seconds":3600,"request_id":"..."}
```

- `job`: 1 to 128 printable characters, no spaces (`build:<id>`, `deploy:<id>`). `recipient`: an
  age X25519 public key (`age1...`; no SSH or plugin recipients). `names` (and/or `ids`): 1 to 64
  secrets, each once. `ttl_seconds`: 60 to 86,400.
- **Answer:** `{"ok":true,"sealed":[{"name","id","sealed_base64"}],"missing":[names it holds nothing under],"expires_at","job"}`.
  Ciphertext only: each `sealed_base64` is an age file sealed to `recipient`, whose plaintext is
  `{"v":1,"lease":"build:4812","name":"shop-npm","value":"npm_...","expires_at":"2026-11-16T13:00:00Z"}`.
- **The job checks what it opens:** it refuses a plaintext whose `v`, `lease` or `name` isn't
  what it asked for, or whose `expires_at` has passed. The expiry is inside the ciphertext, so no
  relay can change it; the vault can't reach the job to hold it to it.
- **A secret it holds that isn't a leasable app secret refuses the whole lease**, and nothing is
  sealed: `{"ok":false,"error":"not_leasable","message","names":[the refused names]}`. A vault
  older than this answers `bad_request` "unknown op".
- **Audit:** one `lease` line per secret leased (its name and id, the job, the recipient key's
  fingerprint, the expiry and the caller), on disk before the answer leaves; a refusal is one
  `lease denied: <code>` line. Never a value.
- **The accepted gap:** any process running as you can lease to a key of its own, as it can read
  the vault's files today. A lease is never automatic: only secrets you marked leasable, and each
  lease is in `vault audit`. See the threat model's 2026-11-16 (3) block.

## Build

A Rust (Cargo) project with no native shim: `cargo build` is the gate, on macOS or Linux.
`cargo build --features test-upstream` is for local evidence only and never released: its
daemon sends every kind's hosts and token servers (`api.anthropic.com`, `chatgpt.com`,
`auth.openai.com`, `cli-chat-proxy.grok.com`, `auth.x.ai`) to `127.0.0.1:$VAULT_TEST_UPSTREAM_PORT` and also trusts the CA in
`$VAULT_TEST_CA`, so a local test server can stand in for Anthropic over real TLS.
Release builds (static Linux, and macOS on a Mac): `scripts/release.sh`, described in
[docs/releasing.md](docs/releasing.md).

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. See `AGENTS.md`. The gate is that
`cargo build` succeeds, plus a terminal recording of anything a person can see.
