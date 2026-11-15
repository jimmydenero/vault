# volgenic/vault

Volgenic's vault: keeps your agents' secrets on your own machine and lets agents use them without
seeing them. The design is the owner's decision page, "Volgenic v2 secret store: secrets on the
user's own hardware", https://volgenic.com/pages/1f495021-effc-4fd2-9160-24cbcd73dbe3.

## Build

A Rust (Cargo) project for macOS and Linux.

```sh
cargo build                                    # the gate (on Linux it needs no OpenSSL headers)
cargo check --target aarch64-apple-darwin      # from Linux: the macOS code still type-checks
cargo run                                      # the command-line executable
```

- `src/lib.rs`: the library crate. Decisions live here as functions over plain values.
- `src/main.rs`: the `vault` command-line executable, a thin shell around the library.
- What differs between macOS and Linux sits behind `cfg`, in a few places only: `platform` (the
  socket caller check, hardening, who listens on a DevTools port), `store` (paths), `keyprotect`
  (the vault key; the only code that touches where it is kept), `install` (launchd or systemd)
  and the proxy's TLS backend.
- A container usually has no systemd: `vault install` then writes the unit and says it didn't
  start it, and `~/.local/share/volgenic/bin/vault daemon` runs the daemon by hand. The socket is
  then `~/.local/share/volgenic/socket/vault.sock`, because there is no `/run/user/<uid>`.

## Tests: none, as an experiment

The owner, 2026-11-07, for Volgenic v2's core, app and host, extended to the vault on 2026-11-09
(work item #6101): the vault starts with no tests at all. We only need to know that it builds.

- **Don't write tests.** Don't add `#[test]` or `#[cfg(test)]` code, a `tests/` folder, CI, GitHub
  Actions or style lints (no rustfmt or clippy gate).
- **The gate for a change is that `cargo build` succeeds.** A worker runs it once at the end; a
  reviewer reads the code and runs it once. A missing test is not a finding.
- **Anything a person can see** (the command's output, a prompt, an approval) gets a short
  terminal recording or screenshots in its pull request. That is where a broken experience is
  caught: by the author and the reviewer looking.
- **A test is added only for a regression that actually happened, and only when the owner asks
  for it.** Then follow the test guidelines,
  https://volgenic.com/pages/6ddc923c-9ba4-468c-990b-d45d722b381c, and the test discipline at
  `/kit/icm/test-discipline/CONTEXT.md` (in every Volgenic container), which also covers setting
  up the lint and the unit and integration split that day.
- Decisions still belong in pure, deterministic code in the library crate, with side effects
  (Keychain, files, network, the clock) in a thin shell. That keeps a bug findable and a later
  test cheap.
- No change ever calls a paid provider to prove itself.
