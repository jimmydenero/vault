#!/usr/bin/env bash
# Builds the vault's release archives and, with --publish, publishes them as a GitHub release.
#
#   scripts/release.sh                 # build every target this machine can build, into dist/
#   scripts/release.sh --publish       # ... and create release v<version> on volgenic/vault
#   scripts/release.sh --add           # ... and add this machine's archives to the existing
#                                      #     release, merging SHA256SUMS (the Mac's turn)
#   TARGETS="x86_64-unknown-linux-musl" scripts/release.sh   # just some targets
#
# Targets: x86_64-unknown-linux-musl and aarch64-unknown-linux-musl (static, built with
# cargo-zigbuild, on Linux or a Mac), and aarch64-apple-darwin (only on a Mac, with plain cargo).
# Each becomes dist/vault-<version>-<target>.tar.gz holding `vault`, README.md and LICENSE, and
# dist/SHA256SUMS lists them all. See docs/releasing.md.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO="volgenic/vault"
MODE="build"
case "${1:-}" in
  "") ;;
  --publish) MODE="publish" ;;
  --add) MODE="add" ;;
  *) echo "usage: $0 [--publish | --add]" >&2; exit 2 ;;
esac

VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)"
[ -n "$VERSION" ] || { echo "can't read the version from Cargo.toml" >&2; exit 1; }
TAG="v$VERSION"

# A release is built from a clean, committed tree, so `vault --version` names its real commit.
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "the working tree has uncommitted changes; commit them first" >&2
  exit 1
fi
COMMIT="$(git rev-parse --short=12 HEAD)"

HOST_OS="$(uname -s)"
if [ -z "${TARGETS:-}" ]; then
  TARGETS="x86_64-unknown-linux-musl aarch64-unknown-linux-musl"
  [ "$HOST_OS" = "Darwin" ] && TARGETS="$TARGETS aarch64-apple-darwin"
fi

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

DIST="dist"
mkdir -p "$DIST"
BUILT=()
for target in $TARGETS; do
  echo "== $target"
  rustup target add "$target" >/dev/null
  case "$target" in
    *-apple-darwin)
      [ "$HOST_OS" = "Darwin" ] || { echo "$target is built on a Mac only" >&2; exit 1; }
      cargo build --release --locked --target "$target"
      ;;
    *-linux-musl)
      command -v cargo-zigbuild >/dev/null || {
        echo "needs cargo-zigbuild and zig: cargo install cargo-zigbuild, and zig from https://ziglang.org/download/" >&2
        exit 1
      }
      cargo zigbuild --release --locked --target "$target"
      ;;
    *) echo "unknown target $target" >&2; exit 1 ;;
  esac
  bin="target/$target/release/vault"
  stage="$(mktemp -d)"
  name="vault-$VERSION-$target"
  mkdir "$stage/$name"
  cp "$bin" "$stage/$name/vault"
  cp README.md LICENSE "$stage/$name/"
  # Owner 0 in the archive (GNU tar), so it names no local account.
  tar -C "$stage" -czf "$DIST/$name.tar.gz" --owner=0 --group=0 "$name" 2>/dev/null \
    || tar -C "$stage" -czf "$DIST/$name.tar.gz" "$name"
  rm -rf "${stage:?}"
  BUILT+=("$name.tar.gz")
  file "$bin" || true
done

# SHA256SUMS lists every archive in dist/ for this version (the Mac's run adds its own line to
# the Linux ones it downloaded; see --add).
(
  cd "$DIST"
  ls "vault-$VERSION-"*.tar.gz | sort | while read -r archive; do sha256 "$archive"; done > SHA256SUMS
)
echo "== dist/SHA256SUMS"
cat "$DIST/SHA256SUMS"

case "$MODE" in
  build) ;;
  publish)
    notes="Volgenic vault $VERSION, commit $COMMIT.

Download the archive for your machine, check it against SHA256SUMS, unpack it and run \`./vault install\` (add \`--json\` for a program). Linux builds are static (musl) and need no Rust toolchain or OpenSSL. See docs/releasing.md."
    gh release create "$TAG" --repo "$REPO" --target "$(git rev-parse HEAD)" --title "vault $VERSION" \
      --notes "$notes" "${BUILT[@]/#/$DIST/}" "$DIST/SHA256SUMS"
    gh release view "$TAG" --repo "$REPO" --json url --jq .url
    ;;
  add)
    # Merge with the release's SHA256SUMS: take its lines for archives this run didn't build.
    old="$(mktemp)"
    gh release download "$TAG" --repo "$REPO" --pattern SHA256SUMS --output "$old" --clobber
    merged="$(mktemp)"
    {
      for archive in "${BUILT[@]}"; do grep -v "  $archive\$" "$old" > "$old.x" || true; mv "$old.x" "$old"; done
      cat "$old"
      (cd "$DIST" && for archive in "${BUILT[@]}"; do sha256 "$archive"; done)
    } | sort -k2 > "$merged"
    cp "$merged" "$DIST/SHA256SUMS"
    rm -f "$old" "$merged"
    echo "== merged SHA256SUMS"
    cat "$DIST/SHA256SUMS"
    gh release upload "$TAG" --repo "$REPO" --clobber "${BUILT[@]/#/$DIST/}" "$DIST/SHA256SUMS"
    gh release view "$TAG" --repo "$REPO" --json url --jq .url
    ;;
esac
