#!/usr/bin/env bash
set -euo pipefail

# Fallback yara rules dir
YARA_RULES_URL="https://github.com/nmagill123/compiled-yara-rules-rb2/releases/download/v20260212-032645/linux.tar.xz"
# Fallback libbpf source tarball
LIBBPF_SRC_URL="https://github.com/libbpf/libbpf/archive/refs/tags/v1.6.2.tar.gz"

IMAGE_NAME="rb2-builder:local"
OUT_PATH="./rb2"

ARTIFACT_PATH="${ARTIFACT_PATH:-/src/target/x86_64-unknown-linux-musl/release/rb2}"

LIBBPF_DIR_REL="rb2-ebpf/libbpf"
LIBBPF_SRC_SENTINEL_REL="$LIBBPF_DIR_REL/src/Makefile"

have() { command -v "$1" >/dev/null 2>&1; }
note() { echo "[*] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

need_host_tools() {
  have docker || die "docker is required on the host"
  have tar || die "tar is required on the host"
  have curl || die "curl is required on the host"
}

try_init_submodules() {
  if ! have git; then
    note "git not installed; skipping submodule init"
    return 1
  fi
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    note "not in a git repo; skipping submodule init"
    return 1
  fi
  note "Trying: git submodule update --init --recursive"
  git submodule update --init --recursive
}

ensure_libbpf_source_in_worktree() {
  if [ -f "$LIBBPF_SRC_SENTINEL_REL" ]; then
    note "Found libbpf source in worktree: $LIBBPF_SRC_SENTINEL_REL"
    return 0
  fi

  note "libbpf source not present; fetching from $LIBBPF_SRC_URL"
  rm -rf "$LIBBPF_DIR_REL"
  mkdir -p "$LIBBPF_DIR_REL"

  # Extract tarball into rb2-ebpf/libbpf, stripping the top-level directory
  curl -fsSL "$LIBBPF_SRC_URL" -o /tmp/libbpf-src.tar.gz

  case "$LIBBPF_SRC_URL" in
    *.tar.gz|*.tgz)
      tar -xzf /tmp/libbpf-src.tar.gz -C "$LIBBPF_DIR_REL" --strip-components=1
      ;;
    *.tar.xz)
      tar -xJf /tmp/libbpf-src.tar.gz -C "$LIBBPF_DIR_REL" --strip-components=1
      ;;
    *)
      die "LIBBPF_SRC_URL must end with .tar.gz/.tgz or .tar.xz"
      ;;
  esac
  rm -f /tmp/libbpf-src.tar.gz

  [ -f "$LIBBPF_SRC_SENTINEL_REL" ] || die "Downloaded libbpf source but $LIBBPF_SRC_SENTINEL_REL is still missing"
}

ensure_yara_rules_in_context() {
  local dest="$1"
  if [ -d "$dest/yara_linux" ]; then
    note "yara_linux already present in build context"
    return 0
  fi

  note "Fetching YARA rules -> $dest/yara_linux"
  mkdir -p "$dest/yara_linux"
  curl -fsSL "$YARA_RULES_URL" -o "$dest/.yara.tar.xz"
  tar -xJf "$dest/.yara.tar.xz" -C "$dest/yara_linux"
  rm -f "$dest/.yara.tar.xz"
}

need_host_tools

if ! try_init_submodules; then
  note "Submodule init failed or skipped; will ensure libbpf source via tarball fallback if needed"
fi

ensure_libbpf_source_in_worktree

ensure_yara_rules_in_context .

note "Building docker image: $IMAGE_NAME"
docker build -t "$IMAGE_NAME" .

# Copy artifact back (without buildx)
note "Copying rb2 out to: $OUT_PATH"
cid="$(docker create "$IMAGE_NAME")"
trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
docker cp "$cid":"$ARTIFACT_PATH" "$OUT_PATH"
docker rm -f "$cid" >/dev/null 2>&1 || true
chmod +x "$OUT_PATH" || true

note "Done: $OUT_PATH"
