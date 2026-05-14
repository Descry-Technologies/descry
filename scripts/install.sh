#!/usr/bin/env sh
set -eu

REPO_URL="${DESCRY_REPO_URL:-https://github.com/descry-dev/descry.git}"
REF="${DESCRY_REF:-main}"
SOURCE_DIR="${DESCRY_SOURCE_DIR:-}"
BIN_DIR="${CARGO_INSTALL_ROOT:-$HOME/.cargo}/bin"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "descry install: missing required command: $1" >&2
    exit 1
  fi
}

install_from_source() {
  cargo install --locked --path "$1/crates/descry-cli"
}

need cargo

if [ -n "$SOURCE_DIR" ]; then
  if [ ! -f "$SOURCE_DIR/crates/descry-cli/Cargo.toml" ]; then
    echo "descry install: DESCRY_SOURCE_DIR does not look like a Descry checkout: $SOURCE_DIR" >&2
    exit 1
  fi
  install_from_source "$SOURCE_DIR"
else
  need git
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT INT TERM

  git clone --depth 1 --branch "$REF" "$REPO_URL" "$tmp_dir/descry"
  install_from_source "$tmp_dir/descry"
fi

if [ -x "$BIN_DIR/descry" ]; then
  DESCRY_BIN="$BIN_DIR/descry"
elif command -v descry >/dev/null 2>&1; then
  DESCRY_BIN="descry"
else
  echo "descry install: install completed, but descry is not on PATH." >&2
  echo "Add $BIN_DIR to PATH and run: descry doctor" >&2
  exit 0
fi

echo "descry install: installed $("$DESCRY_BIN" --help | sed -n '1p')"
echo "Next: run descry init, then descry hook install claude|codex|cursor."
