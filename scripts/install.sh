#!/usr/bin/env sh
set -eu

REPO_URL="${DESCRY_REPO_URL:-https://github.com/descry-dev/descry.git}"
REF="${DESCRY_REF:-main}"
VERSION="${DESCRY_VERSION:-latest}"
RELEASE_BASE_URL="${DESCRY_RELEASE_BASE_URL:-https://github.com/descry-dev/descry/releases/download}"
INSTALL_DIR="${DESCRY_INSTALL_DIR:-$HOME/.local/bin}"
SOURCE_DIR="${DESCRY_SOURCE_DIR:-}"
CARGO_ROOT="${CARGO_INSTALL_ROOT:-$HOME/.cargo}"
INSTALL_MODE="${DESCRY_INSTALL_MODE:-}"
GITHUB_LATEST_API="${DESCRY_GITHUB_LATEST_API:-https://api.github.com/repos/descry-dev/descry/releases/latest}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "descry install: missing required command: $1" >&2
    exit 1
  fi
}

supported_targets() {
  echo "descry install: supported targets:" >&2
  echo "  x86_64-unknown-linux-gnu" >&2
  echo "  aarch64-apple-darwin" >&2
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os:$arch" in
    Linux:x86_64 | Linux:amd64)
      printf '%s\n' "x86_64-unknown-linux-gnu"
      ;;
    Darwin:arm64 | Darwin:aarch64)
      printf '%s\n' "aarch64-apple-darwin"
      ;;
    *)
      echo "descry install: unsupported OS/arch: $os/$arch" >&2
      supported_targets
      exit 2
      ;;
  esac
}

sha256_check() {
  checksum_file="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c "$checksum_file"
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum -c "$checksum_file"
  else
    echo "descry install: missing shasum or sha256sum" >&2
    exit 1
  fi
}

resolve_version() {
  if [ "$VERSION" != "latest" ]; then
    printf '%s\n' "${VERSION#v}"
    return
  fi

  need curl
  resolved="$(curl -fsSL "$GITHUB_LATEST_API" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | sed -n '1p')"
  if [ -z "$resolved" ]; then
    echo "descry install: could not resolve latest release version" >&2
    exit 1
  fi
  printf '%s\n' "$resolved"
}

download() {
  url="$1"
  output="$2"
  need curl
  curl -fsSL "$url" -o "$output"
}

install_binary() {
  binary="$1"
  destination_dir="$2"
  mkdir -p "$destination_dir"
  cp "$binary" "$destination_dir/descry"
  chmod 0755 "$destination_dir/descry"
}

install_from_release() {
  target="$(detect_target)"
  resolved_version="$(resolve_version)"
  package_name="descry-$resolved_version-$target"
  archive="$package_name.tar.gz"
  checksum="$archive.sha256"
  release_url="$RELEASE_BASE_URL/v$resolved_version"

  need tar
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "$tmp_dir"' EXIT INT TERM

  download "$release_url/$archive" "$tmp_dir/$archive"
  download "$release_url/$checksum" "$tmp_dir/$checksum"
  (
    cd "$tmp_dir"
    sha256_check "$checksum"
    tar -xzf "$archive"
  )

  if [ ! -x "$tmp_dir/$package_name/descry" ]; then
    echo "descry install: archive did not contain executable descry binary" >&2
    exit 1
  fi

  install_binary "$tmp_dir/$package_name/descry" "$INSTALL_DIR"
  echo "descry install: installed $INSTALL_DIR/descry from $archive"
}

install_from_source() {
  need cargo
  cargo install --locked --force --path "$1/crates/descry-cli" --root "$CARGO_ROOT"
}

if [ -z "$INSTALL_MODE" ]; then
  if [ -n "$SOURCE_DIR" ]; then
    INSTALL_MODE="source"
  else
    INSTALL_MODE="release"
  fi
fi

case "$INSTALL_MODE" in
  release)
    install_from_release
    DESCRY_BIN="$INSTALL_DIR/descry"
    ;;
  source)
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
    DESCRY_BIN="$CARGO_ROOT/bin/descry"
    ;;
  *)
    echo "descry install: DESCRY_INSTALL_MODE must be release or source" >&2
    exit 2
    ;;
esac

if [ ! -x "$DESCRY_BIN" ]; then
  echo "descry install: install completed, but descry was not found at $DESCRY_BIN" >&2
  exit 1
fi

echo "descry install: installed $("$DESCRY_BIN" --version)"
echo "Next: run descry init, then descry hook install claude|codex|cursor."
