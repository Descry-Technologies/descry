#!/usr/bin/env sh
set -eu

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(git describe --tags --always --dirty 2>/dev/null || printf '0.0.0-dev')"
fi
VERSION="${VERSION#v}"

DIST_DIR="${DESCRY_DIST_DIR:-dist}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "descry package: missing required command: $1" >&2
    exit 1
  fi
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    echo "descry package: missing shasum or sha256sum" >&2
    exit 1
  fi
}

need cargo
need rustc
need tar

TARGET="${DESCRY_PACKAGE_TARGET:-}"
if [ -z "$TARGET" ]; then
  TARGET="$(rustc -vV | awk '/host:/ {print $2}')"
fi
if [ -z "$TARGET" ]; then
  echo "descry package: could not determine Rust target triple" >&2
  exit 1
fi

PACKAGE_NAME="descry-${VERSION}-${TARGET}"
PACKAGE_DIR="$DIST_DIR/$PACKAGE_NAME"
ARCHIVE="$DIST_DIR/$PACKAGE_NAME.tar.gz"
BINARY_PATH="target/$TARGET/release/descry"
CHECKSUMS="$DIST_DIR/SHA256SUMS"

cargo build --locked --release --target "$TARGET" -p descry-cli

if [ ! -f "$BINARY_PATH" ]; then
  echo "descry package: expected target binary missing: $BINARY_PATH" >&2
  echo "descry package: Windows .exe packaging is not implemented for V1" >&2
  exit 1
fi

rm -rf "$PACKAGE_DIR" "$ARCHIVE" "$ARCHIVE.sha256"
mkdir -p "$PACKAGE_DIR"

cp "$BINARY_PATH" "$PACKAGE_DIR/descry"
cp README.md "$PACKAGE_DIR/README.md"
cp CHANGELOG.md "$PACKAGE_DIR/CHANGELOG.md"
cp LICENSE "$PACKAGE_DIR/LICENSE"

tar -C "$DIST_DIR" -czf "$ARCHIVE" "$PACKAGE_NAME"
(
  cd "$DIST_DIR"
  sha256_file "$PACKAGE_NAME.tar.gz" > "$PACKAGE_NAME.tar.gz.sha256"
)
if [ -f "$CHECKSUMS" ]; then
  grep -v "  $PACKAGE_NAME.tar.gz$" "$CHECKSUMS" > "$CHECKSUMS.tmp" || true
  mv "$CHECKSUMS.tmp" "$CHECKSUMS"
fi
cat "$ARCHIVE.sha256" >> "$CHECKSUMS"

echo "descry package: wrote $ARCHIVE"
echo "descry package: wrote $ARCHIVE.sha256"
echo "descry package: updated $CHECKSUMS"
