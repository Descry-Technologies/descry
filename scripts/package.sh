#!/usr/bin/env sh
set -eu

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  VERSION="$(git describe --tags --always --dirty 2>/dev/null || printf '0.0.0-dev')"
fi
VERSION="${VERSION#v}"

TARGET="${DESCRY_PACKAGE_TARGET:-$(uname -m)-$(uname -s | tr '[:upper:]' '[:lower:]')}"
DIST_DIR="${DESCRY_DIST_DIR:-dist}"
PACKAGE_NAME="descry-${VERSION}-${TARGET}"
PACKAGE_DIR="$DIST_DIR/$PACKAGE_NAME"
ARCHIVE="$DIST_DIR/$PACKAGE_NAME.tar.gz"

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
need tar

cargo build --locked --release -p descry-cli

rm -rf "$PACKAGE_DIR" "$ARCHIVE" "$ARCHIVE.sha256"
mkdir -p "$PACKAGE_DIR"

cp target/release/descry "$PACKAGE_DIR/descry"
cp README.md "$PACKAGE_DIR/README.md"
cp CHANGELOG.md "$PACKAGE_DIR/CHANGELOG.md"
cp LICENSE "$PACKAGE_DIR/LICENSE"

tar -C "$DIST_DIR" -czf "$ARCHIVE" "$PACKAGE_NAME"
sha256_file "$ARCHIVE" > "$ARCHIVE.sha256"
cat "$ARCHIVE.sha256" > "$DIST_DIR/SHA256SUMS"

echo "descry package: wrote $ARCHIVE"
echo "descry package: wrote $ARCHIVE.sha256"
