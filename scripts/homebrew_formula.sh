#!/usr/bin/env sh
set -eu

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: scripts/homebrew_formula.sh <version>" >&2
  exit 2
fi
VERSION="${VERSION#v}"

DIST_DIR="${DESCRY_DIST_DIR:-dist}"
OUTPUT="${DESCRY_FORMULA_OUTPUT:-$DIST_DIR/descry.rb}"
LINUX_TARGET="x86_64-unknown-linux-gnu"
MACOS_TARGET="aarch64-apple-darwin"

checksum_for() {
  target="$1"
  checksum_file="$DIST_DIR/descry-${VERSION}-${target}.tar.gz.sha256"
  if [ ! -f "$checksum_file" ]; then
    echo "missing checksum file: $checksum_file" >&2
    exit 1
  fi
  awk '{print $1}' "$checksum_file"
}

linux_sha="$(checksum_for "$LINUX_TARGET")"
macos_sha="$(checksum_for "$MACOS_TARGET")"

mkdir -p "$(dirname "$OUTPUT")"
cat > "$OUTPUT" <<EOF
class Descry < Formula
  desc "Local action firewall for AI coding agents"
  homepage "https://descry.app"
  license "Apache-2.0"
  version "$VERSION"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/descry-dev/descry/releases/download/v$VERSION/descry-$VERSION-$MACOS_TARGET.tar.gz"
      sha256 "$macos_sha"
    end
  end

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/descry-dev/descry/releases/download/v$VERSION/descry-$VERSION-$LINUX_TARGET.tar.gz"
      sha256 "$linux_sha"
    end
  end

  def install
    bin.install "descry"
    prefix.install "README.md"
    prefix.install "CHANGELOG.md"
    prefix.install "LICENSE"
  end

  test do
    assert_match "Usage: descry", shell_output("#{bin}/descry --help")
  end
end
EOF

echo "descry homebrew: wrote $OUTPUT"
