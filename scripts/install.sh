#!/usr/bin/env bash
set -euo pipefail

# Descry install script
# Usage: curl -fsSL https://get.descry.app | sh
#        bash scripts/install.sh

REPO="Descry-Technologies/descry"
BINARY="descry"

echo ""
echo "  Descry installer"
echo ""

# Check if already installed
if command -v descry &>/dev/null; then
    CURRENT=$(descry --version 2>/dev/null || echo "unknown")
    echo "  descry is already installed: $CURRENT"
    echo "  To reinstall, uninstall first or run: cargo install --locked --path crates/descry-cli --force"
    echo ""
    exit 0
fi

# Detect OS and arch
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
    x86_64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *) echo "  Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Try to download prebuilt binary from GitHub releases
LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/' || echo "")

INSTALLED=false
if [ -n "$LATEST_TAG" ]; then
    VERSION="${LATEST_TAG#v}"
    case "$OS" in
        linux)  ASSET="${BINARY}-${VERSION}-${ARCH}-unknown-linux-gnu.tar.gz" ;;
        darwin) ASSET="${BINARY}-${VERSION}-${ARCH}-apple-darwin.tar.gz" ;;
        *)      ASSET="" ;;
    esac

    if [ -n "$ASSET" ]; then
        URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$ASSET"
        if curl -fsSL "$URL" -o /tmp/descry.tar.gz 2>/dev/null; then
            echo "  Downloading $LATEST_TAG prebuilt binary..."
            EXTRACT_DIR="/tmp/${ASSET%.tar.gz}"
            rm -rf "$EXTRACT_DIR"
            tar -xzf /tmp/descry.tar.gz -C /tmp/
            INSTALL_DIR="${HOME}/.local/bin"
            mkdir -p "$INSTALL_DIR"
            mv "$EXTRACT_DIR/descry" "$INSTALL_DIR/descry"
            chmod +x "$INSTALL_DIR/descry"
            rm -rf /tmp/descry.tar.gz "$EXTRACT_DIR"
            echo "  Installed to $INSTALL_DIR/descry"
            INSTALLED=true
        fi
    fi
fi

# Fall back to cargo install
if [ "$INSTALLED" = false ]; then
    echo "  No prebuilt binary available. Building from source..."
    echo ""

    if ! command -v cargo &>/dev/null; then
        echo "  Rust not found. Installing rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
        source "${HOME}/.cargo/env"
    fi

    echo "  Building descry (this takes 1-2 minutes)..."
    echo ""

    TMPDIR=$(mktemp -d)
    git clone --depth 1 "https://github.com/$REPO.git" "$TMPDIR/descry"
    cargo install --locked --path "$TMPDIR/descry/crates/descry-cli"
    rm -rf "$TMPDIR"
    INSTALLED=true
fi

echo ""
echo "  descry installed successfully."
echo ""
echo "  Getting started:"
echo "    descry setup             — initialize this project and install hooks"
echo "    descry doctor            — verify everything is wired"
echo "    descry demo prod-delete  — see Descry block a real attack"
echo ""
