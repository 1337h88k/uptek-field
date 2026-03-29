#!/bin/bash
# Uptek Field Agent — installer
# Usage: curl -fsSL https://906techexpress.com/uptek/install.sh | bash

set -e

INSTALL_DIR="${1:-/usr/local/bin}"
BASE_URL="https://906techexpress.com/uptek"
VERSION_URL="${BASE_URL}/version.txt"
SOURCE_URL="${BASE_URL}/uptek-source.tar.gz"
SOURCE_SHA256_URL="${BASE_URL}/uptek-source.tar.gz.sha256"
BINARY_URL="${BASE_URL}/uptek-field"
APP_DIR="${HOME}/.uptek-app"

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   UPTEK FIELD AGENT  |  906 Tech Express ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""

# ── OS check ──────────────────────────────────────────────────────────────────
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    echo -e "${RED}[!] Uptek Field currently supports Linux only.${RESET}"
    exit 1
fi

REMOTE_VERSION=$(curl -fsSL "$VERSION_URL" 2>/dev/null || echo "unknown")
echo -e "${GREEN}[✓]${RESET} Latest version: ${REMOTE_VERSION}"

# ── Check if already installed ────────────────────────────────────────────────
if command -v uptek &>/dev/null; then
    CURRENT=$(uptek --version 2>/dev/null || echo "unknown")
    echo -e "${YELLOW}[~]${RESET} Existing install found (version: ${CURRENT})"
    if [ "$CURRENT" = "$REMOTE_VERSION" ]; then
        echo -e "${GREEN}[✓]${RESET} Already up to date."
        exit 0
    fi
    echo "    Updating to ${REMOTE_VERSION}..."
fi

# ── Detect glibc version — use binary if ≥2.38, source otherwise ──────────────
GLIBC=$(ldd --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+$' || echo "0")
GLIBC_MAJOR=$(echo "$GLIBC" | cut -d. -f1)
GLIBC_MINOR=$(echo "$GLIBC" | cut -d. -f2)

USE_BINARY=false
if [ "$GLIBC_MAJOR" -gt 2 ] || ([ "$GLIBC_MAJOR" -eq 2 ] && [ "$GLIBC_MINOR" -ge 38 ]); then
    USE_BINARY=true
fi

# ── Install method: binary or source ──────────────────────────────────────────
if [ "$USE_BINARY" = true ]; then
    echo -e "[~] Installing pre-built binary (glibc ${GLIBC} detected)..."
    TMP=$(mktemp)
    curl -fsSL --progress-bar "$BINARY_URL" -o "$TMP"

    BINARY_SHA256_URL="${BASE_URL}/uptek-field.sha256"
    EXPECTED_BIN_SHA=$(curl -fsSL "$BINARY_SHA256_URL" 2>/dev/null | tr -d '[:space:]')
    ACTUAL_BIN_SHA=$(sha256sum "$TMP" | awk '{print $1}')
    if [ -n "$EXPECTED_BIN_SHA" ] && [ "$ACTUAL_BIN_SHA" != "$EXPECTED_BIN_SHA" ]; then
        echo -e "${RED}[!] Checksum mismatch — aborting. Binary may be corrupted or tampered.${RESET}"
        rm -f "$TMP"
        exit 1
    fi

    chmod +x "$TMP"
    if [ -w "$INSTALL_DIR" ]; then
        mv "$TMP" "${INSTALL_DIR}/uptek"
    else
        sudo mv "$TMP" "${INSTALL_DIR}/uptek"
    fi
    echo -e "${GREEN}[✓]${RESET} Binary installed at ${INSTALL_DIR}/uptek"

else
    echo -e "[~] Installing from source (glibc ${GLIBC} — binary needs ≥2.38)..."

    # Dependencies
    echo -e "[~] Checking Python dependencies..."
    python3 -m pip install --quiet python-dotenv cryptography requests 2>/dev/null || \
    sudo pip3 install --quiet python-dotenv cryptography requests 2>/dev/null || true

    # Download + verify + extract source
    mkdir -p "$APP_DIR"
    TMP=$(mktemp)
    curl -fsSL --progress-bar "$SOURCE_URL" -o "$TMP"

    EXPECTED_SHA=$(curl -fsSL "$SOURCE_SHA256_URL" 2>/dev/null | tr -d '[:space:]')
    ACTUAL_SHA=$(sha256sum "$TMP" | awk '{print $1}')
    if [ -n "$EXPECTED_SHA" ] && [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
        echo -e "${RED}[!] Checksum mismatch — aborting. Download may be corrupted or tampered.${RESET}"
        rm -f "$TMP"
        exit 1
    fi

    tar -xzf "$TMP" -C "$APP_DIR" --strip-components=1
    rm -f "$TMP"
    echo -e "${GREEN}[✓]${RESET} Source installed at ${APP_DIR}"

    # Create launcher
    LAUNCHER="${INSTALL_DIR}/uptek"
    LAUNCHER_CONTENT="#!/bin/bash
exec python3 ${APP_DIR}/main.py \"\$@\""

    if [ -w "$INSTALL_DIR" ]; then
        echo "$LAUNCHER_CONTENT" > "$LAUNCHER"
        chmod +x "$LAUNCHER"
    else
        echo "$LAUNCHER_CONTENT" | sudo tee "$LAUNCHER" > /dev/null
        sudo chmod +x "$LAUNCHER"
    fi
    echo -e "${GREEN}[✓]${RESET} Launcher installed at ${LAUNCHER}"
fi

# ── Save version ───────────────────────────────────────────────────────────────
mkdir -p "${HOME}/.uptek"
echo "$REMOTE_VERSION" > "${HOME}/.uptek/version.txt"

# Silent install ping — counts successful installs
curl -fsSL "https://906techexpress.com/uptek/ping?v=${REMOTE_VERSION}" &>/dev/null &

echo ""
echo -e "${GREEN}[✓] Uptek Field ${REMOTE_VERSION} installed.${RESET}"
echo ""
echo -e "${BOLD}Get started:${RESET}"
echo "  uptek              — run interactively"
echo "  uptek --audit      — offline audit, no setup needed"
echo "  uptek --pentest    — launch pentest mode"
echo ""
echo -e "906 Tech Express — info@906techexpress.com"
echo ""
