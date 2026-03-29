#!/bin/bash
# mock-shop-teardown.sh — undoes everything mock-shop-setup.sh created

RED="\033[31m"
GRN="\033[32m"
YEL="\033[33m"
RST="\033[0m"

MOCK_DIR="$HOME/.mock-shop"

echo ""
echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${YEL}  Uptek Mock Shop — Tearing down test environment ${RST}"
echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""

# ── Kill listener processes ───────────────────────────────────────────────────
echo -e "[1] Stopping services..."
for pidfile in "$MOCK_DIR"/*.pid; do
    [ -f "$pidfile" ] || continue
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null && echo -e "   ${GRN}✓${RST} Killed PID $pid ($(basename $pidfile))"
    fi
    rm -f "$pidfile"
done
# Also kill by port in case pidfiles are stale
for port in 8080 2222 2121 21; do
    pid=$(lsof -ti tcp:$port 2>/dev/null)
    if [ -n "$pid" ]; then
        kill $pid 2>/dev/null && echo -e "   ${GRN}✓${RST} Killed process on :$port"
    fi
done

# ── Remove suspicious cron ────────────────────────────────────────────────────
echo ""
echo -e "[2] Removing suspicious cron job..."
crontab -l 2>/dev/null | grep -v "auto-updater" | crontab - 2>/dev/null || true
echo -e "   ${GRN}✓${RST} Cron cleaned"

# ── Remove SUID binary ────────────────────────────────────────────────────────
echo ""
echo -e "[3] Removing SUID binary..."
if [ -f /usr/local/bin/shop-util ]; then
    if [ "$(id -u)" = "0" ]; then
        rm -f /usr/local/bin/shop-util
        echo -e "   ${GRN}✓${RST} Removed /usr/local/bin/shop-util"
    else
        echo -e "   ${YEL}~${RST} Need root to remove /usr/local/bin/shop-util"
    fi
else
    echo -e "   ${GRN}✓${RST} Not present"
fi

# ── Remove test user ──────────────────────────────────────────────────────────
echo ""
echo -e "[4] Removing test user..."
if id shoptemp &>/dev/null; then
    if [ "$(id -u)" = "0" ]; then
        userdel -r shoptemp 2>/dev/null || true
        echo -e "   ${GRN}✓${RST} User 'shoptemp' removed"
    else
        echo -e "   ${YEL}~${RST} Need root to remove user 'shoptemp'"
    fi
else
    echo -e "   ${GRN}✓${RST} Not present"
fi

# ── Re-enable firewall ────────────────────────────────────────────────────────
echo ""
echo -e "[5] Firewall..."
if command -v ufw &>/dev/null; then
    if [ "$(id -u)" = "0" ]; then
        ufw --force enable > /dev/null 2>&1 || true
        echo -e "   ${GRN}✓${RST} ufw re-enabled"
    else
        echo -e "   ${YEL}~${RST} Need root to re-enable ufw"
    fi
fi

# ── Remove mock files ─────────────────────────────────────────────────────────
echo ""
echo -e "[6] Removing mock credential files..."
rm -rf "$MOCK_DIR"
echo -e "   ${GRN}✓${RST} $MOCK_DIR removed"

echo ""
echo -e "${GRN}  All clean. System restored.${RST}"
echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""
