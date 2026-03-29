# Uptek Field Agent -- Dev Log
> 906 Tech Express LLC

---

## 2026-03-20 -- Session 1 (Full Build)

### Concept
Needed a portable AI-powered IT field tool that runs off a thumb drive or installs via curl.
Primary use case: MSP on-site visits -- plug in, audit the client, ask questions, generate a report, leave.

### What got built

**Core architecture**
- `main.py` -- entry point, setup wizard, session loop, CLI flags (`--version`, `--audit`, `--pentest`)
- `core/config.py` -- OS detection, system-install vs portable-install detection, data root routing
- `core/profile.py` -- client profile CRUD with Fernet encryption, PIN-based key derivation, home base sync
- `core/tools.py` -- bash/PowerShell execution with READ/WRITE/DANGER permission tiers, confirm gate
- `core/audit.py` -- 18-check offline security audit battery (no internet required)
- `core/agent.py` -- provider-agnostic AI router (Grok, Claude, OpenAI, Ollama)
- `core/pentest.py` -- pentest mode with mandatory authorization gate, engagement logger, scan functions
- `core/boot.py` -- Pac-Man boot animation + bouncing Pac-Man thinking spinner
- `core/report.py` -- session report generator
- `core/tasks.py` -- saved task templates (4 built-ins: harden-ssh, check-network, clean-docker, update-system)

**Offline audit checks (18 total)**
1. Disk usage
2. Open ports (internet-exposed services)
3. Failed login attempts
4. Sensitive file permissions (.env, .pem, id_rsa, shadow)
5. Non-system users
6. Sudo-capable users
7. Running services
8. Network info (IP, gateway, DNS)
9. SSL certificate expiry
10. Pending OS updates
11. Keylogger detection
12. Firewall status (ufw/iptables)
13. SUID binaries (vs known whitelist)
14. Cron jobs
15. Outbound connections
16. SSH authorized keys
17. /etc/hosts anomalies
18. /etc/shadow permissions

**AI providers supported**
- Grok 3-mini (xAI) -- default
- Claude Sonnet (Anthropic)
- GPT-4o (OpenAI)
- Ollama (local, no key needed)

**Pentest mode** (`uptek --pentest`)
- Mandatory authorization gate (client, scope, authorized-by, notes)
- Tool check + apt install offer on first run
- Tools: nmap, nikto, feroxbuster (primary), gobuster (fallback), dirb wordlists,
  lynis, hydra, john, tshark, sqlmap, whois
- Slash commands: `/portscan`, `/webscan`, `/dirscan`, `/hardening`, `/capture`, `/addfinding`, `/report`
- AI chat wired in -- free-form questions route to the AI with full pentest tool access
- AI can invoke scan tools automatically (scan_ports, scan_web, scan_directories, scan_system_hardening)
- All actions timestamped in engagement log
- `/report` generates plain-English engagement report saved to `~/.uptek/reports/`

**Distribution**
- `install.sh` -- curl install script, downloads binary to `/usr/local/bin`
- `thumbdrive/` -- portable package (binary + run.sh + .env template)
- PyInstaller single-binary build (`build/build-linux.sh`)
- Data stored in `~/.uptek/` when system-installed, drive root when portable

### Bugs fixed during build
- `df` header `Use%` parsed as integer -- added header skip + try/except
- `lastb` footer lines counted as failed logins -- filter `btmp`/`wtmp` prefix lines
- `/etc/shadow` permission false positive -- rewrote using `stat -c '%a'` numeric check
- `*` wildcard in exposed ports -- regex restricted to numeric ports only
- `.env files: (no output)` shown as finding -- added `(no output)` filter
- PermissionError creating `tasks/` in `/usr/local/bin` -- `_is_system_installed()` routes data to `~/.uptek/`
- Client name `/exit` created `/exit_2026-03-19.txt` -- `re.sub(r"[^a-z0-9_\-]", "", safe)` sanitization
- Decryption failure fell through to new client creation -- re-prompt via recursion
- Blank Enter aborted confirm gate -- loop until valid yes/no
- Port/web scan 30s timeout -- bumped to 300s via `subprocess.run()` directly
- SUID false positives (polkit, dbus, etc.) -- expanded known whitelist
- feroxbuster install needed sudo -- documented in output
- `print("uptek > ", end="")` left before `run_agent()` -- moved to after response, printed together

### Notable
- Pac-Man boot animation (yellow `C`/`O` chomping cyan dots, winks at the end)
- Bouncing Pac-Man spinner during AI API calls (faces right going right, left going left)
- Pentest AI chat -- ask "what should I check next?" and it can run nmap/nikto/feroxbuster on its own

---

## 2026-03-20 -- Session 2 (Full Arsenal + Polish)

### Pac-Man spinner fix
- **Problem:** Pac-Man thinking spinner was fighting `input()` during permission confirm gate -- `\r` kept overwriting the prompt line while user typed
- **Fix:** Added `pause_spinner()` / `resume_spinner()` via a module-level `threading.Event` in `core/boot.py`. `_confirm()` in `tools.py` calls pause before `input()`, resumes in `finally`. Smooth as butter.

### Sudo escalation
- At startup (and pentest mode entry), Uptek checks `os.getuid()`. If not root, offers to re-launch via `os.execvp("sudo", ...)` -- replaces the process cleanly, no subprocess nesting.
- `IS_ROOT` flag in `audit.py` -- specific checks use `_sudo()` helper which tries `sudo -n` (non-interactive) and falls back to unprivileged if denied.
- Elevated checks: `lastb`, `ufw status`, `iptables`, `find ... -perm -4000`, `/etc/shadow` read, `.env` find across `/root`.

### AI chat in pentest mode
- Previous: pentest loop was slash-command only, `else` -- "Unknown command"
- Fix: `run_agent()` gained `extra_tools` and `extra_executor` optional params. Pentest loop's `else` branch now calls `run_agent()` with `PENTEST_TOOL_DEFINITIONS` merged in and `make_pentest_executor(engagement)` as the handler.
- `make_pentest_executor()` returns a closure with `engagement` bound -- AI can invoke scans autonomously and they get logged to the engagement.

### New files
- `core/network.py` -- network discovery, fingerprinting, enumeration (8 AI-callable tools)
- `core/diff.py` -- visit-to-visit audit comparison
- `tests/mock-shop-setup.sh` -- creates realistic dirty environment for testing
- `tests/mock-shop-teardown.sh` -- undoes everything cleanly

### Audit battery: 18 -> 23 checks
19. SSH Config Audit -- `sshd_config`: root login, password auth, SSHv1, X11, default port 22
20. Docker Security -- socket world-writable, privileged containers, host network mode, root containers
21. World-Writable Directories -- finds chmod 777 dirs outside /tmp
22. Password Policy -- `login.defs` aging, PAM complexity, accounts with no password
23. WiFi Security -- open connections, saved open SSIDs in NetworkManager

### Network discovery (`core/network.py`)
8 new AI tools -- all available in both regular session and pentest mode:
- `network_sweep` -- nmap ping sweep, structured host list, auto-saves to client profile
- `fingerprint_host` -- top-1000 port + version scan on a single box
- `enumerate_smb` -- enum4linux (shares, users, password policy)
- `scan_wordpress` -- wpscan (plugins, themes, CVEs)
- `scan_ssl_tls` -- testssl/sslscan (weak ciphers, protocol support, cert validity)
- `check_default_creds` -- hydra with built-in vendor defaults list (15 common pairs)
- `dns_enum` -- A/MX/TXT/NS records + zone transfer attempt
- `check_open_shares` -- SMB + NFS share enumeration

### Visit diff (`core/diff.py`)
- `/audit` now auto-saves a snapshot to the encrypted client profile
- On next visit, `/audit` automatically shows what's new, what's fixed, what's still open
- `/diff` prints the diff standalone at any time
- `format_diff()` produces clean categorized output sorted by severity

### HTML report (`core/report.py`)
- `/report html` generates a client-presentable HTML file
- Color-coded severity badges, open items, work done, visit diff baked in
- Saves alongside the plain-text report in `~/.uptek/reports/`

### Pentest mode expanded
- New tools added: masscan, enum4linux, smbclient, sslscan, whatweb, dnsrecon, responder, metasploit-framework
- New AI-callable pentest tools: `masscan_sweep`, `web_fingerprint`, `dns_recon`, `scan_sql_injection`
- Tool list: 11 -> 19 tools
- Pentest AI tool count: 4 -> 8

### New slash commands
- `/sweep [subnet]` -- network discovery, auto-populates client profile systems list
- `/diff` -- standalone visit diff
- `/report html` -- HTML report
- `/report` still works for plain text

### AI tool count summary
- Regular session: **11 tools** (8 network + bash_exec + read_file + check_ip_reputation)
- Pentest session: **19 tools** (11 standard + 8 pentest-specific)

### Mock test environment
- `tests/mock-shop-setup.sh` -- spins up: world-readable .env/keys/PEM, HTTP server on :8080, listeners on :2222/:2121, curl-pipe-bash cron, SUID binary, stale sudo user, firewall off, persistent outbound connection, 777 upload dir
- `tests/mock-shop-teardown.sh` -- kills all PIDs, removes cron, removes test user, re-enables ufw, deletes `~/.mock-shop/`

---

## Pending / Next Session

- [ ] Windows binary build (build-windows.bat exists, untested)
- [ ] Drop agent mode -- TTL-based temporary monitor that self-destructs
- [ ] Rebuild binary + push to server after each significant change
- [ ] Pentest mode `/findings` -- list recorded findings mid-session
- [ ] wpscan needs Ruby gem install -- consider adding to INSTALL_CMDS as gem install path
- [ ] Metasploit integration workflow -- AI needs guidance on how to structure msf module invocation
