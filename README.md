# Uptek Field Agent

An AI-powered IT field tool built for MSP technicians. Runs off a thumb drive or installs in seconds via curl. Plug into a client site, audit the system, ask questions, run scans, generate a report, leave.

Current version: **0.3.5** — Linux only.

---

## Install

```bash
curl -fsSL https://906techexpress.com/uptek/install.sh | bash
```

Installs to `/usr/local/bin/uptek`. Downloads a pre-built binary if your glibc is >= 2.38, otherwise installs from source automatically.

---

## Thumb Drive

Copy the contents of `thumbdrive/` to a USB drive. Run `./run.sh` on any Linux machine. No install required. All data stays on the drive.

---

## Setup

On first run, Uptek walks you through a short setup wizard:

- Choose your AI provider (Grok, Claude, OpenAI, or Ollama for local/offline)
- Enter your API key
- Set a PIN for encrypting client profiles

Config is saved to `~/.uptek/.env` (system install) or the drive root (portable).

---

## Usage

```bash
uptek                  # interactive session
uptek --audit          # offline security audit, no setup needed
uptek --pentest        # pentest mode
uptek --version        # print version
```

---

## What it does

### Interactive session
Full AI chat with tool access. Ask anything about the system you're on. The AI can read files, run commands (with permission gates), check IP reputation, sweep the network, fingerprint hosts, and more.

Slash commands:
- `/audit` — run the full offline security audit
- `/sweep [subnet]` — network discovery, saves hosts to client profile
- `/diff` — compare this visit's audit against the last one
- `/report` — save a plain-text session report
- `/report html` — save a client-presentable HTML report
- `/chat` — drop into chill chat mode (full tools still available, less intense)
- `/tasks` — saved task templates (harden-ssh, check-network, clean-docker, update-system)
- `/exit` — end session

### Offline audit (no internet required)
23-point security check battery. Runs without an API key.

| # | Check |
|---|-------|
| 1 | Disk usage |
| 2 | Open ports (internet-exposed services) |
| 3 | Failed login attempts |
| 4 | Sensitive file permissions (.env, .pem, id_rsa, shadow) |
| 5 | Non-system users |
| 6 | Sudo-capable users |
| 7 | Running services |
| 8 | Network info (IP, gateway, DNS) |
| 9 | SSL certificate expiry |
| 10 | Pending OS updates |
| 11 | Keylogger detection |
| 12 | Firewall status (ufw/iptables) |
| 13 | SUID binaries |
| 14 | Cron jobs |
| 15 | Outbound connections |
| 16 | SSH authorized keys |
| 17 | /etc/hosts anomalies |
| 18 | /etc/shadow permissions |
| 19 | SSH config audit (sshd_config) |
| 20 | Docker security |
| 21 | World-writable directories |
| 22 | Password policy |
| 23 | WiFi security (open connections, saved open SSIDs) |

Audit snapshots are saved to the encrypted client profile. On the next visit, `/audit` automatically shows what's new, what's fixed, and what's still open.

### Pentest mode
Requires explicit authorization gate before anything runs (client name, scope, authorized-by, notes). Everything is logged to a timestamped engagement file.

Tools checked and offered for install on first run:
`nmap`, `nikto`, `feroxbuster`, `gobuster`, `masscan`, `hydra`, `john`, `sqlmap`, `tshark`, `lynis`, `enum4linux`, `smbclient`, `sslscan`, `whatweb`, `dnsrecon`, `responder`, `metasploit-framework`, `wpscan`

Slash commands:
- `/portscan [host]` — nmap port scan
- `/webscan [url]` — nikto web scan
- `/dirscan [url]` — feroxbuster/gobuster directory brute force
- `/sweep [subnet]` — masscan network sweep
- `/hardening` — lynis system hardening audit
- `/capture [iface]` — tshark packet capture
- `/addfinding` — manually log a finding
- `/findings` — list findings recorded so far
- `/report` — generate plain-English engagement report

The AI is fully wired into pentest mode. Ask "what should I check next?" and it can run nmap, nikto, feroxbuster, and other tools on its own, with all actions logged to the engagement.

### Client profiles
Each client gets an encrypted profile (Fernet, PIN-derived key). Stores system inventory, audit history, networks, notes, and findings across visits.

---

## AI Providers

| Provider | Model | Requires |
|----------|-------|---------|
| Grok | grok-3-mini | xAI API key |
| Claude | claude-sonnet | Anthropic API key |
| OpenAI | gpt-4o | OpenAI API key |
| Ollama | any local model | Ollama running locally |

Ollama works fully offline with no API key.

---

## Build from source

```bash
pip install -r requirements.txt
python main.py
```

To build a single binary:

```bash
bash build/build-linux.sh
```

Requires PyInstaller. Output lands in `dist/`.

---

## Requirements

- Linux
- Python 3.10+
- pip packages: `requests`, `python-dotenv`, `cryptography`

---

## License

MIT

---

906 Tech Express LLC — info@906techexpress.com
