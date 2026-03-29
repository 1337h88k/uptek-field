# core/tools.py — tool execution with permission gates
import subprocess
import os
import json
import platform
from core.config import OS
from core.network import (
    network_sweep, fingerprint_host, enumerate_smb,
    scan_wordpress, scan_ssl_tls, check_default_creds,
    dns_enum, check_open_shares, NETWORK_TOOL_DEFINITIONS,
)

# ── Permission tiers ──────────────────────────────────────────────────────────
# read   → auto-approved, no prompt
# write  → ask before executing, show what + estimated impact
# danger → always confirm, log it, require explicit yes

READ_COMMANDS = [
    "ls", "dir", "cat", "type", "head", "tail", "find", "grep",
    "netstat", "ss", "nmap", "ping", "traceroute", "df", "du",
    "free", "top", "ps", "who", "last", "lastb", "uptime",
    "systemctl status", "docker ps", "docker inspect", "ipconfig",
    "ifconfig", "ip addr", "ip route", "route", "arp",
    "Get-", "Select-", "Where-", "Format-",  # PowerShell read verbs
]

DANGER_PATTERNS = [
    "rm ", "del ", "format ", "mkfs", "dd if=", "> /dev/",
    "DROP TABLE", "DELETE FROM", ":(){:|:&};:",
    "chmod 777", "chown root", "passwd ", "userdel",
]


def _classify(command: str) -> str:
    cmd_lower = command.strip().lower()
    for danger in DANGER_PATTERNS:
        if danger.lower() in cmd_lower:
            return "danger"
    for read_cmd in READ_COMMANDS:
        if cmd_lower.startswith(read_cmd.lower()):
            return "read"
    return "write"


def _confirm(prompt: str) -> bool:
    try:
        from core.boot import pause_spinner, resume_spinner
        pause_spinner()
    except Exception:
        pass
    try:
        while True:
            answer = input(f"\n⚠️  {prompt}\nProceed? (yes/no) > ").strip().lower()
            if answer in ("yes", "y"):
                return True
            if answer in ("no", "n"):
                return False
            print("  Please type yes or no.")
    except (EOFError, KeyboardInterrupt):
        return False
    finally:
        try:
            resume_spinner()
        except Exception:
            pass


def _execute_network_tool(name: str, args: dict):
    """Execute a network tool by name. Returns None if name not recognized."""
    if name == "network_sweep":
        result = network_sweep(args.get("subnet", ""))
        return f"Found {result['count']} hosts:\n{result['summary']}\n\nFull output:\n{result['raw']}"
    elif name == "fingerprint_host":
        result = fingerprint_host(args.get("ip", ""))
        services = "\n".join(
            f"  {s['port']:<12} {s['service']:<15} {s['version']}"
            for s in result["services"]
        ) or "  (no open ports found)"
        return f"Services on {result['ip']}:\n{services}\n\nRaw:\n{result['raw']}"
    elif name == "enumerate_smb":
        return enumerate_smb(args.get("target", ""))
    elif name == "scan_wordpress":
        return scan_wordpress(args.get("target", ""))
    elif name == "scan_ssl_tls":
        return scan_ssl_tls(args.get("target", ""))
    elif name == "check_default_creds":
        return check_default_creds(args.get("target", ""), args.get("service", "ssh"))
    elif name == "dns_enum":
        return dns_enum(args.get("domain", ""))
    elif name == "check_open_shares":
        return check_open_shares(args.get("target", ""))
    return None


def bash_exec(command: str, force: bool = False) -> str:
    """Execute a shell command. Prompts for write/danger ops unless forced."""
    tier = _classify(command)

    if tier == "danger" and not force:
        print(f"\n🚨 DESTRUCTIVE OPERATION DETECTED: `{command}`")
        if not _confirm(f"This command may cause irreversible changes: `{command}`"):
            return "[Aborted by user]"

    elif tier == "write" and not force:
        if not _confirm(f"Uptek wants to run: `{command}`"):
            return "[Aborted by user]"

    try:
        if OS == "windows":
            result = subprocess.run(
                ["powershell", "-NonInteractive", "-Command", command],
                capture_output=True, text=True, timeout=30
            )
        else:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30
            )
        out = result.stdout.strip()
        err = result.stderr.strip()
        if err and not out:
            return f"[stderr] {err}"
        return out or "(no output)"
    except subprocess.TimeoutExpired:
        return "[Timeout after 30s]"
    except Exception as e:
        return f"[Error] {e}"


def read_file(path: str, tail_lines: int = 100) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
        if tail_lines and len(lines) > tail_lines:
            lines = lines[-tail_lines:]
        return "".join(lines)
    except PermissionError:
        return f"[Permission denied: {path}]"
    except FileNotFoundError:
        return f"[File not found: {path}]"
    except Exception as e:
        return f"[Error reading {path}]: {e}"


def write_file(path: str, content: str) -> str:
    """Write content to a file, resolving ~ and creating parent dirs as needed."""
    resolved = os.path.expanduser(path)
    resolved = os.path.abspath(resolved)
    if not _confirm(f"Uptek wants to write file: `{resolved}` ({len(content)} chars)"):
        return "[Aborted by user]"
    try:
        parent = os.path.dirname(resolved)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(resolved, "w") as f:
            f.write(content)
        return f"[OK] Written to {resolved}"
    except PermissionError:
        return f"[Permission denied: {path}]"
    except Exception as e:
        return f"[Error writing {path}]: {e}"


def write_memory(client_name: str, note: str) -> str:
    """Save a note to the client's rolling memory file."""
    from core.memory import append_note
    return append_note(client_name, note)


def check_ip_reputation(ip: str, abuseipdb_key: str = "") -> dict:
    if not abuseipdb_key:
        return {"error": "No AbuseIPDB key configured"}
    import requests
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": abuseipdb_key, "Accept": "application/json"},
            timeout=10,
        )
        return r.json().get("data", {})
    except Exception as e:
        return {"error": str(e)}


# ── Tool definitions for Grok function calling ────────────────────────────────

TOOL_DEFINITIONS = NETWORK_TOOL_DEFINITIONS + [
    {
        "type": "function",
        "function": {
            "name": "bash_exec",
            "description": (
                "Execute a shell command on the target machine. "
                "Read-only commands run immediately. Write/destructive commands "
                "require user confirmation before executing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The command to run"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": (
                "Write text content to a file on the local machine. "
                "Automatically resolves ~ to the user's home directory and "
                "creates any missing parent directories. Use this instead of "
                "bash_exec for all file creation tasks."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path (~ supported)"},
                    "content": {"type": "string", "description": "Text content to write"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from the filesystem. Returns last N lines.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute file path"},
                    "tail_lines": {"type": "integer", "description": "Lines to return from end (default 100)"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_memory",
            "description": (
                "Save a note to this client's persistent memory. "
                "Use this to record findings, decisions, changes made, or anything "
                "worth remembering for the next visit. Memory is per-client and "
                "persists for 14 days across sessions."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "client_name": {"type": "string", "description": "Client name (must match current client)"},
                    "note": {"type": "string", "description": "What to remember"},
                },
                "required": ["client_name", "note"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_ip_reputation",
            "description": "Check an IP address against AbuseIPDB for reputation/threat data.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address to check"},
                },
                "required": ["ip"],
            },
        },
    },
]
