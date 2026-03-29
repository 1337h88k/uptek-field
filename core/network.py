# core/network.py — network discovery, fingerprinting, enumeration
import subprocess
import re
import os


def _run(cmd: str, timeout: int = 120) -> str:
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() or r.stderr.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "[Timeout]"
    except Exception as e:
        return f"[Error: {e}]"


# ── Host Discovery ─────────────────────────────────────────────────────────────

def network_sweep(subnet: str) -> dict:
    """Ping sweep — find all live hosts on a subnet. Returns structured host list."""
    raw = _run(f"nmap -sn {subnet} 2>/dev/null", timeout=180)
    hosts = []
    current = {}
    for line in raw.splitlines():
        if "Nmap scan report for" in line:
            if current:
                hosts.append(current)
            m = re.search(r"for (.+?) \((.+?)\)|for ([\d\.]+)", line)
            if m:
                if m.group(2):
                    current = {"hostname": m.group(1).strip(), "ip": m.group(2).strip()}
                else:
                    current = {"hostname": "", "ip": m.group(3).strip()}
        elif "MAC Address" in line:
            m = re.search(r"MAC Address: ([\w:]+) \((.+?)\)", line)
            if m:
                current["mac"]    = m.group(1)
                current["vendor"] = m.group(2)
        elif "Host is up" in line:
            m = re.search(r"\((.+?) latency\)", line)
            current["latency"] = m.group(1) if m else ""
    if current:
        hosts.append(current)

    summary = []
    for h in hosts:
        name = h.get("hostname") or h.get("ip", "?")
        vendor = f" [{h['vendor']}]" if h.get("vendor") else ""
        summary.append(f"  {h.get('ip','?'):<16} {name:<30}{vendor}")

    return {
        "hosts":   hosts,
        "count":   len(hosts),
        "summary": "\n".join(summary),
        "raw":     raw,
    }


def fingerprint_host(ip: str) -> dict:
    """Quick service fingerprint of a single host — top 1000 ports, version detect."""
    raw = _run(f"nmap -sV --open -T4 --top-ports 1000 {ip} 2>/dev/null", timeout=120)
    services = []
    for line in raw.splitlines():
        if "/tcp" in line or "/udp" in line:
            parts = line.split()
            if len(parts) >= 3:
                services.append({
                    "port":    parts[0],
                    "state":   parts[1],
                    "service": parts[2],
                    "version": " ".join(parts[3:]) if len(parts) > 3 else "",
                })
    return {"ip": ip, "services": services, "raw": raw}


# ── Service-Specific Enumeration ───────────────────────────────────────────────

def enumerate_smb(target: str) -> str:
    """enum4linux — SMB/Windows share, user, and policy enumeration."""
    if subprocess.run("which enum4linux", shell=True, capture_output=True).returncode != 0:
        return "[enum4linux not installed — sudo apt-get install -y enum4linux]"
    return _run(f"enum4linux -a {target} 2>/dev/null", timeout=120)


def scan_wordpress(target: str) -> str:
    """wpscan — WordPress vulnerability scan."""
    if subprocess.run("which wpscan", shell=True, capture_output=True).returncode != 0:
        return "[wpscan not installed — sudo gem install wpscan  OR  sudo apt-get install -y wpscan]"
    return _run(f"wpscan --url {target} --no-banner --random-user-agent 2>/dev/null", timeout=180)


def scan_ssl_tls(target: str) -> str:
    """Check SSL/TLS configuration — weak ciphers, expired certs, protocol support."""
    if subprocess.run("which testssl.sh", shell=True, capture_output=True).returncode == 0:
        return _run(f"testssl.sh --quiet --color 0 {target} 2>/dev/null", timeout=120)
    elif subprocess.run("which testssl", shell=True, capture_output=True).returncode == 0:
        return _run(f"testssl --quiet --color 0 {target} 2>/dev/null", timeout=120)
    elif subprocess.run("which sslscan", shell=True, capture_output=True).returncode == 0:
        return _run(f"sslscan --no-colour {target} 2>/dev/null", timeout=60)
    return "[No SSL scanner found — sudo apt-get install -y sslscan]"


def check_default_creds(target: str, service: str = "ssh") -> str:
    """
    Quick default credential check using hydra with a small built-in list.
    NOT a full brute force — just the most common vendor defaults.
    """
    if subprocess.run("which hydra", shell=True, capture_output=True).returncode != 0:
        return "[hydra not installed]"
    defaults = [
        "admin:admin", "admin:password", "admin:1234", "admin:admin123",
        "admin:", "root:root", "root:toor", "root:password", "root:",
        "user:user", "guest:guest", "operator:operator", "manager:manager",
        "admin:Password1", "administrator:administrator",
    ]
    creds_file = "/tmp/_uptek_defaults.txt"
    with open(creds_file, "w") as f:
        f.write("\n".join(defaults))
    result = _run(
        f"hydra -C {creds_file} -t 4 -q {service}://{target} 2>/dev/null",
        timeout=90,
    )
    os.remove(creds_file)
    return result


def dns_enum(domain: str) -> str:
    """Basic DNS enumeration — A, MX, TXT, NS records + subdomain check."""
    out = []
    for record in ["A", "MX", "TXT", "NS", "AAAA"]:
        r = _run(f"dig +short {record} {domain} 2>/dev/null || nslookup -type={record} {domain} 2>/dev/null")
        if r and "(no output)" not in r:
            out.append(f"--- {record} ---\n{r}")
    # Zone transfer attempt (almost always fails, but worth noting if it doesn't)
    axfr = _run(f"dig axfr {domain} 2>/dev/null | head -20")
    if axfr and "Transfer failed" not in axfr and "(no output)" not in axfr:
        out.append(f"--- ZONE TRANSFER (!) ---\n{axfr}")
    return "\n\n".join(out) or "(no DNS records found)"


def check_open_shares(target: str) -> str:
    """Check for open SMB/NFS shares."""
    smb = ""
    nfs = ""
    if subprocess.run("which smbclient", shell=True, capture_output=True).returncode == 0:
        smb = _run(f"smbclient -L //{target} -N 2>/dev/null", timeout=30)
    nfs = _run(f"showmount -e {target} 2>/dev/null", timeout=30)
    parts = []
    if smb and "(no output)" not in smb and "[" not in smb:
        parts.append(f"SMB shares:\n{smb}")
    if nfs and "(no output)" not in nfs and "[" not in nfs:
        parts.append(f"NFS exports:\n{nfs}")
    return "\n\n".join(parts) or "(no open shares found)"


# ── Tool definitions for AI ────────────────────────────────────────────────────

NETWORK_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "network_sweep",
            "description": "Ping sweep a subnet to discover all live hosts. Use before anything else on a new network.",
            "parameters": {
                "type": "object",
                "properties": {
                    "subnet": {"type": "string", "description": "Subnet in CIDR notation, e.g. 192.168.1.0/24"},
                },
                "required": ["subnet"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fingerprint_host",
            "description": "Run a service version scan against a single host to identify what's running.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ip": {"type": "string", "description": "IP address or hostname to fingerprint"},
                },
                "required": ["ip"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_smb",
            "description": "Enumerate SMB/Windows shares, users, and policies with enum4linux.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP or hostname"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_wordpress",
            "description": "Scan a WordPress site for vulnerabilities, outdated plugins, and misconfigurations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL of the WordPress site"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_ssl_tls",
            "description": "Audit SSL/TLS configuration — weak ciphers, protocol support, certificate validity.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Hostname:port, e.g. example.com:443"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_default_creds",
            "description": "Test a target service for common default credentials (not a full brute force).",
            "parameters": {
                "type": "object",
                "properties": {
                    "target":  {"type": "string", "description": "IP or hostname"},
                    "service": {"type": "string", "description": "Service type: ssh, ftp, http, smb", "enum": ["ssh", "ftp", "http", "smb", "rdp", "telnet"]},
                },
                "required": ["target", "service"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dns_enum",
            "description": "Enumerate DNS records for a domain — A, MX, TXT, NS, and zone transfer attempt.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain name to enumerate"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_open_shares",
            "description": "Check for open SMB shares and NFS exports on a target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP or hostname"},
                },
                "required": ["target"],
            },
        },
    },
]
