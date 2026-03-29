# core/audit.py — offline audit battery (runs without AI/internet)
import os
import re
import subprocess
import platform
import datetime
import socket
from core.config import OS


IS_ROOT = (os.name != "nt" and os.getuid() == 0)


def _run(cmd: str, shell=True, timeout=15) -> str:
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() or r.stderr.strip() or "(no output)"
    except subprocess.TimeoutExpired:
        return "[Timeout]"
    except Exception as e:
        return f"[Error: {e}]"


def _ps(cmd: str, timeout=15) -> str:
    """Run a PowerShell command on Windows."""
    return _run(f'powershell -NonInteractive -Command "{cmd}"', timeout=timeout)


def _sudo(cmd: str) -> str:
    """Run a command, prefixing with sudo if not already root."""
    prefix = "" if IS_ROOT else "sudo -n "  # -n = non-interactive, fails if password needed
    result = _run(f"{prefix}{cmd}")
    # If sudo -n fails (needs password), fall back to unprivileged attempt
    if "sudo:" in result and not IS_ROOT:
        result = _run(cmd)
    return result


# ── Individual checks ─────────────────────────────────────────────────────────

def check_open_ports() -> dict:
    if OS == "windows":
        raw = _run("netstat -an | findstr LISTENING")
    else:
        raw = _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    return {"label": "Open Ports", "raw": raw}


def check_internet_exposed(subnet: str = "") -> dict:
    """Check for services listening on 0.0.0.0 (exposed to all interfaces)."""
    if OS == "windows":
        raw = _run("netstat -an | findstr '0.0.0.0'")
    else:
        raw = _run("ss -tlnp | grep '0.0.0.0'")
    lines = [l for l in raw.splitlines() if l.strip()]
    exposed = []
    for line in lines:
        if "0.0.0.0" in line or re.search(r'\s\*:', line):
            parts = line.split()
            for p in parts:
                if ("0.0.0.0:" in p or re.match(r'^\*:\d+$', p)):
                    port = p.split(":")[-1]
                    try:
                        int(port)
                        exposed.append(port)
                    except ValueError:
                        pass
    return {
        "label": "Internet-Exposed Services",
        "exposed_ports": list(set(exposed)),
        "severity": "warning" if exposed else "ok",
        "raw": raw,
    }


def check_failed_logins() -> dict:
    if OS == "windows":
        raw = _ps('Get-WinEvent -LogName Security -FilterXPath '
                  '"*[System[EventID=4625]]" -MaxEvents 20 2>$null | '
                  'Select-Object TimeCreated, Message | Format-List')
    else:
        raw = _sudo("lastb 2>/dev/null | head -20") or \
              _run("grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -20")
    count = len([l for l in raw.splitlines() if l.strip()
                 and not l.startswith("btmp") and not l.startswith("wtmp")
                 and "(no output)" not in l])
    return {
        "label": "Failed Login Attempts",
        "count": count,
        "severity": "warning" if count > 10 else "ok",
        "raw": raw,
    }


def check_disk() -> dict:
    if OS == "windows":
        raw = _ps("Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free | Format-Table")
    else:
        raw = _run("df -h")
    # Parse Linux df for warning
    severity = "ok"
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[4].endswith("%") and parts[4] != "Use%":
            try:
                pct = int(parts[4].replace("%", ""))
            except ValueError:
                continue
            if pct >= 90:
                severity = "critical"
            elif pct >= 80 and severity != "critical":
                severity = "warning"
    return {"label": "Disk Usage", "severity": severity, "raw": raw}


def check_running_services() -> dict:
    if OS == "windows":
        raw = _ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName | Format-Table")
    else:
        raw = _run("systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -40")
    return {"label": "Running Services", "raw": raw}


def check_world_readable_sensitive() -> dict:
    """Look for sensitive files with loose permissions (Linux only)."""
    if OS == "windows":
        return {"label": "World-Readable Files", "raw": "Not supported on Windows", "severity": "ok"}
    findings = []
    # Check shadow is not world-readable (should be 640 or 000)
    shadow_perms = _run("stat -c '%a' /etc/shadow 2>/dev/null").strip()
    if shadow_perms and int(shadow_perms) % 10 != 0:
        findings.append(f"/etc/shadow is world-readable (perms: {shadow_perms})")
    # Check for .env files world-readable
    env_check = _sudo("find /var /opt /home /root /srv -name '.env' -perm -o+r 2>/dev/null | grep -v '.uptek' | grep -v 'uptek-field/thumbdrive' | head -10")
    if env_check and "[" not in env_check and "(no output)" not in env_check:
        findings.append(f".env files: {env_check}")
    return {
        "label": "Sensitive File Permissions",
        "findings": findings,
        "severity": "warning" if findings else "ok",
    }


def check_users() -> dict:
    if OS == "windows":
        raw = _ps("Get-LocalUser | Select-Object Name,Enabled,LastLogon | Format-Table")
    else:
        raw = _run("cat /etc/passwd | grep -v nologin | grep -v false | awk -F: '{print $1, $3, $6}'")
    return {"label": "User Accounts", "raw": raw}


def check_sudo_users() -> dict:
    if OS == "windows":
        raw = _ps("Get-LocalGroupMember -Group Administrators | Format-Table")
    else:
        raw = _run("getent group sudo wheel 2>/dev/null || cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep -v '^$'")
    return {"label": "Admin/Sudo Users", "raw": raw}


def check_network_info() -> dict:
    if OS == "windows":
        raw = _run("ipconfig /all")
    else:
        raw = _run("ip addr show && echo '---' && ip route show")
    return {"label": "Network Interfaces", "raw": raw}


def check_ssl_certs() -> dict:
    """Check SSL certs for common web ports."""
    findings = []
    ports = [443, 8443, 8000]
    host = "localhost"
    for port in ports:
        try:
            import ssl, socket
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(3)
                s.connect((host, port))
                cert = s.getpeercert()
                if cert:
                    exp = cert.get("notAfter", "")
                    findings.append(f"Port {port}: expires {exp}")
        except Exception:
            pass
    return {
        "label": "SSL Certificate Expiry",
        "findings": findings,
        "severity": "info",
    }


def check_updates() -> dict:
    if OS == "windows":
        raw = _ps("Get-WindowsUpdate -MicrosoftUpdate 2>$null | Select-Object Title | Format-Table")
    elif OS == "linux":
        raw = _run("apt list --upgradable 2>/dev/null | head -20 || yum check-update 2>/dev/null | head -20")
    else:
        raw = "Not supported on this OS"
    count = len([l for l in raw.splitlines() if l.strip() and "upgradable" not in l and "Listing" not in l])
    return {
        "label": "Pending Updates",
        "count": count,
        "severity": "warning" if count > 20 else "info",
        "raw": raw,
    }


def check_keyloggers() -> dict:
    if OS == "windows":
        return {"label": "Keylogger Check", "severity": "info", "raw": "Manual check recommended on Windows"}
    findings = []

    # Known keylogger process names
    known = ["logkeys", "xspy", "xkeysnail", "keylogger", "grabber", "lkl", "PyKeylogger"]
    ps_out = _run("ps aux")
    for name in known:
        if name.lower() in ps_out.lower():
            findings.append(f"Suspicious process: {name}")

    # Processes reading /dev/input directly (keyloggers do this)
    input_readers = _run("lsof /dev/input/event* 2>/dev/null | grep -v 'Xorg\\|systemd\\|libinput\\|acpid\\|COMMAND\\|touchegg\\|upowerd\\|fprintd\\|gnome-shell\\|ibus\\|at-spi'")
    if input_readers and "(no output)" not in input_readers and "[" not in input_readers:
        for line in input_readers.splitlines():
            parts = line.split()
            proc = parts[0] if parts else ""
            if proc and proc != "COMMAND":
                findings.append(f"Reads /dev/input: {proc}")

    # Suspicious autostart entries
    autostart_dirs = ["/etc/xdg/autostart", os.path.expanduser("~/.config/autostart")]
    suspicious_keywords = ["keylog", "spy", "grab", "capture"]
    known_safe = ["gnome", "dejaDup", "dejadup", "tracker", "evolution",
                  "ubuntu", "update", "nvidia", "nm-applet", "spice", "orca"]
    for d in autostart_dirs:
        if os.path.isdir(d):
            for f in os.listdir(d):
                fpath = os.path.join(d, f)
                try:
                    content = open(fpath).read()
                    content_lower = content.lower()
                    if any(s in content_lower for s in known_safe):
                        continue
                    for kw in suspicious_keywords:
                        if kw in content_lower:
                            findings.append(f"Suspicious autostart: {f}")
                            break
                except Exception:
                    pass

    # Processes running from /tmp or /dev/shm (common malware staging)
    tmp_procs = _run("ps aux | awk '{print $11}' | grep -E '^/tmp|^/dev/shm' | sort -u")
    if tmp_procs and "(no output)" not in tmp_procs:
        for p in tmp_procs.splitlines():
            findings.append(f"Process running from temp dir: {p}")

    return {
        "label": "Keylogger / Spyware Check",
        "findings": findings,
        "severity": "critical" if findings else "ok",
    }


def check_firewall() -> dict:
    if OS == "windows":
        raw = _run("netsh advfirewall show allprofiles state")
        enabled = "on" in raw.lower()
    else:
        ufw = _sudo("ufw status 2>/dev/null")
        iptables = _sudo("iptables -L INPUT --line-numbers 2>/dev/null | head -10")
        raw = ufw + "\n" + iptables
        enabled = "active" in ufw.lower() or "ACCEPT" in iptables or "DROP" in iptables

    return {
        "label": "Firewall Status",
        "severity": "ok" if enabled else "warning",
        "findings": [] if enabled else ["No active firewall detected"],
        "raw": raw,
    }


def check_suid_files() -> dict:
    if OS == "windows":
        return {"label": "SUID Files", "severity": "ok", "raw": "N/A on Windows"}
    raw = _sudo("find /usr /bin /sbin /usr/local -perm -4000 -type f 2>/dev/null | grep -v snap | head -20")
    known_suid = [
        "sudo", "su", "passwd", "ping", "ping6", "mount", "umount", "newgrp",
        "chsh", "chfn", "gpasswd", "pkexec", "at", "crontab", "ssh-agent",
        "fusermount", "fusermount3", "ntfs-3g", "pppd", "Xorg.wrap",
        "ssh-keysign", "polkit-agent-helper-1", "dbus-daemon-launch-helper",
        "unix_chkpwd", "expiry", "chage", "write", "wall", "screen",
    ]
    unexpected = []
    for line in raw.splitlines():
        binary = line.strip().split("/")[-1]
        if binary and binary not in known_suid:
            unexpected.append(line.strip())
    return {
        "label": "Unexpected SUID Binaries",
        "findings": unexpected[:10],
        "severity": "warning" if unexpected else "ok",
    }


def check_cron_jobs() -> dict:
    if OS == "windows":
        raw = _ps("schtasks /query /fo LIST 2>$null | Select-Object -First 40")
        return {"label": "Scheduled Tasks", "raw": raw, "severity": "info"}
    findings = []
    # System crontabs
    cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                 "/etc/cron.weekly", "/etc/cron.monthly"]
    all_crons = _run("crontab -l 2>/dev/null")
    root_cron = _run("cat /var/spool/cron/crontabs/root 2>/dev/null")
    suspicious = ["curl", "wget", "bash -i", "/tmp", "/dev/tcp", "nc ", "ncat", "python -c", "perl -e"]
    for content in [all_crons, root_cron]:
        for line in content.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            for s in suspicious:
                if s in line:
                    findings.append(f"Suspicious cron: {line.strip()[:100]}")
                    break
    return {
        "label": "Cron Job Audit",
        "findings": findings,
        "severity": "warning" if findings else "ok",
        "raw": all_crons,
    }


def check_outbound_connections() -> dict:
    if OS == "windows":
        raw = _run("netstat -an | findstr ESTABLISHED")
    else:
        raw = _run("ss -tnp state established 2>/dev/null | tail -20")
    # Flag connections to non-standard REMOTE ports
    suspicious = []
    common_ports = {"80", "443", "22", "53", "123", "25", "587", "993", "995"}
    for line in raw.splitlines():
        parts = line.split()
        # ss format: State Recv-Q Send-Q Local:port Remote:port
        if len(parts) >= 5:
            remote = parts[4] if len(parts) > 4 else parts[-1]
            port = remote.split(":")[-1].strip("]")
            if port.isdigit() and port not in common_ports and int(port) < 1024:
                suspicious.append(f"Outbound to unusual port {port}: {line.strip()[:100]}")
    return {
        "label": "Outbound Connections",
        "findings": suspicious[:5],
        "severity": "warning" if suspicious else "ok",
        "raw": raw,
    }


def check_ssh_keys() -> dict:
    if OS == "windows":
        return {"label": "SSH Authorized Keys", "severity": "ok", "raw": "N/A"}
    findings = []
    auth_files = [
        "/root/.ssh/authorized_keys",
        os.path.expanduser("~/.ssh/authorized_keys"),
    ]
    for path in auth_files:
        if os.path.exists(path):
            content = _run(f"cat {path}")
            if content and "(no output)" not in content and "[" not in content:
                count = len([l for l in content.splitlines() if l.strip() and not l.startswith("#")])
                findings.append(f"{path}: {count} key(s)")
    return {
        "label": "SSH Authorized Keys",
        "findings": findings,
        "severity": "info",
    }


def check_hosts_file() -> dict:
    if OS == "windows":
        raw = _run("type C:\\Windows\\System32\\drivers\\etc\\hosts")
    else:
        raw = _run("cat /etc/hosts")
    suspicious = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Flag if common domains are redirected
        if any(d in line for d in ["google.com", "microsoft.com", "apple.com",
                                    "bitwarden.com", "github.com", "paypal.com"]):
            if not line.startswith("127.0.0.1") and not line.startswith("::1"):
                suspicious.append(f"Suspicious hosts entry: {line}")
    return {
        "label": "Hosts File Tampering",
        "findings": suspicious,
        "severity": "critical" if suspicious else "ok",
        "raw": raw,
    }


# ── Additional checks ─────────────────────────────────────────────────────────

def check_ssh_config() -> dict:
    """Audit sshd_config for dangerous settings."""
    if OS == "windows":
        return {"label": "SSH Config", "severity": "ok", "raw": "N/A on Windows"}
    config = _sudo("cat /etc/ssh/sshd_config 2>/dev/null")
    findings = []
    danger_settings = {
        "PermitRootLogin yes":      "Root SSH login enabled",
        "PasswordAuthentication yes": "Password auth enabled (prefer keys only)",
        "PermitEmptyPasswords yes": "Empty passwords allowed — critical",
        "Protocol 1":               "SSHv1 enabled — obsolete and broken",
        "X11Forwarding yes":        "X11 forwarding enabled",
        "UseDNS yes":               "DNS lookups on connect (slow + spoofable)",
    }
    for pattern, message in danger_settings.items():
        for line in config.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if pattern.lower() in stripped.lower():
                findings.append(message)
                break
    # Default port check
    for line in config.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if stripped.lower().startswith("port ") and stripped.split()[-1] == "22":
            findings.append("SSH on default port 22 — consider changing")
    sev = "critical" if any("critical" in f or "v1" in f.lower() or "Empty" in f for f in findings) \
          else "warning" if findings else "ok"
    return {"label": "SSH Config Audit", "findings": findings, "severity": sev}


def check_docker_security() -> dict:
    """Docker socket permissions, privileged containers, host network mode."""
    if OS == "windows":
        return {"label": "Docker Security", "severity": "ok", "raw": "N/A"}
    # Check if Docker is reachable
    probe = _sudo("docker info 2>/dev/null | head -3")
    if (not probe or "Cannot connect" in probe or "permission denied" in probe.lower()
            or "(no output)" in probe or "not found" in probe.lower()
            or "no such file" in probe.lower() or "[Error" in probe):
        return {"label": "Docker Security", "severity": "ok", "raw": "Docker not running"}
    findings = []
    # Socket world-writable?
    sock_perms = _run("stat -c '%a' /var/run/docker.sock 2>/dev/null").strip()
    if sock_perms and int(sock_perms) % 10 >= 6:
        findings.append("Docker socket is world-writable — any local user can get root via docker")
    # Privileged containers
    priv = _sudo("docker ps -q 2>/dev/null | xargs -r docker inspect "
                 "--format '{{.Name}} privileged={{.HostConfig.Privileged}}' 2>/dev/null "
                 "| grep 'privileged=true'")
    if priv and "(no output)" not in priv and "[" not in priv:
        for line in priv.splitlines():
            findings.append(f"Privileged container: {line.strip()}")
    # Containers running as root (no User set)
    root_c = _sudo("docker ps -q 2>/dev/null | xargs -r docker inspect "
                   "--format '{{.Name}} {{.Config.User}}' 2>/dev/null | awk '$2==\"\"'")
    if root_c and "(no output)" not in root_c and "[" not in root_c:
        count = len(root_c.splitlines())
        findings.append(f"{count} container(s) running as root (no User set)")
    # Host network mode
    host_net = _sudo("docker ps -q 2>/dev/null | xargs -r docker inspect "
                     "--format '{{.Name}} {{.HostConfig.NetworkMode}}' 2>/dev/null "
                     "| grep ' host$'")
    if host_net and "(no output)" not in host_net and "[" not in host_net:
        for line in host_net.splitlines():
            findings.append(f"Container on host network (bypasses network isolation): {line.strip()}")
    sev = "critical" if any("world-writable" in f for f in findings) \
          else "warning" if findings else "ok"
    return {"label": "Docker Security", "findings": findings, "severity": sev}


def check_world_writable() -> dict:
    """World-writable directories outside /tmp — often left by misconfigured apps."""
    if OS == "windows":
        return {"label": "World-Writable Dirs", "severity": "ok", "raw": "N/A"}
    raw = _sudo(
        "find /var /opt /home /srv /etc -maxdepth 5 -type d -perm -o+w "
        "2>/dev/null | grep -v '/proc' | grep -v '/sys' | grep -v '/tmp' "
        "| grep -v '/var/lock' | grep -v '/var/crash' | grep -v '/var/metrics' "
        "| grep -v '/var/lib/BrlAPI' | head -20"
    )
    findings = [l.strip() for l in raw.splitlines() if l.strip() and "[" not in l and "Timeout" not in l]
    return {
        "label": "World-Writable Directories",
        "findings": findings[:10],
        "severity": "warning" if findings else "ok",
    }


def check_password_policy() -> dict:
    """Password aging, minimum length, and complexity enforcement."""
    if OS == "windows":
        return {"label": "Password Policy", "severity": "ok", "raw": "N/A"}
    findings = []
    login_defs = _run("cat /etc/login.defs 2>/dev/null | grep -v '^#' | grep -v '^$'")
    for line in login_defs.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        key, val = parts[0], parts[1]
        try:
            if key == "PASS_MAX_DAYS" and int(val) > 90:
                findings.append(f"Password max age {val} days (recommend ≤90)")
            if key == "PASS_MIN_LEN" and int(val) < 8:
                findings.append(f"Minimum password length {val} chars (recommend ≥8)")
            if key == "PASS_MIN_DAYS" and int(val) == 0:
                findings.append("No min days between password changes")
        except ValueError:
            pass
    # Complexity enforcement
    pam = _run("grep -r 'pwquality\\|cracklib' /etc/pam.d/ 2>/dev/null | head -3")
    if not pam or "(no output)" in pam:
        findings.append("No password complexity policy (pwquality/cracklib not configured)")
    # Accounts with no password
    no_pass = _sudo("awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null")
    if no_pass and "(no output)" not in no_pass and "[" not in no_pass:
        for u in no_pass.splitlines():
            findings.append(f"Account with no password: {u}")
    return {
        "label": "Password Policy",
        "findings": findings,
        "severity": "warning" if findings else "ok",
    }


def check_wifi_security() -> dict:
    """Check WiFi interface security — open connections, weak encryption."""
    if OS == "windows":
        raw = _run("netsh wlan show interfaces 2>$null")
        return {"label": "WiFi Security", "severity": "info", "raw": raw}
    findings = []
    iw = _run("iw dev 2>/dev/null | grep -E 'Interface|ssid|type'")
    if not iw or "(no output)" in iw or "[" in iw:
        return {"label": "WiFi Security", "severity": "ok", "raw": "No wireless interfaces"}
    # Current connection encryption
    current = _run("iwconfig 2>/dev/null | grep -E 'ESSID|Encryption'")
    if "Encryption key:off" in current:
        findings.append("Currently connected to an open (unencrypted) WiFi network")
    # Saved open networks in NetworkManager
    nm_open = _sudo(
        "grep -rl 'key-mgmt=none' /etc/NetworkManager/system-connections/ 2>/dev/null | head -5"
    )
    if nm_open and "(no output)" not in nm_open and "[" not in nm_open:
        findings.append(f"Saved open WiFi networks: {nm_open.strip()}")
    return {
        "label": "WiFi Security",
        "findings": findings,
        "severity": "warning" if findings else "info",
        "raw": iw + "\n" + current,
    }


# ── Full offline audit ────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2, "ok": 3}


def run_offline_audit() -> list:
    """Run all checks and return sorted findings list."""
    print("\n[Uptek] Running offline audit battery...")
    checks = [
        check_disk,
        check_open_ports,
        check_internet_exposed,
        check_failed_logins,
        check_world_readable_sensitive,
        check_world_writable,
        check_users,
        check_sudo_users,
        check_password_policy,
        check_running_services,
        check_network_info,
        check_wifi_security,
        check_ssl_certs,
        check_updates,
        check_keyloggers,
        check_firewall,
        check_ssh_config,
        check_suid_files,
        check_cron_jobs,
        check_outbound_connections,
        check_ssh_keys,
        check_hosts_file,
        check_docker_security,
    ]
    results = []
    for check in checks:
        try:
            print(f"  ✓ {check.__name__.replace('check_', '').replace('_', ' ').title()}")
            result = check()
            results.append(result)
        except Exception as e:
            results.append({"label": check.__name__, "error": str(e), "severity": "info"})

    results.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "ok"), 3))
    return results


def format_audit_report(results: list, client_name: str = "") -> str:
    lines = [
        f"{'=' * 60}",
        f"  UPTEK FIELD AUDIT — {client_name or 'Unknown Client'}",
        f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"{'=' * 60}",
        "",
    ]
    for r in results:
        sev = r.get("severity", "ok")
        icon = {"critical": "🔴", "warning": "⚠️ ", "info": "ℹ️ ", "ok": "✅"}.get(sev, "  ")
        lines.append(f"{icon} {r.get('label', '?')}")
        if "findings" in r and r["findings"]:
            for f in r["findings"]:
                lines.append(f"     → {f}")
        if "exposed_ports" in r and r["exposed_ports"]:
            lines.append(f"     → Exposed ports: {', '.join(r['exposed_ports'])}")
        if "count" in r:
            lines.append(f"     → Count: {r['count']}")
        lines.append("")
    return "\n".join(lines)
