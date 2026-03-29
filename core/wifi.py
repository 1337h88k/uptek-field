# core/wifi.py — Uptek Field WiFi / hidden network scanner
# Guides technician through hidden network detection and triangulation
import os
import re
import time
import subprocess
import threading


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run(cmd: list, timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return str(e)


def _check_root() -> bool:
    return os.getuid() == 0


def _aircrack_installed() -> bool:
    return _run(["which", "airodump-ng"]).startswith("/")


# ── Interface detection ───────────────────────────────────────────────────────

def get_wireless_interfaces() -> list:
    """Return list of wireless interface names."""
    out = _run(["iwconfig"])
    ifaces = []
    for line in out.splitlines():
        if "IEEE 802.11" in line or "Mode:Monitor" in line or "Mode:Managed" in line:
            iface = line.split()[0]
            if iface:
                ifaces.append(iface)
        elif line and not line.startswith(" ") and "no wireless" not in line:
            parts = line.split()
            if parts:
                name = parts[0]
                if name and not any(x in name for x in ["lo", "eth", "docker",
                        "veth", "br-", "tailscale", "tun", "tap"]):
                    pass  # only add if confirmed wireless above
    # Cleaner parse
    ifaces = []
    for line in out.splitlines():
        if not line.startswith(" ") and line.strip():
            name = line.split()[0]
            if ("IEEE 802.11" in line or "Mode:Monitor" in line or
                    "Mode:Managed" in line or "Tx-Power" in line):
                if name not in ifaces:
                    ifaces.append(name)
    return ifaces


def get_wireless_interfaces_clean() -> list:
    """Parse iwconfig for real wireless interfaces."""
    out = _run(["iwconfig"])
    ifaces = []
    current = None
    for line in out.splitlines():
        if line and not line.startswith(" ") and not line.startswith("\t"):
            parts = line.split()
            if parts:
                current = parts[0]
                if "no wireless extensions" in line:
                    current = None
                elif current and current not in ifaces:
                    ifaces.append(current)
    return ifaces


# ── Monitor mode ──────────────────────────────────────────────────────────────

def start_monitor_mode(iface: str) -> str | None:
    """Start monitor mode. Returns monitor interface name or None on failure."""
    print(f"  [*] Killing conflicting processes...")
    _run(["sudo", "airmon-ng", "check", "kill"])
    time.sleep(1)

    print(f"  [*] Starting monitor mode on {iface}...")
    out = _run(["sudo", "airmon-ng", "start", iface], timeout=15)

    # Parse new interface name from output
    for line in out.splitlines():
        m = re.search(r'monitor mode vif enabled.*?on \[.*?\](\S+)', line)
        if m:
            return m.group(1)
        m = re.search(r'monitor mode enabled on (\S+)', line)
        if m:
            return m.group(1)

    # Fallback: check iwconfig for monitor interface
    time.sleep(1)
    out2 = _run(["iwconfig"])
    for line in out2.splitlines():
        if "Mode:Monitor" in line:
            return line.split()[0]

    return iface + "mon"  # best guess


def stop_monitor_mode(mon_iface: str):
    """Stop monitor mode and restore NetworkManager."""
    print(f"\n  [*] Stopping monitor mode...")
    _run(["sudo", "airmon-ng", "stop", mon_iface], timeout=10)
    time.sleep(1)
    print(f"  [*] Restarting NetworkManager...")
    _run(["sudo", "systemctl", "restart", "NetworkManager"])
    time.sleep(2)
    print(f"  [*] WiFi restored.")


# ── Network scanning ──────────────────────────────────────────────────────────

def parse_airodump_output(csv_path: str) -> list:
    """Parse airodump-ng CSV output into list of network dicts."""
    networks = []
    if not os.path.exists(csv_path):
        return networks
    try:
        with open(csv_path, errors="replace") as f:
            lines = f.readlines()

        in_ap_section = True
        for line in lines:
            line = line.strip()
            if not line:
                in_ap_section = False
                continue
            if line.startswith("BSSID") or line.startswith("Station"):
                continue
            if in_ap_section:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 14:
                    bssid   = parts[0]
                    channel = parts[3].strip()
                    power   = parts[8].strip()
                    enc     = parts[5].strip()
                    essid   = parts[13].strip()
                    if re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', bssid):
                        networks.append({
                            "bssid":   bssid,
                            "channel": channel,
                            "power":   power,
                            "enc":     enc,
                            "essid":   essid,
                            "hidden":  essid == "" or essid.startswith("\\x00") or "length:" in essid.lower(),
                        })
    except Exception:
        pass
    return networks


def scan_all_networks(mon_iface: str, duration: int = 30) -> list:
    """
    Run airodump-ng for `duration` seconds, return parsed networks.
    Uses CSV output for reliable parsing.
    """
    csv_prefix = "/tmp/uptek_wifi_scan"
    csv_file   = csv_prefix + "-01.csv"

    # Clean up old scan files
    for f in [csv_file, csv_prefix + "-01.cap"]:
        if os.path.exists(f):
            os.remove(f)

    print(f"\n  [*] Scanning all channels for {duration} seconds...")
    print(f"      (Hidden networks will appear with blank or <length:X> ESSID)\n")

    proc = subprocess.Popen(
        ["sudo", "airodump-ng", "--write", csv_prefix,
         "--output-format", "csv", mon_iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # Show countdown
    for i in range(duration, 0, -5):
        print(f"      {i}s remaining...", end="\r")
        time.sleep(5)
    print()

    proc.terminate()
    time.sleep(1)

    networks = parse_airodump_output(csv_file)

    # Clean up
    for f in [csv_file, csv_prefix + "-01.cap",
              csv_prefix + "-01.kismet.csv", csv_prefix + "-01.kismet.netxml"]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except Exception:
                pass

    return networks


# ── Signal meter ──────────────────────────────────────────────────────────────

def get_signal_strength(mon_iface: str, bssid: str) -> int | None:
    """Return signal level (dBm) for a specific BSSID. None if not found."""
    out = _run(["sudo", "iwlist", mon_iface, "scan"], timeout=10)
    current_bssid = None
    for line in out.splitlines():
        line = line.strip()
        m = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', line)
        if m:
            current_bssid = m.group(1).upper()
        if current_bssid and current_bssid.upper() == bssid.upper():
            m = re.search(r'Signal level=(-\d+)', line)
            if m:
                return int(m.group(1))
    return None


def signal_meter_loop(mon_iface: str, bssid: str):
    """Interactive signal meter — shows strength in real time. Ctrl+C to stop."""
    print(f"\n  [*] Signal meter locked on {bssid}")
    print(f"      Walk slowly — closer to 0 dBm = physically closer to device")
    print(f"      -30 to -50 = very close | -51 to -65 = medium | -66+ = far")
    print(f"      Ctrl+C to stop\n")

    try:
        while True:
            sig = get_signal_strength(mon_iface, bssid)
            if sig is not None:
                # Visual bar
                strength = max(0, min(100, 100 + sig))  # -100=0%, 0=100%
                bar_len  = strength // 5
                bar      = "█" * bar_len + "░" * (20 - bar_len)
                label    = "VERY CLOSE" if sig >= -50 else "CLOSE" if sig >= -60 else "MEDIUM" if sig >= -70 else "FAR"
                print(f"  [{bar}] {sig} dBm  {label}    ", end="\r")
            else:
                print(f"  [no signal — device may be between beacons]         ", end="\r")
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n  [*] Signal meter stopped.")


# ── MAC vendor lookup ─────────────────────────────────────────────────────────

def lookup_mac_vendor(bssid: str) -> str:
    """Look up MAC vendor from OUI. Offline first, then online fallback."""
    oui = bssid.upper().replace(":", "")[:6]

    # Check if locally administered (randomized MAC)
    first_byte = int(oui[:2], 16)
    if first_byte & 0x02:
        return "Locally administered MAC (randomized) — vendor lookup not possible"

    # Try online lookup
    try:
        import urllib.request
        url = f"https://api.macvendors.com/{bssid[:8]}"
        req = urllib.request.Request(url, headers={"User-Agent": "uptek-field"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        pass

    return f"OUI {oui} — lookup failed (offline or unknown)"


# ── Deauth ────────────────────────────────────────────────────────────────────

def deauth(mon_iface: str, bssid: str, count: int = 20):
    """Send deauth frames to force client reconnect."""
    print(f"  [*] Sending {count} deauth frames to {bssid}...")
    out = _run(["sudo", "aireplay-ng", "--deauth", str(count),
                "-a", bssid, mon_iface], timeout=30)
    print(f"  [*] Deauth complete.")


# ── Main interactive mode ─────────────────────────────────────────────────────

def run_wifi_scan_mode():
    """Full guided hidden network detection workflow."""

    print("\n╔══════════════════════════════════════════╗")
    print("║   UPTEK WIFI SCANNER — Hidden Net Detect ║")
    print("╚══════════════════════════════════════════╝\n")

    if not _check_root():
        print("  [!] This mode requires root. Re-run with sudo or answer yes to sudo prompt.")
        return

    if not _aircrack_installed():
        print("  [!] aircrack-ng not found. Installing...")
        os.system("sudo apt install aircrack-ng -y")
        if not _aircrack_installed():
            print("  [!] Install failed. Run: sudo apt install aircrack-ng -y")
            return

    # Interface selection
    ifaces = get_wireless_interfaces_clean()
    if not ifaces:
        print("  [!] No wireless interfaces found.")
        print("      Run iwconfig to check your adapter.")
        return

    if len(ifaces) == 1:
        iface = ifaces[0]
        print(f"  [*] Using interface: {iface}")
    else:
        print("  Available interfaces:")
        for i, f in enumerate(ifaces, 1):
            print(f"    {i}. {f}")
        choice = input("  Select interface: ").strip()
        try:
            iface = ifaces[int(choice) - 1]
        except (ValueError, IndexError):
            iface = ifaces[0]

    print(f"\n  [!] This will disconnect WiFi temporarily during scan.")
    confirm = input("  Continue? (yes/no): ").strip().lower()
    if confirm not in ("yes", "y"):
        print("  Cancelled.")
        return

    # Start monitor mode
    mon_iface = start_monitor_mode(iface)
    print(f"  [*] Monitor interface: {mon_iface}\n")

    try:
        # Full scan
        networks = scan_all_networks(mon_iface, duration=30)

        if not networks:
            print("  [!] No networks found. Try running again or check interface.")
            return

        # Separate hidden vs visible
        hidden  = [n for n in networks if n["hidden"]]
        visible = [n for n in networks if not n["hidden"]]

        print(f"\n  Found {len(networks)} networks ({len(hidden)} hidden, {len(visible)} visible)\n")

        if hidden:
            print("  ── HIDDEN NETWORKS ──────────────────────────────────")
            for i, n in enumerate(hidden, 1):
                print(f"  {i}. BSSID: {n['bssid']}  Ch:{n['channel']}  "
                      f"Pwr:{n['power']}dBm  Enc:{n['enc']}")
            print()

        if visible:
            print("  ── VISIBLE NETWORKS ─────────────────────────────────")
            for i, n in enumerate(visible, 1):
                print(f"  {i}. {n['essid']:<30} BSSID: {n['bssid']}  "
                      f"Ch:{n['channel']}  Pwr:{n['power']}dBm")
            print()

        # All networks combined for selection
        all_nets = hidden + visible
        choice = input("  Enter number to investigate, or press Enter to skip: ").strip()

        if choice:
            try:
                target = all_nets[int(choice) - 1]
            except (ValueError, IndexError):
                print("  Invalid selection.")
                return

            bssid   = target["bssid"]
            channel = target["channel"].strip()
            essid   = target["essid"] or "(hidden)"

            print(f"\n  ── Investigating: {essid} ──────────────────────────")
            print(f"     BSSID:   {bssid}")
            print(f"     Channel: {channel}")
            print(f"     Power:   {target['power']} dBm")

            # MAC vendor lookup
            vendor = lookup_mac_vendor(bssid)
            print(f"     Vendor:  {vendor}\n")

            while True:
                print("  Options:")
                print("    1. Signal meter (triangulate physical location)")
                print("    2. Deauth (force client reconnect — reveals client MACs)")
                print("    3. Both (deauth then signal meter)")
                print("    4. Done — restore WiFi and exit")
                action = input("\n  Choice: ").strip()

                if action == "1":
                    signal_meter_loop(mon_iface, bssid)

                elif action == "2":
                    count = input("  Deauth count (default 20): ").strip()
                    count = int(count) if count.isdigit() else 20
                    deauth(mon_iface, bssid, count)
                    print(f"\n  [*] Watch airodump-ng in another terminal for client MACs:")
                    print(f"      sudo airodump-ng --bssid {bssid} -c {channel} {mon_iface}")

                elif action == "3":
                    deauth(mon_iface, bssid, 15)
                    signal_meter_loop(mon_iface, bssid)

                elif action == "4":
                    break

                else:
                    print("  Invalid choice.")

    finally:
        stop_monitor_mode(mon_iface)

    print("\n  [*] WiFi scan complete.\n")
