#!/usr/bin/env python3
# main.py — Uptek Field Agent entry point
import os
import sys
import json
import datetime
from dotenv import load_dotenv

# Load .env — from ~/.uptek/ if system-installed, else from drive root
_root = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
_system_dirs = ("/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin")
_data_home = os.path.join(os.path.expanduser("~"), ".uptek") if any(_root.startswith(d) for d in _system_dirs) else _root
os.makedirs(_data_home, exist_ok=True)
load_dotenv(os.path.join(_data_home, ".env"))

# ── Version + CLI flags ───────────────────────────────────────────────────────
_VERSION_FILE = os.path.join(_root, "version.txt")
VERSION = open(_VERSION_FILE).read().strip() if os.path.exists(_VERSION_FILE) else "0.1.0"

if "--version" in sys.argv:
    print(VERSION)
    sys.exit(0)

if "--audit" in sys.argv:
    # Quick offline audit, no setup needed
    from core.audit import run_offline_audit, format_audit_report
    results = run_offline_audit()
    print(format_audit_report(results, "Quick Audit"))
    sys.exit(0)

def run_chat_mode(provider: str, api_key: str, technician: str,
                  chat_history: list, pacman_thinking_fn=None):
    """Chill chat loop — no IT intensity, full tools still available. /back to return."""
    system_prompt = build_chat_system_prompt(technician)
    print("\n[Uptek] Chat mode — just vibing. /back to return to session.\n")

    while True:
        try:
            user_input = input("you > ").strip()
        except (EOFError, KeyboardInterrupt):
            user_input = "/back"

        if not user_input:
            continue

        if user_input in ("/back", "/exit"):
            print("[Uptek] Back to main session.\n")
            return

        if user_input == "/clear":
            chat_history.clear()
            print("[Uptek] Chat history cleared.")
            continue

        if user_input == "/history":
            if not chat_history:
                print("No chat history yet.")
            else:
                for h in chat_history:
                    prefix = "you" if h["role"] == "user" else "uptek"
                    print(f"\n{prefix} > {h['content'][:300]}")
            continue

        stop = pacman_thinking_fn() if pacman_thinking_fn else None
        response = run_agent(
            user_input, {}, chat_history,
            provider=provider,
            system_prompt=system_prompt,
        )
        if stop:
            stop()
        print(f"\nuptek > {response}")

        chat_history.append({"role": "user", "content": user_input})
        chat_history.append({"role": "assistant", "content": response})
        if len(chat_history) > 40:
            chat_history = chat_history[-40:]


def run_pentest_mode(pacman_thinking_fn=None):
    """Full pentest session — callable from CLI flag or /pentest command."""
    from core.pentest import (
        authorization_gate, check_tools, install_missing_tools,
        scan_ports, scan_web, scan_directories, scan_system_hardening,
        scan_sql_injection, capture_traffic, generate_pentest_report,
        log_action, make_pentest_executor, PENTEST_TOOL_DEFINITIONS,
    )
    from core.agent import run_agent, provider_name, PROVIDERS, build_pentest_system_prompt

    # Offer sudo escalation if not root
    if os.name != "nt" and os.getuid() != 0:
        print("\n[Uptek] Some pentest tools (nmap UDP, tshark, raw sockets) require root.")
        try:
            ans = input("Re-launch with sudo? (yes/no) > ").strip().lower()
            if ans in ("yes", "y"):
                os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except (EOFError, KeyboardInterrupt):
            pass
        print()

    engagement = authorization_gate()
    if not engagement:
        return

    # Tool check
    tools = check_tools()
    missing = [t for t, path in tools.items() if not path]
    if missing:
        missing = install_missing_tools(missing)
        if missing:
            print(f"[Uptek] Warning: some tools unavailable: {', '.join(missing)}")

    findings  = []
    scope     = engagement["scope"]
    pt_history = []

    _pt_provider      = os.getenv("AI_PROVIDER", "1")
    _pt_cfg           = PROVIDERS.get(_pt_provider, PROVIDERS["1"])
    _pt_api_key       = os.getenv(_pt_cfg["env_key"], "") if _pt_cfg["env_key"] else "ollama"
    _pt_executor      = make_pentest_executor(engagement)
    _pt_system_prompt = build_pentest_system_prompt(engagement)

    _pt_client = {
        "client_name": engagement["client"],
        "technician":  engagement["technician"],
        "notes":       f"PENTEST ENGAGEMENT. Scope: {scope}. Auth by: {engagement['authorized_by']}. {engagement.get('notes','')}",
        "network":     {"subnet": scope, "gateway": ""},
        "systems":     [],
        "open_items":  [],
    }

    print("Pentest commands:")
    print("  /portscan [target] [quick|full|udp]  — nmap scan")
    print("  /webscan [target]                    — nikto web scan")
    print("  /dirscan [target]                    — directory brute-force")
    print("  /hardening                           — lynis local audit")
    print("  /capture [interface] [seconds]       — traffic capture")
    print("  /addfinding                          — record a finding")
    print("  /report                              — generate engagement report")
    print("  /exit                                — end engagement and return")
    if _pt_api_key:
        print(f"\nAI chat active ({provider_name(_pt_provider)}) — just type to ask questions.\n")
    else:
        print("\n[No API key — AI chat disabled. Slash commands only.]\n")

    while True:
        try:
            cmd = input("pentest > ").strip()
        except (EOFError, KeyboardInterrupt):
            cmd = "/exit"

        if not cmd:
            continue

        if cmd == "/exit":
            path = generate_pentest_report(engagement, findings)
            print(f"\n[Uptek] Engagement report saved: {path}")
            return

        elif cmd == "/report":
            path = generate_pentest_report(engagement, findings)
            print(f"[Uptek] Report saved: {path}")
            with open(path) as f:
                print(f.read())

        elif cmd == "/hardening":
            print("[Uptek] Running lynis hardening audit...")
            out = scan_system_hardening(engagement)
            print(out)

        elif cmd.startswith("/portscan"):
            parts  = cmd.split()
            target = parts[1] if len(parts) > 1 else scope
            mode   = parts[2] if len(parts) > 2 else "quick"
            print(f"[Uptek] Scanning {target} ({mode})...")
            out = scan_ports(target, engagement, mode)
            print(out)

        elif cmd.startswith("/webscan"):
            parts  = cmd.split()
            target = parts[1] if len(parts) > 1 else scope
            print(f"[Uptek] Web scan: {target}...")
            out = scan_web(target, engagement)
            print(out)

        elif cmd.startswith("/dirscan"):
            parts  = cmd.split()
            target = parts[1] if len(parts) > 1 else scope
            print(f"[Uptek] Directory scan: {target}...")
            out = scan_directories(target, engagement)
            print(out)

        elif cmd.startswith("/capture"):
            parts  = cmd.split()
            iface  = parts[1] if len(parts) > 1 else "eth0"
            dur    = int(parts[2]) if len(parts) > 2 else 30
            print(f"[Uptek] Capturing on {iface} for {dur}s...")
            out = capture_traffic(iface, dur, engagement)
            print(out)

        elif cmd.startswith("/addfinding"):
            sev    = input("Severity (critical/high/medium/low): ").strip()
            title  = input("Title: ").strip()
            detail = input("Detail: ").strip()
            findings.append({"severity": sev, "title": title, "detail": detail})
            log_action(engagement, f"Finding added: [{sev}] {title}")
            print("[Uptek] Finding recorded.")

        else:
            if not _pt_api_key:
                print("Unknown command. (No API key — AI chat disabled.)")
                continue
            log_action(engagement, f"AI query: {cmd[:80]}")
            spinner = pacman_thinking_fn() if pacman_thinking_fn else None
            response = run_agent(
                cmd, _pt_client, pt_history,
                provider=_pt_provider,
                extra_tools=PENTEST_TOOL_DEFINITIONS,
                extra_executor=_pt_executor,
                system_prompt=_pt_system_prompt,
            )
            if spinner:
                spinner()
            print(f"\nuptek > {response}")
            pt_history.append({"role": "user", "content": cmd})
            pt_history.append({"role": "assistant", "content": response})
            if len(pt_history) > 20:
                pt_history = pt_history[-20:]


if "--pentest" in sys.argv:
    run_pentest_mode()
    sys.exit(0)

from core.config import OS, get_profiles_dir, get_reports_dir
from core.profile import (
    new_profile, list_profiles, load_profile, save_profile,
    record_finding, record_fix, record_open_item,
    update_network, start_visit, close_visit, sync_to_homebase,
    _derive_key,
)
from core.audit import run_offline_audit, format_audit_report
from core.agent import run_agent, provider_menu, provider_name, build_chat_system_prompt, PROVIDERS
from core.report import generate_report, print_report, generate_html_report
from core.network import network_sweep
from core.diff import diff_audits, format_diff
from core.tasks import list_tasks, run_task, save_task, ensure_builtin_tasks, BUILTIN_TASKS
from core.code import run_code_mode
from core.wifi import run_wifi_scan_mode


BANNER = """
╔══════════════════════════════════════════╗
║   UPTEK FIELD AGENT  |  906 Tech Express ║
║   AI-powered IT ops for the road         ║
╚══════════════════════════════════════════╝
"""

HELP = """
Commands:
  /chat               — chill mode, just talk (tools still available, /back to return)
  /code               — project mode: persistent memory + AI coding co-pilot
  /wifiscan           — hidden network scanner + signal triangulation
  /pentest            — launch pentest mode (authorization gate + full toolkit)
  /audit              — 23-check offline security audit (no internet needed)
  /diff               — show what changed since last visit
  /sweep [subnet]     — discover all hosts on the network
  /report             — generate plain-text session report
  /report html        — generate client-presentable HTML report
  /tasks              — list saved task templates
  /run <name>         — run a saved task
  /savetask           — save a new task template
  /profile            — show current client profile summary
  /additem            — add an open item to the profile
  /sync               — sync profile to home base
  /history            — show conversation history
  /clear              — clear conversation history
  /exit               — end session (saves profile + report)
  /help               — this message

Or just talk — the AI has full tool access:
  "sweep the network and tell me what's running"
  "check if that box has default creds"
  "scan the WordPress site for vulns"
  "what changed since last time?"
  "enumerate the SMB shares on 192.168.1.50"
"""


# ── Setup wizard ──────────────────────────────────────────────────────────────

def _ask(prompt: str, default: str = "") -> str:
    val = input(prompt).strip()
    return val if val else default


def setup_wizard() -> tuple[dict, bytes | None, str]:
    """First-run: collect credentials and save .env"""
    print("\n[Uptek] First-time setup\n")

    # Provider selection
    provider = provider_menu()
    cfg      = PROVIDERS[provider]
    api_key  = ""
    if cfg["env_key"]:
        api_key = _ask(f"{cfg['name']} API key: ")

    pin       = _ask("Set a PIN for profile encryption: ", "0000")
    tech_name = _ask("Your name (technician): ", "Jesse")
    homebase  = _ask("Home base URL (leave blank to skip sync): ", "")
    hb_token  = _ask("Home base API token (leave blank to skip): ", "") if homebase else ""

    env_path = os.path.join(_data_home, ".env")
    with open(env_path, "w") as f:
        if cfg["env_key"] and api_key:
            f.write(f"{cfg['env_key']}={api_key}\n")
        f.write(f"AI_PROVIDER={provider}\n")
        f.write(f"UPTEK_PIN={pin}\n")
        f.write(f"TECHNICIAN={tech_name}\n")
        if homebase:
            f.write(f"HOMEBASE_URL={homebase}\n")
        if hb_token:
            f.write(f"HOMEBASE_TOKEN={hb_token}\n")

    print(f"\n[Uptek] Setup complete. Using {cfg['name']}. Saved to .env\n")
    enc_key = _derive_key(api_key or pin, pin) if pin else None
    return {"technician": tech_name}, enc_key, provider


def get_enc_key() -> bytes | None:
    grok_key = os.getenv("GROK_API_KEY", "")
    pin      = os.getenv("UPTEK_PIN", "")
    if grok_key and pin:
        return _derive_key(grok_key, pin)
    return None


# ── Client selection ──────────────────────────────────────────────────────────

def select_or_create_client(enc_key) -> dict:
    tech = os.getenv("TECHNICIAN", "Jesse")
    existing = list_profiles()

    if existing:
        print("\nKnown clients:")
        for i, name in enumerate(existing, 1):
            print(f"  {i}. {name}")
        print("  N. New client")
        choice = _ask("\nSelect client or N for new: ").strip()

        if choice.upper() != "N":
            try:
                idx = int(choice) - 1
                client_name = existing[idx]
                profile = load_profile(client_name, enc_key)
                if profile:
                    _print_profile_summary(profile)
                    start_visit(profile)
                    return profile
                else:
                    print(f"[Uptek] Could not load profile for '{client_name}'. Starting new client.")
            except (ValueError, IndexError):
                print("[Uptek] Invalid selection.")
            # Re-prompt instead of falling through to new client
            return select_or_create_client(enc_key)

    # New client
    print()
    client_name = _ask("Client name: ")
    notes       = _ask("Quick notes (what do they run, any context): ")
    profile = new_profile(client_name, tech, notes)
    start_visit(profile)
    save_profile(profile, enc_key)
    print(f"\n[Uptek] New profile created for {client_name}")
    return profile


def _print_profile_summary(profile: dict):
    name       = profile.get("client_name", "?")
    last_visit = profile.get("last_visit", "Never")[:10] if profile.get("last_visit") else "Never"
    visits     = len(profile.get("visits", []))
    open_items = [i for i in profile.get("open_items", []) if i.get("status") == "open"]
    systems    = profile.get("systems", [])
    findings   = [f for f in profile.get("findings", []) if f.get("status") == "open"]

    print(f"""
┌─ {name} {'─' * max(0, 40 - len(name))}
│  Last visit:  {last_visit}  |  Total visits: {visits}
│  Systems:     {len(systems)}  |  Open findings: {len(findings)}  |  Open items: {len(open_items)}""")

    if open_items:
        print("│")
        print("│  Open items:")
        for item in open_items[:3]:
            due = f" [due: {item['due']}]" if item.get("due") else ""
            print(f"│    • {item['title']}{due}")
        if len(open_items) > 3:
            print(f"│    ... and {len(open_items) - 3} more")

    if findings:
        print("│")
        print("│  Open findings:")
        for f in findings[:3]:
            icon = "🔴" if f["severity"] == "critical" else "⚠️ "
            print(f"│    {icon} {f['title']}")

    print("└" + "─" * 45)


# ── Main session loop ─────────────────────────────────────────────────────────

def _offer_sudo():
    """If not root on Linux, offer to re-launch with sudo for full audit results."""
    if os.name == "nt" or os.getuid() == 0:
        return  # Windows or already root — nothing to do
    print("\n[Uptek] Running without root — firewall, SUID, and user checks will be limited.")
    try:
        ans = input("Re-launch with sudo for full results? (yes/no) > ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return
    if ans in ("yes", "y"):
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        # execvp replaces this process — never returns on success


def main():
    from core.boot import pacman_boot, pacman_thinking, check_for_update
    pacman_boot()
    print(BANNER)
    check_for_update(VERSION)
    _offer_sudo()

    # First run check
    env_path = os.path.join(_data_home, ".env")
    if not os.path.exists(env_path):
        _, enc_key, _provider = setup_wizard()
        load_dotenv(env_path)
    else:
        enc_key = get_enc_key()
        _provider = None

    ensure_builtin_tasks()

    provider  = _provider or os.getenv("AI_PROVIDER", "1")
    cfg       = PROVIDERS.get(provider, PROVIDERS["1"])
    api_key   = os.getenv(cfg["env_key"], "") if cfg["env_key"] else "ollama"
    homebase  = os.getenv("HOMEBASE_URL", "")
    hb_token  = os.getenv("HOMEBASE_TOKEN", "")

    if not api_key:
        print(f"[Uptek] No API key for {cfg['name']} — running in offline mode (audit only).\n")
    else:
        print(f"[Uptek] AI: {cfg['name']}\n")

    profile     = select_or_create_client(enc_key)
    history     = []
    chat_history = []
    session_log = []
    audit_results = []
    audit_summary = ""

    print(f"\nOS detected: {OS}")
    print("Type /help for commands or just start talking.\n")

    while True:
        try:
            user_input = input("you > ").strip()
        except (EOFError, KeyboardInterrupt):
            user_input = "/exit"

        if not user_input:
            continue

        # ── Built-in commands ──────────────────────────────────────────────

        if user_input == "/exit":
            print("\n[Uptek] Closing session...")
            close_visit(profile)
            save_profile(profile, enc_key)

            if homebase and hb_token:
                print("[Uptek] Syncing profile to home base...")
                ok = sync_to_homebase(profile, enc_key, homebase, hb_token)
                print("[Uptek] Sync " + ("✅ OK" if ok else "⚠️ failed (saved to drive)"))

            path = generate_report(profile, session_log, audit_results)
            print(f"\n[Uptek] Session report saved: {path}")
            print_report(path)
            break

        elif user_input == "/chat":
            tech = profile.get("technician", os.getenv("TECHNICIAN", "Jesse"))
            run_chat_mode(provider, api_key, tech, chat_history,
                          pacman_thinking_fn=pacman_thinking)

        elif user_input == "/code":
            run_code_mode(provider, api_key,
                          pacman_thinking_fn=pacman_thinking)

        elif user_input == "/wifiscan":
            run_wifi_scan_mode()

        elif user_input == "/pentest":
            run_pentest_mode(pacman_thinking_fn=pacman_thinking)

        elif user_input == "/help":
            print(HELP)

        elif user_input == "/audit":
            # Save previous audit before overwriting
            prev_audit = profile.get("last_audit_snapshot", [])
            prev_date  = profile.get("last_audit_date", "")

            audit_results = run_offline_audit()
            report_text   = format_audit_report(audit_results, profile["client_name"])
            print("\n" + report_text)

            # Visit diff if we have a baseline
            if prev_audit:
                diff = diff_audits(audit_results, prev_audit)
                print(format_diff(diff, profile["client_name"], prev_date))

            # Feed summary into AI context
            audit_summary = "\n".join(
                f"{r.get('label')}: {r.get('severity','ok').upper()}"
                + (f" — {r.get('findings')}" if r.get("findings") else "")
                for r in audit_results
            )
            # Save snapshot for next visit diff
            profile["last_audit_snapshot"] = audit_results
            profile["last_audit_date"]     = datetime.datetime.now().strftime("%Y-%m-%d")
            # Auto-record critical/warning findings into profile
            for r in audit_results:
                if r.get("severity") in ("critical", "warning"):
                    record_finding(profile, r["severity"], r["label"],
                                   str(r.get("findings") or r.get("raw", "")[:200]))
            save_profile(profile, enc_key)

        elif user_input == "/diff":
            prev_audit = profile.get("last_audit_snapshot", [])
            prev_date  = profile.get("last_audit_date", "")
            if not audit_results:
                print("[Uptek] Run /audit first to generate a current snapshot.")
            else:
                diff = diff_audits(audit_results, prev_audit)
                print(format_diff(diff, profile["client_name"], prev_date))

        elif user_input.startswith("/sweep"):
            parts  = user_input.split()
            subnet = parts[1] if len(parts) > 1 else profile.get("network", {}).get("subnet", "")
            if not subnet:
                subnet = input("Subnet to sweep (e.g. 192.168.1.0/24): ").strip()
            if subnet:
                print(f"[Uptek] Sweeping {subnet}...")
                stop = pacman_thinking()
                result = network_sweep(subnet)
                stop()
                print(f"\nFound {result['count']} hosts:\n{result['summary']}")
                if result["hosts"]:
                    update_network(profile, subnet=subnet)
                    for h in result["hosts"]:
                        if h.get("ip"):
                            existing = [s["ip"] for s in profile.get("systems", [])]
                            if h["ip"] not in existing:
                                profile.setdefault("systems", []).append({
                                    "ip":       h["ip"],
                                    "hostname": h.get("hostname", ""),
                                    "os":       h.get("vendor", ""),
                                    "role":     "",
                                })
                    save_profile(profile, enc_key)
                    print(f"[Uptek] {result['count']} hosts saved to client profile.")

        elif user_input == "/report":
            path = generate_report(profile, session_log, audit_results)
            print_report(path)

        elif user_input == "/report html":
            prev_audit = profile.get("last_audit_snapshot", [])
            diff = diff_audits(audit_results, prev_audit) if audit_results and prev_audit else None
            path = generate_html_report(profile, session_log, audit_results, diff)
            print(f"[Uptek] HTML report saved: {path}")
            print("  Open in a browser to view — client-presentable format.")

        elif user_input == "/profile":
            _print_profile_summary(profile)

        elif user_input == "/tasks":
            tasks = list_tasks()
            if tasks:
                print("\nSaved tasks:")
                for t in tasks:
                    print(f"  /run {t}")
            else:
                print("\nNo saved tasks yet. Use /savetask to create one.")

        elif user_input.startswith("/run "):
            name = user_input[5:].strip()
            results = run_task(name)
            if results:
                session_log.append({"type": "task", "name": name, "results": results})
                save_profile(profile, enc_key)

        elif user_input == "/savetask":
            name  = _ask("Task name (no spaces, e.g. restart-nginx): ")
            desc  = _ask("Description: ")
            steps = []
            print("Add steps (blank label to finish):")
            while True:
                label = _ask(f"  Step {len(steps)+1} label: ")
                if not label:
                    break
                cmd = _ask(f"  Step {len(steps)+1} command: ")
                steps.append({"label": label, "command": cmd})
            if steps:
                save_task(name, desc, steps)

        elif user_input == "/additem":
            title  = _ask("Item title: ")
            detail = _ask("Detail: ")
            due    = _ask("Due date (optional): ")
            record_open_item(profile, title, detail, due)
            session_log.append({"type": "open_item", "title": title,
                                 "detail": detail, "due": due})
            save_profile(profile, enc_key)
            print(f"[Uptek] Open item added: {title}")

        elif user_input == "/sync":
            if homebase and hb_token:
                ok = sync_to_homebase(profile, enc_key, homebase, hb_token)
                print("Sync " + ("✅ OK" if ok else "⚠️ failed"))
            else:
                print("[Uptek] No HOMEBASE_URL/TOKEN configured in .env")

        elif user_input == "/history":
            if not history:
                print("No conversation history yet.")
            else:
                for h in history:
                    prefix = "you" if h["role"] == "user" else "uptek"
                    print(f"\n{prefix} > {h['content'][:300]}")

        elif user_input == "/clear":
            history = []
            print("[Uptek] Conversation cleared.")

        else:
            # ── AI response ────────────────────────────────────────────────
            if not api_key:
                print("[Uptek] No API key. Use /audit for offline mode.")
                continue

            stop = pacman_thinking()
            response = run_agent(user_input, profile, history,
                                 audit_summary, provider)
            stop()
            print(f"\nuptek > {response}")

            history.append({"role": "user", "content": user_input})
            history.append({"role": "assistant", "content": response})
            if len(history) > 20:
                history = history[-20:]

            # Auto-save profile after each AI turn (Grok may have discovered things)
            save_profile(profile, enc_key)


if __name__ == "__main__":
    main()
