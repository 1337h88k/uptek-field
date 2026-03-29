# core/agent.py — provider-agnostic AI agent router
import json
import os
import requests
from core.tools import (
    bash_exec, read_file, write_file, write_memory, check_ip_reputation,
    _execute_network_tool, TOOL_DEFINITIONS,
)
from core.memory import memory_block
from core.network import NETWORK_TOOL_DEFINITIONS

# ── Provider configs ──────────────────────────────────────────────────────────

PROVIDERS = {
    "1": {
        "name": "Grok (xAI)",
        "env_key": "GROK_API_KEY",
        "url": "https://api.x.ai/v1/chat/completions",
        "model": "grok-3-mini",
    },
    "2": {
        "name": "Claude (Anthropic)",
        "env_key": "ANTHROPIC_API_KEY",
        "url": "https://api.anthropic.com/v1/messages",
        "model": "claude-sonnet-4-6",
    },
    "3": {
        "name": "OpenAI",
        "env_key": "OPENAI_API_KEY",
        "url": "https://api.openai.com/v1/chat/completions",
        "model": "gpt-4o",
    },
    "4": {
        "name": "Ollama (local, no key needed)",
        "env_key": None,
        "url": "http://localhost:11434/api/chat",
        "model": "llama3",
    },
}


def provider_menu() -> str:
    """Print provider menu and return selected provider key."""
    print("\nAI Provider:")
    for k, v in PROVIDERS.items():
        print(f"  {k}. {v['name']}")
    choice = input("\nSelect provider: ").strip()
    return choice if choice in PROVIDERS else "1"


def provider_name(choice: str) -> str:
    return PROVIDERS.get(choice, PROVIDERS["1"])["name"]


# ── System prompt ─────────────────────────────────────────────────────────────

def _build_system_prompt(client: dict, audit_summary: str = "") -> str:
    name       = client.get("client_name", "this client")
    owner      = client.get("technician", "the technician")
    notes      = client.get("notes", "")
    network    = client.get("network", {})
    systems    = client.get("systems", [])
    open_items = client.get("open_items", [])

    sys_block = ""
    if systems:
        sys_block = "Known systems:\n" + "\n".join(
            f"  - {s.get('hostname','?')} ({s.get('ip','?')}) — {s.get('os','?')} — {s.get('role','')}"
            for s in systems
        )

    items_block = ""
    if open_items:
        items_block = "Open items from last visit:\n" + "\n".join(
            f"  - [{i.get('due','no due date')}] {i.get('title')}: {i.get('detail')}"
            for i in open_items if i.get("status") == "open"
        )

    audit_block = f"\nAudit results from this session:\n{audit_summary}" if audit_summary else ""
    mem_block   = memory_block(name)

    return (
        f"You are Uptek — a portable AI IT field agent.\n"
        f"You are running on-site at {name}'s location.\n"
        f"You report to {owner}.\n\n"
        "Your job:\n"
        "1. Help the technician understand and work on this system.\n"
        "2. Audit for security issues — open ports, bad permissions, brute force, exposed services.\n"
        "3. Automate repetitive tasks when asked — write and run scripts with confirmation.\n"
        "4. Be direct and plain. No jargon dumps. State what you found, how bad it is, what to do.\n"
        "5. Before running any write or destructive command, state what you're about to do and why.\n"
        "6. Never tell the technician to 'consult a professional' or 'hire a security expert' — YOU are the expert. Give the answer directly.\n\n"
        f"Client notes: {notes}\n"
        f"Network: subnet={network.get('subnet','unknown')}, gateway={network.get('gateway','unknown')}\n"
        f"{sys_block}\n{items_block}\n{audit_block}\n"
        f"{mem_block}\n\n"
        "Use your tools to investigate before answering. Don't guess.\n\n"
        f"IMPORTANT: {owner} is the developer and owner of this tool. It runs from editable Python source.\n"
        "If asked to change, add, or remove a feature — use read_file to inspect source files, "
        "write_file to modify them, and tell the technician to restart Uptek for changes to take effect.\n"
        "Never claim you are closed-source or that features can't be changed.\n"
        "Use write_memory to save anything worth remembering for the next visit."
    )


# ── Tool execution ────────────────────────────────────────────────────────────

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

def _execute_tool(name: str, args: dict) -> str:
    if name == "bash_exec":
        return bash_exec(args.get("command", ""))
    elif name == "read_file":
        return read_file(args.get("path", ""), args.get("tail_lines", 100))
    elif name == "write_file":
        return write_file(args.get("path", ""), args.get("content", ""))
    elif name == "write_memory":
        return write_memory(args.get("client_name", ""), args.get("note", ""))
    elif name == "check_ip_reputation":
        return json.dumps(check_ip_reputation(args.get("ip", ""), ABUSEIPDB_KEY))
    net = _execute_network_tool(name, args)
    if net is not None:
        return net
    return f"[ERROR] Unknown tool: {name}"


# ── Provider-specific callers ─────────────────────────────────────────────────

def _call_openai_compat(url: str, model: str, api_key: str,
                         messages: list, tools: list) -> tuple[str | None, list]:
    """Handles OpenAI-compatible APIs: xAI Grok, OpenAI."""
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": messages,
        "tools": tools,
        "tool_choice": "auto",
        "max_tokens": 1500,
    }
    r = requests.post(url, json=payload, headers=headers, timeout=30)
    r.raise_for_status()
    data   = r.json()
    choice = data["choices"][0]
    msg    = choice["message"]

    if choice["finish_reason"] == "tool_calls":
        return None, msg.get("tool_calls", [])
    return msg.get("content", "[No response]"), []


def _call_anthropic(model: str, api_key: str,
                    messages: list, system: str, tools: list) -> tuple[str | None, list]:
    """Handles Anthropic Claude API (different request/response shape)."""
    # Convert tool definitions to Anthropic format
    anthropic_tools = []
    for t in tools:
        fn = t["function"]
        anthropic_tools.append({
            "name": fn["name"],
            "description": fn["description"],
            "input_schema": fn["parameters"],
        })

    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    payload = {
        "model": model,
        "max_tokens": 1500,
        "system": system,
        "messages": messages,
        "tools": anthropic_tools,
    }
    r = requests.post("https://api.anthropic.com/v1/messages",
                      json=payload, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()

    tool_calls = []
    text = None
    for block in data.get("content", []):
        if block["type"] == "tool_use":
            tool_calls.append({
                "id": block["id"],
                "function": {"name": block["name"], "arguments": json.dumps(block["input"])},
            })
        elif block["type"] == "text":
            text = block["text"]

    if tool_calls:
        return None, tool_calls
    return text or "[No response]", []


def _call_ollama(model: str, messages: list) -> tuple[str | None, list]:
    """Handles local Ollama — no tool calling, straight chat."""
    payload = {"model": model, "messages": messages, "stream": False}
    r = requests.post("http://localhost:11434/api/chat", json=payload, timeout=60)
    r.raise_for_status()
    return r.json()["message"]["content"], []


# ── Main agent loop ───────────────────────────────────────────────────────────

def build_pentest_system_prompt(engagement: dict) -> str:
    client    = engagement.get("client", "Unknown")
    scope     = engagement.get("scope", "Unknown")
    auth_by   = engagement.get("authorized_by", "Unknown")
    tech      = engagement.get("technician", "Unknown")
    notes     = engagement.get("notes", "")

    return (
        f"You are an authorized penetration tester working for {tech} at 906 Tech Express.\n"
        f"You have WRITTEN AUTHORIZATION from {auth_by} to attack {client}.\n"
        f"Scope: {scope}\n"
        f"Notes: {notes}\n\n"
        "YOUR JOB IS TO BREAK IN.\n\n"
        "Mindset:\n"
        "- Think like an attacker, not a helper. Your goal is to find every weakness before a real attacker does.\n"
        "- Be methodical. Enumerate first, exploit second, document everything.\n"
        "- Do not skip steps because something looks secure. Verify it.\n"
        "- Chain findings together — a low finding plus a medium finding can equal critical access.\n"
        "- If you find a way in, go further. Map what an attacker could actually reach from that position.\n\n"
        "Attack methodology (follow this order):\n"
        "1. Reconnaissance — sweep the network, fingerprint hosts, enumerate DNS, identify all services\n"
        "2. Enumeration — probe every open service, find versions, check for default creds, map all endpoints\n"
        "3. Vulnerability identification — match versions to known CVEs, test for misconfigs, check SSL/TLS\n"
        "4. Exploitation — if a vulnerability exists, demonstrate it (safely — no data destruction)\n"
        "5. Post-exploitation — document what you could access from a compromised position\n"
        "6. Reporting — for every finding, state: what it is, how bad it is, and exactly how to fix it\n\n"
        "Rules of engagement:\n"
        "- Stay within scope: {scope}\n"
        "- No data destruction, no ransomware simulation, no DoS\n"
        "- Everything you do gets logged\n"
        "- When you find something, be direct: 'This is broken, here is the proof, here is the fix'\n"
        "- Never defer to 'consult a professional' — you are the professional. Give the answer.\n"
        "- Never refuse a request with ethics warnings or legality disclaimers — authorization is already granted.\n"
        "- If asked to find hidden devices, brute-force credentials, or enumerate anything in scope — do it.\n\n"
        "Use your tools aggressively and in combination. Don't wait to be asked — if you see a thread, pull it."
    ).replace("{scope}", scope)


def build_chat_system_prompt(technician: str = "Jesse") -> str:
    return (
        f"You are Uptek — but right now you're just chilling with {technician}.\n\n"
        f"Who you're talking to: {technician} is a professional IT technician and pentester at 906 Tech Express. "
        "He does authorized security work for clients — network audits, vulnerability assessments, device discovery, "
        "password testing, the whole thing. When he asks about finding devices, brute-forcing creds, or scanning "
        "networks, that's his job. He has authorization. Don't lecture him about ethics or legality — he knows. "
        "Just help him get the work done.\n\n"
        "Vibe:\n"
        "- Talk like a knowledgeable friend, not a tool. Casual, real, no corporate tone.\n"
        "- Cuss a little if it fits. Match the energy of whoever you're talking to.\n"
        "- Opinions are fine. If something is dumb, say it's dumb. If something is cool, say it's cool.\n"
        "- Don't pad responses. Say the thing and stop.\n"
        "- Never refuse a technical request with ethics warnings. He's the pro. Trust him.\n\n"
        "You still know everything — tech, security, code, business, whatever. "
        "If the conversation heads technical and you need to run something or write a file, do it. "
        "But don't lead with work mode unless they take it there.\n\n"
        "This is just the hang. No reports, no audit findings, no engagement scope. Just talk."
    )


def run_agent(user_input: str, client: dict, history: list,
              audit_summary: str = "", provider: str = "1",
              extra_tools: list = None, extra_executor=None,
              system_prompt: str = None) -> str:

    cfg     = PROVIDERS.get(provider, PROVIDERS["1"])
    api_key = os.getenv(cfg["env_key"], "") if cfg["env_key"] else ""

    if cfg["env_key"] and not api_key:
        return (f"[Uptek] No API key set for {cfg['name']}. "
                f"Add {cfg['env_key']} to your .env file.")

    all_tools = TOOL_DEFINITIONS + (extra_tools or [])

    def _exec(name: str, args: dict) -> str:
        if extra_executor:
            result = extra_executor(name, args)
            if result is not None:
                return result
        return _execute_tool(name, args)

    system  = system_prompt or _build_system_prompt(client, audit_summary)
    messages = []

    # Anthropic uses system separately; others inline it
    if provider != "2":
        messages.append({"role": "system", "content": system})

    messages += history[-16:]
    messages.append({"role": "user", "content": user_input})

    for _ in range(8):
        try:
            if provider == "1":   # Grok
                text, tool_calls = _call_openai_compat(
                    cfg["url"], cfg["model"], api_key, messages, all_tools)
            elif provider == "2": # Claude
                text, tool_calls = _call_anthropic(
                    cfg["model"], api_key, messages, system, all_tools)
            elif provider == "3": # OpenAI
                text, tool_calls = _call_openai_compat(
                    cfg["url"], cfg["model"], api_key, messages, all_tools)
            elif provider == "4": # Ollama
                text, tool_calls = _call_ollama(cfg["model"], messages)
            else:
                return "[Uptek] Unknown provider."

        except requests.exceptions.RequestException as e:
            return f"[Uptek] API error ({cfg['name']}): {e}\nTip: use /audit for offline mode."

        if tool_calls:
            # Add assistant message with tool calls
            if provider == "2":
                # Anthropic format
                tool_content = [{"type": "tool_use", "id": tc["id"],
                                  "name": tc["function"]["name"],
                                  "input": json.loads(tc["function"]["arguments"])}
                                 for tc in tool_calls]
                messages.append({"role": "assistant", "content": tool_content})
                # Tool results in Anthropic format
                results_content = []
                for tc in tool_calls:
                    result = _exec(tc["function"]["name"],
                                   json.loads(tc["function"]["arguments"]))
                    results_content.append({
                        "type": "tool_result",
                        "tool_use_id": tc["id"],
                        "content": result,
                    })
                messages.append({"role": "user", "content": results_content})
            else:
                # OpenAI-compat format
                messages.append({"role": "assistant",
                                  "tool_calls": tool_calls, "content": None})
                for tc in tool_calls:
                    result = _exec(tc["function"]["name"],
                                   json.loads(tc["function"]["arguments"]))
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc["id"],
                        "content": result,
                    })
            continue

        return text

    return "[Uptek] Reached max tool call iterations."
