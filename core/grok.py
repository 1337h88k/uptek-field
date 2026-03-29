# core/grok.py — Grok agent with tool calling loop
import json
import os
import requests
from core.tools import bash_exec, read_file, write_file, write_memory, check_ip_reputation, TOOL_DEFINITIONS
from core.memory import memory_block

GROK_URL = "https://api.x.ai/v1/chat/completions"
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")


def _build_system_prompt(client: dict, audit_summary: str = "") -> str:
    name    = client.get("client_name", "this client")
    owner   = client.get("technician", "the technician")
    notes   = client.get("notes", "")
    network = client.get("network", {})
    systems = client.get("systems", [])
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

    return f"""You are Uptek — a portable AI IT field agent.
You are running on-site at {name}'s location.
You report to {owner}.

Your job:
1. Help the technician understand and work on this system.
2. Audit for security issues — open ports, bad permissions, brute force attempts, exposed services.
3. Automate repetitive tasks when asked — write and run scripts with confirmation.
4. Be direct and plain. No jargon dumps. State what you found, how bad it is, what to do.
5. Before running any write or destructive command, state what you're about to do and why.
6. Update your understanding as you discover things — note hostnames, IPs, services.

Client notes: {notes}
Network: subnet={network.get('subnet','unknown')}, gateway={network.get('gateway','unknown')}
{sys_block}
{items_block}
{audit_block}
{mem_block}

Use your tools to investigate before answering. Don't guess.

IMPORTANT: {owner} is the developer and owner of this tool. It runs from editable Python source.
If asked to change, add, or remove a feature — use read_file to inspect source files,
write_file to modify them, and tell the technician to restart Uptek for changes to take effect.
Never claim you are closed-source or that features can't be changed.
Use write_memory to save anything worth remembering for the next visit."""


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
    return f"[ERROR] Unknown tool: {name}"


def run_agent(user_input: str, client: dict, history: list,
              audit_summary: str = "", grok_key: str = "") -> str:
    key = grok_key or os.getenv("GROK_API_KEY", "")
    if not key:
        return "[Uptek] No GROK_API_KEY set. AI responses unavailable — use /audit for offline mode."

    system_prompt = _build_system_prompt(client, audit_summary)
    messages = [{"role": "system", "content": system_prompt}]
    messages += history[-16:]  # keep last 8 exchanges
    messages.append({"role": "user", "content": user_input})

    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    for _ in range(8):  # max tool call iterations
        payload = {
            "model": "grok-3-mini",
            "messages": messages,
            "tools": TOOL_DEFINITIONS,
            "tool_choice": "auto",
            "max_tokens": 1500,
        }
        try:
            r = requests.post(GROK_URL, json=payload, headers=headers, timeout=30)
            r.raise_for_status()
        except requests.exceptions.RequestException as e:
            return f"[Uptek] Grok API error: {e}\nTip: use /audit for offline mode."

        data    = r.json()
        choice  = data["choices"][0]
        message = choice["message"]

        if choice["finish_reason"] == "tool_calls":
            messages.append(message)
            for call in message.get("tool_calls", []):
                fn_name = call["function"]["name"]
                fn_args = json.loads(call["function"]["arguments"])
                result  = _execute_tool(fn_name, fn_args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "content": result,
                })
            continue

        return message.get("content", "[No response]")

    return "[Uptek] Reached max tool call iterations."
