# core/memory.py — per-client rolling memory (14-day window)
import json
import os
import re
import datetime
from core.config import get_memory_dir

RETENTION_DAYS = 14


def _slug(client_name: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "", client_name.lower().replace(" ", "_")).strip("_-") or "unnamed"


def _client_path(client_name: str) -> str:
    d = get_memory_dir()
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"{_slug(client_name)}.json")


def load_memory(client_name: str) -> list:
    """Return memory entries for client, trimmed to last 14 days."""
    path = _client_path(client_name)
    if not os.path.exists(path):
        return []
    try:
        with open(path) as f:
            entries = json.load(f)
    except Exception:
        return []
    cutoff = (datetime.date.today() - datetime.timedelta(days=RETENTION_DAYS)).isoformat()
    return [e for e in entries if e.get("date", "9999") >= cutoff]


def _save(client_name: str, entries: list):
    with open(_client_path(client_name), "w") as f:
        json.dump(entries, f, indent=2)


def append_note(client_name: str, note: str) -> str:
    """Add a note to today's memory entry. Returns confirmation string."""
    today = datetime.date.today().isoformat()
    entries = load_memory(client_name)
    day = next((e for e in entries if e.get("date") == today), None)
    if day is None:
        day = {"date": today, "notes": []}
        entries.append(day)
    day["notes"].append(note)
    _save(client_name, entries)
    return f"[Memory] Note saved for {client_name} on {today}."


def memory_block(client_name: str) -> str:
    """Return formatted memory string for system prompt injection."""
    entries = load_memory(client_name)
    if not entries:
        return ""
    lines = ["Recent session memory (last 2 weeks):"]
    for e in sorted(entries, key=lambda x: x.get("date", "")):
        lines.append(f"  [{e['date']}]")
        for n in e.get("notes", []):
            lines.append(f"    - {n}")
    return "\n".join(lines)
