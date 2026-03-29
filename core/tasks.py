# core/tasks.py — saved task templates
import os
import json
from core.config import get_tasks_dir
from core.tools import bash_exec


def list_tasks() -> list:
    d = get_tasks_dir()
    if not os.path.isdir(d):
        return []
    return [f.replace(".json", "") for f in os.listdir(d) if f.endswith(".json")]


def load_task(name: str) -> dict | None:
    path = os.path.join(get_tasks_dir(), f"{name}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def save_task(name: str, description: str, steps: list):
    """
    steps: list of {"label": str, "command": str, "confirm": bool}
    """
    os.makedirs(get_tasks_dir(), exist_ok=True)
    path = os.path.join(get_tasks_dir(), f"{name}.json")
    with open(path, "w") as f:
        json.dump({"name": name, "description": description, "steps": steps}, f, indent=2)
    print(f"[Tasks] Saved task '{name}'")


def run_task(name: str) -> list:
    task = load_task(name)
    if not task:
        print(f"[Tasks] Task '{name}' not found.")
        return []

    print(f"\n⚡ Running task: {task['name']}")
    print(f"   {task.get('description', '')}\n")

    results = []
    for step in task.get("steps", []):
        label   = step.get("label", step.get("command", "?"))
        command = step.get("command", "")
        print(f"  → {label}")
        out = bash_exec(command)
        results.append({"label": label, "command": command, "output": out})
        if out and out != "[Aborted by user]":
            print(f"    {out[:200]}")

    print(f"\n[Tasks] Done: {task['name']}")
    return results


def delete_task(name: str) -> bool:
    path = os.path.join(get_tasks_dir(), f"{name}.json")
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


# ── Built-in starter tasks ─────────────────────────────────────────────────────

BUILTIN_TASKS = {
    "harden-ssh": {
        "description": "Disable root SSH login and password auth, restart SSH.",
        "steps": [
            {"label": "Disable root login", "command": "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config"},
            {"label": "Disable password auth", "command": "sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config"},
            {"label": "Restart SSH", "command": "systemctl restart sshd"},
        ],
    },
    "check-network": {
        "description": "Quick network snapshot — interfaces, routes, open ports.",
        "steps": [
            {"label": "Interfaces", "command": "ip addr show"},
            {"label": "Routes", "command": "ip route show"},
            {"label": "Open ports", "command": "ss -tlnp"},
        ],
    },
    "clean-docker": {
        "description": "Remove stopped containers, dangling images, unused volumes.",
        "steps": [
            {"label": "Remove stopped containers", "command": "docker container prune -f"},
            {"label": "Remove dangling images", "command": "docker image prune -f"},
            {"label": "Remove unused volumes", "command": "docker volume prune -f"},
        ],
    },
    "update-system": {
        "description": "Run apt update + upgrade (non-interactive).",
        "steps": [
            {"label": "Update package list", "command": "apt-get update -q"},
            {"label": "Upgrade packages", "command": "DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q"},
        ],
    },
}


def ensure_builtin_tasks():
    """Write built-in tasks to disk if they don't exist yet."""
    for name, task in BUILTIN_TASKS.items():
        if not load_task(name):
            save_task(name, task["description"], task["steps"])
