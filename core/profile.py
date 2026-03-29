# core/profile.py — client profile: create, load, update, encrypt, sync
import os
import re
import json
import hashlib
import base64
import datetime
import requests
from pathlib import Path
from core.config import get_profiles_dir

try:
    from cryptography.fernet import Fernet
    _CRYPTO = True
except ImportError:
    _CRYPTO = False


# ── Encryption ────────────────────────────────────────────────────────────────

def _derive_key(grok_key: str, pin: str) -> bytes:
    """Derive a Fernet key from Grok API key + PIN."""
    raw = f"{grok_key}:{pin}".encode()
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest)

def _encrypt(data: str, key: bytes) -> str:
    if not _CRYPTO:
        return data  # fallback: no encryption if cryptography not installed
    f = Fernet(key)
    return f.encrypt(data.encode()).decode()

def _decrypt(data: str, key: bytes) -> str:
    if not _CRYPTO:
        return data
    f = Fernet(key)
    return f.decrypt(data.encode()).decode()


# ── Profile schema ────────────────────────────────────────────────────────────

def new_profile(client_name: str, technician: str, notes: str = "") -> dict:
    return {
        "client_name": client_name,
        "technician": technician,
        "notes": notes,
        "created": datetime.datetime.now().isoformat(),
        "last_visit": None,
        "visits": [],
        "network": {
            "subnet": None,
            "gateway": None,
            "dns": [],
            "open_ports": [],
            "known_hosts": [],
        },
        "systems": [],       # {hostname, os, ip, role, services[]}
        "findings": [],      # {date, severity, title, detail, status}
        "fixes": [],         # {date, what, how, by}
        "open_items": [],    # {date, title, detail, due}
        "tasks_run": [],     # {date, task_name, result}
        "credentials_note": "",  # reminder only, never store actual creds
    }


# ── Persistence ───────────────────────────────────────────────────────────────

def _profile_path(client_name: str) -> str:
    safe = client_name.lower().strip().replace(" ", "_")
    safe = re.sub(r"[^a-z0-9_\-]", "", safe)
    safe = safe.strip("_-") or "unnamed"
    return os.path.join(get_profiles_dir(), f"{safe}.uptek")

def list_profiles() -> list:
    d = get_profiles_dir()
    if not os.path.isdir(d):
        return []
    return [f.replace(".uptek", "").replace("_", " ").title()
            for f in os.listdir(d) if f.endswith(".uptek")]

def save_profile(profile: dict, enc_key: bytes | None = None):
    os.makedirs(get_profiles_dir(), exist_ok=True)
    path = _profile_path(profile["client_name"])
    raw = json.dumps(profile, indent=2)
    if enc_key:
        raw = _encrypt(raw, enc_key)
    with open(path, "w") as f:
        f.write(raw)

def load_profile(client_name: str, enc_key: bytes | None = None) -> dict | None:
    path = _profile_path(client_name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        raw = f.read()
    if enc_key:
        try:
            raw = _decrypt(raw, enc_key)
        except Exception:
            # Maybe it was saved before encryption was set up — try plain JSON
            try:
                profile = json.loads(raw)
                print("[Profile] Loaded unencrypted profile — re-saving with encryption.")
                save_profile(profile, enc_key)
                return profile
            except Exception:
                print("[Profile] Decryption failed — wrong key or PIN.")
                return None
    return json.loads(raw)


# ── Profile updates (called automatically as Uptek discovers things) ──────────

def record_finding(profile: dict, severity: str, title: str, detail: str):
    """severity: critical | warning | info"""
    profile["findings"].append({
        "date": datetime.datetime.now().isoformat(),
        "severity": severity,
        "title": title,
        "detail": detail,
        "status": "open",
    })

def record_fix(profile: dict, what: str, how: str, by: str = "uptek"):
    profile["fixes"].append({
        "date": datetime.datetime.now().isoformat(),
        "what": what,
        "how": how,
        "by": by,
    })

def record_open_item(profile: dict, title: str, detail: str, due: str = ""):
    profile["open_items"].append({
        "date": datetime.datetime.now().isoformat(),
        "title": title,
        "detail": detail,
        "due": due,
        "status": "open",
    })

def update_network(profile: dict, **kwargs):
    """Update any network fields discovered during the session."""
    for k, v in kwargs.items():
        if k in profile["network"]:
            if isinstance(profile["network"][k], list) and not isinstance(v, list):
                if v not in profile["network"][k]:
                    profile["network"][k].append(v)
            else:
                profile["network"][k] = v

def add_system(profile: dict, hostname: str, ip: str, os_name: str,
               role: str = "", services: list = None):
    existing = [s for s in profile["systems"] if s["ip"] == ip]
    if existing:
        existing[0].update({"hostname": hostname, "os": os_name,
                            "role": role, "services": services or []})
    else:
        profile["systems"].append({
            "hostname": hostname, "ip": ip, "os": os_name,
            "role": role, "services": services or [],
        })

def start_visit(profile: dict):
    now = datetime.datetime.now().isoformat()
    profile["last_visit"] = now
    profile["visits"].append({"date": now, "findings": 0, "fixes": 0})

def close_visit(profile: dict):
    if profile["visits"]:
        v = profile["visits"][-1]
        open_findings = [f for f in profile["findings"] if f["status"] == "open"]
        v["findings"] = len(open_findings)
        v["fixes"] = len([f for f in profile["fixes"]
                          if f["date"] >= v["date"]])


# ── Home base sync ────────────────────────────────────────────────────────────

def sync_to_homebase(profile: dict, enc_key: bytes, homebase_url: str, api_token: str) -> bool:
    """Encrypt profile and POST it to the home base API."""
    try:
        raw = json.dumps(profile)
        encrypted = _encrypt(raw, enc_key)
        safe_name = profile["client_name"].lower().replace(" ", "_")
        r = requests.post(
            f"{homebase_url}/api/uptek/profiles/sync",
            json={"client_id": safe_name, "data": encrypted},
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=10,
        )
        return r.status_code == 200
    except Exception as e:
        print(f"[Profile] Homebase sync failed: {e}")
        return False
