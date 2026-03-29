# core/code.py — Uptek Field /code project mode
# Persistent project memory + AI coding assistant
import os
import json
import time
import datetime

_KEY_FILES = {
    "main.py", "server.py", "web.py", "app.py", "index.py",
    "manage.py", "wsgi.py", "asgi.py", "cli.py", "run.py",
}
_CODE_EXTS = {".py", ".js", ".ts", ".go", ".rs", ".rb", ".php",
              ".sh", ".yaml", ".yml", ".toml", ".env.example", ".md"}
_SKIP_DIRS = {"__pycache__", ".git", "node_modules", "venv", ".venv",
              "dist", "build", ".mypy_cache", ".pytest_cache"}

_PROJECTS_DIR = os.path.join(os.path.expanduser("~"), ".uptek", "projects")


# ── Storage ───────────────────────────────────────────────────────────────────

def get_projects_dir() -> str:
    os.makedirs(_PROJECTS_DIR, exist_ok=True)
    return _PROJECTS_DIR


def _project_dir(name: str) -> str:
    path = os.path.join(_PROJECTS_DIR, _safe(name))
    os.makedirs(path, exist_ok=True)
    return path


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)


def _memory_path(name: str) -> str:
    return os.path.join(_project_dir(name), "memory.json")


def list_projects() -> list:
    base = get_projects_dir()
    return sorted([
        d for d in os.listdir(base)
        if os.path.isdir(os.path.join(base, d)) and
           os.path.exists(os.path.join(base, d, "memory.json"))
    ])


def load_project(name: str) -> dict | None:
    path = _memory_path(name)
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def save_project(data: dict):
    name = data["name"]
    path = _memory_path(name)
    data["updated_at"] = datetime.datetime.now().isoformat()
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def get_project_files(name: str) -> list:
    """Return list of (filename, content) tuples for files in the project folder."""
    pdir = _project_dir(name)
    files = []
    for fn in sorted(os.listdir(pdir)):
        if fn == "memory.json" or fn.startswith("."):
            continue
        fpath = os.path.join(pdir, fn)
        if os.path.isfile(fpath):
            try:
                with open(fpath, errors="replace") as f:
                    content = f.read(8000)  # cap at 8k per file
                files.append((fn, content))
            except Exception:
                pass
    return files


def scan_workdir(workdir: str, recent_days: int = 3,
                 max_files: int = 10, max_chars: int = 5000) -> list:
    """
    Smart scan of workdir — returns (rel_path, content) tuples.
    Priority: key entry points first, then recently modified files.
    """
    if not workdir or not os.path.isdir(workdir):
        return []

    cutoff   = time.time() - (recent_days * 86400)
    found    = []  # (mtime, rel_path, abs_path)

    for root, dirs, files in os.walk(workdir):
        # Prune skip dirs in-place
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            _, ext = os.path.splitext(fn)
            if ext.lower() not in _CODE_EXTS:
                continue
            abs_path = os.path.join(root, fn)
            rel_path = os.path.relpath(abs_path, workdir)
            try:
                mtime = os.path.getmtime(abs_path)
                size  = os.path.getsize(abs_path)
            except OSError:
                continue
            if size > 200_000:  # skip files over 200k
                continue
            found.append((mtime, rel_path, abs_path, fn))

    # Sort: key entry points first (regardless of mtime), then by recency
    def sort_key(item):
        mtime, rel, abs_p, fn = item
        is_key    = fn in _KEY_FILES
        is_recent = mtime >= cutoff
        # Lower = higher priority: key+recent, key, recent, other
        if is_key and is_recent: return (0, -mtime)
        if is_key:               return (1, -mtime)
        if is_recent:            return (2, -mtime)
        return (3, -mtime)

    found.sort(key=sort_key)

    results = []
    total_chars = 0
    for mtime, rel_path, abs_path, fn in found:
        if len(results) >= max_files:
            break
        if total_chars >= max_files * max_chars:
            break
        try:
            with open(abs_path, errors="replace") as f:
                content = f.read(max_chars)
            results.append((rel_path, content))
            total_chars += len(content)
        except Exception:
            pass

    return results


def add_file_to_project(project_name: str, source_path: str) -> str:
    """Copy a file into the project folder. Returns the destination path."""
    import shutil
    pdir = _project_dir(project_name)
    fn   = os.path.basename(source_path)
    dest = os.path.join(pdir, fn)
    shutil.copy2(source_path, dest)
    return dest


def remove_file_from_project(project_name: str, filename: str) -> bool:
    fpath = os.path.join(_project_dir(project_name), filename)
    if os.path.exists(fpath):
        os.remove(fpath)
        return True
    return False


# ── Project wizard ────────────────────────────────────────────────────────────

def _ask(prompt: str, default: str = "") -> str:
    val = input(prompt).strip()
    return val if val else default


def new_project_wizard() -> dict:
    print("\n[Uptek /code] New project — fill in what you know, leave blank to skip.\n")
    name  = _ask("Project name (no spaces): ").replace(" ", "-")
    if not name:
        raise ValueError("Project name required.")

    print("\n  These five fields are your permanent memory — the context any AI needs")
    print("  to understand your project from a cold start.\n")

    who   = _ask("  WHO  — who owns/built this, who uses it: ")
    what  = _ask("  WHAT — what does it do, what stack: ")
    where = _ask("  WHERE — where does it live (repo path, server, URL): ")
    why   = _ask("  WHY  — why does it exist, what problem does it solve: ")
    when  = _ask("  WHEN — timeline, key dates, launch status: ")
    notes = _ask("  Any other context (leave blank to skip): ")

    data = {
        "name":       name,
        "who":        who,
        "what":       what,
        "where":      where,
        "why":        why,
        "when":       when,
        "notes":      notes,
        "created_at": datetime.datetime.now().isoformat(),
        "updated_at": datetime.datetime.now().isoformat(),
        "session_log": [],
    }
    save_project(data)
    print(f"\n[Uptek] Project '{name}' created at {_project_dir(name)}")
    return data


def select_or_create_project() -> dict:
    existing = list_projects()

    if existing:
        print("\nProjects:")
        for i, name in enumerate(existing, 1):
            p = load_project(name)
            what = (p.get("what") or "")[:60] if p else ""
            print(f"  {i}. {name}  —  {what}")
        print("  N. New project\n")

        choice = _ask("Select project or N for new: ").strip()
        if choice.upper() != "N":
            try:
                idx  = int(choice) - 1
                name = existing[idx]
                p    = load_project(name)
                if p:
                    return p
            except (ValueError, IndexError):
                print("[Uptek] Invalid selection.")
            return select_or_create_project()

    return new_project_wizard()


def update_project_wizard(data: dict) -> dict:
    print("\n[Uptek /code] Update project memory — press Enter to keep current value.\n")
    fields = [("who", "WHO"), ("what", "WHAT"), ("where", "WHERE"),
              ("why", "WHY"), ("when", "WHEN"), ("notes", "Notes")]
    for key, label in fields:
        current = data.get(key, "")
        val = input(f"  {label} [{current[:60]}]: ").strip()
        if val:
            data[key] = val
    save_project(data)
    print("[Uptek] Memory updated.")
    return data


# ── System prompt builder ─────────────────────────────────────────────────────

def build_code_system_prompt(project: dict, manual_files: list,
                              workdir_files: list) -> str:
    prompt = f"""You are an expert software engineer and technical co-pilot embedded in Uptek Field.

PROJECT MEMORY
==============
Name:   {project.get('name', '')}
Who:    {project.get('who', '')}
What:   {project.get('what', '')}
Where:  {project.get('where', '')}
Why:    {project.get('why', '')}
When:   {project.get('when', '')}
Notes:  {project.get('notes', '')}

INSTRUCTIONS
============
- You have full context on this project. Refer to it in every response.
- Write clean, minimal code. Don't over-engineer. No unnecessary abstractions.
- When asked to build something, output the actual code ready to use.
- When reviewing code, be direct. Call out real problems, not style preferences.
- Remember what was discussed earlier in this session — you have full history.
- If the user says "you" they mean you, the AI. Act on it.
- You are the backup brain for this project. Treat it that way.
"""

    if workdir_files:
        prompt += "\nLIVE CODEBASE (auto-loaded from workdir — key files + recently modified)\n"
        prompt += "=" * 70 + "\n"
        for rel_path, content in workdir_files:
            prompt += f"\n--- {rel_path} ---\n{content}\n"

    if manual_files:
        prompt += "\nMANUALLY ADDED FILES\n" + "=" * 70 + "\n"
        for fn, content in manual_files:
            prompt += f"\n--- {fn} ---\n{content}\n"

    return prompt


# ── Main code mode loop ───────────────────────────────────────────────────────

CODE_HELP = """
/code commands:
  /memory            — show project memory (who/what/where/why/when)
  /update            — edit project memory fields
  /workdir <path>    — set working directory (auto-loads recent files each session)
  /reload            — re-scan workdir and refresh context
  /files             — list all files currently in context
  /add <path>        — manually add a file to context
  /remove <name>     — remove a manually added file
  /save <note>       — append a note to project memory
  /projects          — switch to a different project
  /clear             — clear conversation history
  /back              — return to main session
"""


def run_code_mode(provider: str, api_key: str, pacman_thinking_fn=None,
                  initial_project: dict = None):
    from core.agent import run_agent

    project = initial_project or select_or_create_project()
    history = []

    def _reload_prompt():
        manual_files  = get_project_files(project["name"])
        workdir       = project.get("workdir", "")
        workdir_files = scan_workdir(workdir) if workdir else []
        return build_code_system_prompt(project, manual_files, workdir_files), workdir_files

    system_prompt, _wfiles = _reload_prompt()

    print(f"\n[Uptek /code] Project: {project['name']}")
    print(f"  {project.get('what', '')}")
    workdir = project.get("workdir", "")
    if workdir and _wfiles:
        print(f"  Loaded {len(_wfiles)} files from {workdir}")
    elif workdir:
        print(f"  Workdir: {workdir} (no recent files found)")
    else:
        print(f"  No workdir set — use /workdir <path> to enable auto-loading")
    print(f"  /memory to review context  |  /help for commands  |  /back to exit\n")

    while True:
        try:
            user_input = input("code > ").strip()
        except (EOFError, KeyboardInterrupt):
            user_input = "/back"

        if not user_input:
            continue

        if user_input in ("/back", "/exit"):
            print("[Uptek] Back to main session.\n")
            return

        elif user_input == "/help":
            print(CODE_HELP)

        elif user_input == "/memory":
            print(f"""
  Project:  {project['name']}
  WHO:      {project.get('who', '—')}
  WHAT:     {project.get('what', '—')}
  WHERE:    {project.get('where', '—')}
  WHY:      {project.get('why', '—')}
  WHEN:     {project.get('when', '—')}
  Notes:    {project.get('notes', '—')}
  Updated:  {project.get('updated_at', '—')[:19]}
""")

        elif user_input == "/update":
            project = update_project_wizard(project)
            system_prompt, _ = _reload_prompt()
            print("[Uptek] Context reloaded.")

        elif user_input.startswith("/workdir"):
            parts = user_input.split(None, 1)
            if len(parts) < 2:
                current = project.get("workdir", "not set")
                print(f"  Current workdir: {current}")
                print(f"  Usage: /workdir /path/to/your/project")
            else:
                path = os.path.expanduser(parts[1].strip())
                if not os.path.isdir(path):
                    print(f"  Directory not found: {path}")
                else:
                    project["workdir"] = path
                    save_project(project)
                    system_prompt, wf = _reload_prompt()
                    print(f"  Workdir set: {path}")
                    print(f"  Loaded {len(wf)} files into context.")

        elif user_input == "/reload":
            system_prompt, wf = _reload_prompt()
            workdir = project.get("workdir", "")
            if workdir:
                print(f"  Reloaded — {len(wf)} files from {workdir}")
            else:
                print("  No workdir set. Use /workdir <path> first.")

        elif user_input == "/files":
            manual_files  = get_project_files(project["name"])
            workdir       = project.get("workdir", "")
            workdir_files = scan_workdir(workdir) if workdir else []
            pdir = _project_dir(project["name"])
            if workdir_files:
                print(f"\n  Auto-loaded from workdir ({workdir}):")
                for rel, content in workdir_files:
                    print(f"    {rel}  ({len(content)} chars)")
            if manual_files:
                print(f"\n  Manually added ({pdir}):")
                for fn, content in manual_files:
                    print(f"    {fn}  ({len(content)} chars)")
            if not workdir_files and not manual_files:
                print(f"  No files in context. Use /workdir <path> or /add <file>")
            print()

        elif user_input.startswith("/add "):
            src = user_input[5:].strip().strip('"')
            src = os.path.expanduser(src)
            if not os.path.exists(src):
                print(f"  File not found: {src}")
            else:
                dest = add_file_to_project(project["name"], src)
                system_prompt, _ = _reload_prompt()
                print(f"  Added: {os.path.basename(src)} — context reloaded.")

        elif user_input.startswith("/remove "):
            fn = user_input[8:].strip()
            if remove_file_from_project(project["name"], fn):
                system_prompt, _ = _reload_prompt()
                print(f"  Removed: {fn} — context reloaded.")
            else:
                print(f"  File not found in project: {fn}")

        elif user_input.startswith("/save "):
            note = user_input[6:].strip()
            ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            existing_notes = project.get("notes", "")
            project["notes"] = f"{existing_notes}\n[{ts}] {note}".strip()
            save_project(project)
            system_prompt, _ = _reload_prompt()
            print("  Note saved to project memory.")

        elif user_input == "/projects":
            project = select_or_create_project()
            system_prompt, _ = _reload_prompt()
            history = []
            print(f"[Uptek] Switched to: {project['name']}\n")

        elif user_input == "/clear":
            history = []
            print("[Uptek] Conversation cleared.")

        else:
            if not api_key:
                print("[Uptek] No API key configured.")
                continue

            spinner = pacman_thinking_fn() if pacman_thinking_fn else None
            response = run_agent(
                user_input, {}, history,
                provider=provider,
                system_prompt=system_prompt,
            )
            if spinner:
                spinner()

            print(f"\nuptek > {response}\n")

            history.append({"role": "user",      "content": user_input})
            history.append({"role": "assistant",  "content": response})
            if len(history) > 60:
                history = history[-60:]

            # Auto-append to project session log
            project.setdefault("session_log", []).append({
                "ts":  datetime.datetime.now().isoformat(),
                "q":   user_input[:200],
                "a":   response[:500],
            })
            # Keep last 100 exchanges in log
            project["session_log"] = project["session_log"][-100:]
            save_project(project)
