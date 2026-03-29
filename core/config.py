# core/config.py — environment detection and global config
import os
import platform
import sys

def detect_os() -> str:
    """Returns 'linux', 'windows', or 'mac'."""
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    if s == "darwin":
        return "mac"
    return "linux"

def detect_shell() -> str:
    if detect_os() == "windows":
        return "powershell"
    return "bash"

SYSTEM_BIN_DIRS = ("/usr/local/bin", "/usr/bin", "/bin", "/usr/local/sbin")

def get_drive_root() -> str:
    """Returns the directory containing the uptek-field binary/script."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _is_system_installed() -> bool:
    """True when the binary lives in a system bin dir (not a thumb drive)."""
    root = get_drive_root()
    return any(root.startswith(d) for d in SYSTEM_BIN_DIRS)

def _data_root() -> str:
    """Where to store profiles/tasks/reports — home dir if system-installed, drive if portable."""
    if _is_system_installed():
        return os.path.join(os.path.expanduser("~"), ".uptek")
    return get_drive_root()

def get_profiles_dir() -> str:
    return os.path.join(_data_root(), "profiles")

def get_tasks_dir() -> str:
    return os.path.join(_data_root(), "tasks")

def get_reports_dir() -> str:
    return os.path.join(_data_root(), "reports")

def get_memory_dir() -> str:
    return os.path.join(_data_root(), "memory")

OS   = detect_os()
SHELL = detect_shell()
