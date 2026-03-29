# core/boot.py — startup animation + thinking spinner
import sys
import time
import shutil
import threading
import urllib.request


def check_for_update(current_version: str):
    """
    Check 906techexpress.com for a newer version in a background thread.
    Prints a one-liner notice if an update is available. Silent on failure.
    """
    def _check():
        try:
            url = "https://906techexpress.com/uptek/version.txt"
            with urllib.request.urlopen(url, timeout=2) as r:
                remote = r.read().decode().strip()
            if remote and remote != current_version:
                print(f"\n  📦 Update available: {current_version} → {remote}")
                print("     curl -fsSL https://906techexpress.com/uptek/install.sh | bash\n")
        except Exception:
            pass  # Offline or server not hosting yet — silent

    threading.Thread(target=_check, daemon=True).start()


def pacman_boot():
    """Pac-Man chomps across the terminal eating bits, then vanishes."""
    try:
        Y  = "\033[93m"   # yellow
        CY = "\033[96m"   # cyan
        R  = "\033[0m"    # reset

        cols  = shutil.get_terminal_size((60, 20)).columns
        width = min(cols - 6, 58)

        # Two-frame mouth animation: open / closed
        pac = [f"{Y}C{R}", f"{Y}O{R}"]
        dot = f"{CY}\xb7{R}"   # · middle dot

        row = [dot] * width

        for i in range(width):
            line = list(row)
            line[i] = pac[i % 2]
            for j in range(i):
                line[j] = " "
            sys.stdout.write("\r  " + "".join(line))
            sys.stdout.flush()
            time.sleep(0.020)

        # Wink — full closed circle at the end before vanishing
        sys.stdout.write(f"\r  {Y}O{R}" + " " * (width - 1))
        sys.stdout.flush()
        time.sleep(0.15)

        # Clear the line
        sys.stdout.write("\r" + " " * (width + 4) + "\r")
        sys.stdout.flush()

    except Exception:
        pass  # Never crash the boot over an animation


# Module-level pause flag — tools.py sets this before input() calls
_pause_event = threading.Event()

def pause_spinner():
    """Freeze the spinner before prompting for user input."""
    _pause_event.set()
    # Give the animation thread one cycle to stop writing before input() starts
    time.sleep(0.05)
    # Clear whatever the spinner last drew so the prompt line is clean
    try:
        cols = shutil.get_terminal_size((60, 20)).columns
        sys.stdout.write("\r" + " " * (cols - 1) + "\r")
        sys.stdout.flush()
    except Exception:
        pass

def resume_spinner():
    """Unfreeze the spinner after input() returns."""
    _pause_event.clear()


def pacman_thinking():
    """
    Starts a bouncing Pac-Man spinner in a background thread.
    Returns a stop() function — call it when the response arrives.

        stop = pacman_thinking()
        result = some_slow_call()
        stop()
    """
    stop_event = threading.Event()

    def animate():
        try:
            Y  = "\033[93m"   # yellow
            CY = "\033[96m"   # cyan
            R  = "\033[0m"    # reset

            cols  = shutil.get_terminal_size((60, 20)).columns
            width = min(cols - 16, 40)
            label = "  uptek > "

            dot = f"{CY}\xb7{R}"
            # Pac-Man faces right (C) going right, left ()) going left
            pac_r = [f"{Y}C{R}", f"{Y}O{R}"]
            pac_l = [f"{Y}){R}", f"{Y}O{R}"]

            dots      = [dot] * width
            pos       = 0
            direction = 1
            frame     = 0

            while not stop_event.is_set():
                if _pause_event.is_set():
                    time.sleep(0.05)
                    continue

                line    = list(dots)
                pac     = pac_r if direction == 1 else pac_l
                line[pos] = pac[frame % 2]

                # Eaten dots behind Pac-Man are blank
                if direction == 1:
                    for j in range(pos):
                        line[j] = " "
                else:
                    for j in range(pos + 1, width):
                        line[j] = " "

                sys.stdout.write("\r" + label + "".join(line))
                sys.stdout.flush()

                pos   += direction
                frame += 1

                if pos >= width:       # hit right wall — bounce left
                    direction = -1
                    pos       = width - 1
                    dots      = [dot] * width
                elif pos < 0:          # hit left wall — bounce right
                    direction = 1
                    pos       = 0
                    dots      = [dot] * width

                time.sleep(0.038)

            # Clear the spinner line
            sys.stdout.write("\r" + " " * (width + len(label) + 2) + "\r")
            sys.stdout.flush()

        except Exception:
            pass

    t = threading.Thread(target=animate, daemon=True)
    t.start()

    def stop():
        stop_event.set()
        t.join()

    return stop
