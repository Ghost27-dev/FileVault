#!/usr/bin/env python3
"""
filevault.py - lil app i made to hide files n folders behind a password.
started as a weekend thing, kept bolting stuff onto it. works tho!!

GUI:   python filevault.py          (easiest, just run it)
CLI:   python filevault.py add <path> [...]     hide this (1st time asks you to make a pw)
       python filevault.py list                 whats protected rn
       python filevault.py hide [id ...]        hide everything, or just some ids
       python filevault.py reveal [id ...]      show stuff again (needs pw)
       python filevault.py remove <id>          stop protecting it (pw)
       python filevault.py passwd               change pw
       python filevault.py newkey               new recovery key (pw) -- WRITE IT DOWN
       python filevault.py recover              forgot pw?? use the recovery key
       python filevault.py log [-n 20]          activity log
       python filevault.py set <setting> <val>  tweak a setting
       python filevault.py icon <id> [image]    custom icon (item has to be visible first)
       python filevault.py decoy <id> [path]    fake file/folder that shows up while hidden (pw; no path = off)
       python filevault.py startup on|off|status
       python filevault.py --hide               hides everything quiet, this is what runs at login
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import platform
import plistlib
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

APP_DIR = Path.home() / ".filevault"
CONFIG = APP_DIR / "config.json"
LOG = APP_DIR / "activity.log"
ITERATIONS = 300_000  # saw this number in a stackoverflow answer, seems fine
SYSTEM = platform.system()  # Windows / Darwin / Linux -- gotta know what we're running on lol

DEFAULT_SETTINGS = {
    "hide_on_add": True,       # hide an item as soon as it is added
    "auto_hide_min": 0,        # re-hide revealed items after N minutes (0 = off, GUI must be open)
    "hide_on_exit": False,     # hide everything when FileVault is closed
    "lock_app": False,         # ask for the password to open FileVault itself
    "open_after_reveal": False,  # open the item's location after revealing it
}


# ---------------------------------------------------------------- crypto utils (the sciency bit)
def _hash(secret: str, salt: bytes) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, ITERATIONS)
    return base64.b64encode(dk).decode()


def make_credential(secret: str) -> dict:
    salt = secrets.token_bytes(16)
    return {"salt": base64.b64encode(salt).decode(), "hash": _hash(secret, salt)}


def check_credential(secret: str, cred: dict) -> bool:
    salt = base64.b64decode(cred["salt"])
    return hmac.compare_digest(_hash(secret, salt), cred["hash"])


def new_recovery_key() -> str:
    raw = secrets.token_hex(10).upper()  # 20 hex chars
    return "-".join(raw[i:i + 5] for i in range(0, 20, 5))


def normalize_key(k: str) -> str:
    return k.replace("-", "").replace(" ", "").strip().upper()


# ---------------------------------------------------------------- config
def save_config(cfg: dict):
    APP_DIR.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    os.replace(tmp, CONFIG)
    try:
        os.chmod(CONFIG, 0o600)
    except OSError:
        pass


def load_config():
    if not CONFIG.exists():
        return None
    cfg = json.loads(CONFIG.read_text())
    if "items" not in cfg:  # migrate the old single-item format
        items = []
        if cfg.get("path"):
            it = {"id": secrets.token_hex(4), "path": cfg["path"],
                  "hidden": cfg.get("hidden", False), "added": time.time()}
            if cfg.get("current_path"):
                it["current_path"] = cfg["current_path"]
            items.append(it)
        cfg = {"version": 2, "password": cfg["password"], "recovery": cfg["recovery"],
               "failed": cfg.get("failed", 0), "locked_until": cfg.get("locked_until", 0),
               "items": items}
        save_config(cfg)
    cfg["settings"] = {**DEFAULT_SETTINGS, **cfg.get("settings", {})}
    return cfg


# ---------------------------------------------------------------- activity log
def log_event(kind: str, detail: str = ""):
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        detail = detail.replace("\t", " ").replace("\n", " ")
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(f"{int(time.time())}\t{kind}\t{detail}\n")
    except OSError:
        pass


def read_log(limit: int = 200) -> list:
    """Newest first: [(timestamp, kind, detail), ...]"""
    if not LOG.exists():
        return []
    rows = []
    for line in LOG.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        parts = line.split("\t", 2)
        if len(parts) >= 2 and parts[0].isdigit():
            rows.append((int(parts[0]), parts[1], parts[2] if len(parts) > 2 else ""))
    return rows[::-1]


# ---------------------------------------------------------------- hide / unhide
def _hidden_name(p: Path) -> Path:
    return p.with_name("." + p.name) if not p.name.startswith(".") else p


def _run(cmd: list):
    kw = {"check": True, "capture_output": True}
    if SYSTEM == "Windows":
        kw["creationflags"] = 0x08000000  # no console window flash
    subprocess.run(cmd, **kw)


def _stash_path(it: dict) -> Path:
    """Where the real item sits while a stand-in occupies its visible path."""
    return APP_DIR / "stash" / it["id"]


def _remove_path(p: Path):
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p)
    else:
        p.unlink()


def _place_decoy(it: dict, p: Path):
    """copies the fake stuff into the real item's spot. undoes itself if it messes up"""
    X = Path(it["decoy"])  # the decoy. called it X, sue me
    try:
        if X.is_dir():
            shutil.copytree(X, p)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(X, p)
    except Exception:
        stash = _stash_path(it)
        if stash.exists() and not p.exists():
            shutil.move(str(stash), str(p))  # don't lose the real item if the copy failed
        raise


def item_state(it: dict) -> str:
    """'hidden', 'visible' or 'missing' - checks the actual filesystem, doesn't trust a saved flag"""
    p = Path(it["path"])
    if it.get("decoy"):
        # the swap trick: real stuff lives in the stash, fake stuff sits where the real thing was. sneaky
        return "hidden" if _stash_path(it).exists() else ("visible" if p.exists() else "missing")
    if SYSTEM == "Linux":
        cp = it.get("current_path")
        if p.exists():
            return "visible"
        return "hidden" if cp and Path(cp).exists() else "missing"
    if not p.exists():
        return "missing"
    if SYSTEM == "Windows":
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(p))
        if attrs in (-1, 0xFFFFFFFF):
            return "missing"
        return "hidden" if attrs & 0x2 else "visible"
    import stat
    flags = getattr(os.stat(p), "st_flags", 0)
    return "hidden" if flags & getattr(stat, "UF_HIDDEN", 0x8000) else "visible"


def hide_item(it: dict):
    p = Path(it["path"])
    if item_state(it) == "hidden":
        it["hidden"] = True
        return
    if it.get("decoy"):
        if not p.exists():
            raise FileNotFoundError(f"Not found: {p}")
        stash = _stash_path(it)
        stash.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(p), str(stash))
        _place_decoy(it, p)
    elif not p.exists():
        raise FileNotFoundError(f"Not found: {p}")
    elif SYSTEM == "Windows":
        _run(["attrib", "+h", "+s", str(p)])
    elif SYSTEM == "Darwin":
        _run(["chflags", "hidden", str(p)])
    else:
        target = _hidden_name(p)
        if target == p:
            raise RuntimeError("On Linux, names that already start with a dot can't be hidden.")
        p.rename(target)
        it["current_path"] = str(target)
    it["hidden"] = True
    it.pop("revealed_at", None)


def unhide_item(it: dict):
    p = Path(it["path"])
    if it.get("decoy"):
        stash = _stash_path(it)
        if stash.exists():
            if p.exists():
                _remove_path(p)  # remove the stand-in that's been sitting in its place
            shutil.move(str(stash), str(p))
    elif SYSTEM == "Windows":
        if not p.exists():
            raise FileNotFoundError(f"Not found: {p}")
        _run(["attrib", "-h", "-s", str(p)])
    elif SYSTEM == "Darwin":
        if not p.exists():
            raise FileNotFoundError(f"Not found: {p}")
        _run(["chflags", "nohidden", str(p)])
    else:
        cp = Path(it.get("current_path") or _hidden_name(p))
        if cp.exists() and not p.exists():
            cp.rename(p)
    it["hidden"] = False


def hide_all(cfg: dict, only_revealed: bool = False):
    """hides everything. gives back (how many, any errors)"""
    n, errors = 0, []
    for Batman in cfg["items"]:  # idk why i called it that, it just happened
        try:
            if only_revealed and item_state(Batman) != "visible":
                continue
            if item_state(Batman) != "hidden":
                n += 1
            hide_item(Batman)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{Path(Batman['path']).name}: {e}")
    save_config(cfg)
    return n, errors


def open_location(path: str):
    p = Path(path)
    try:
        if SYSTEM == "Windows":
            if p.is_dir():
                os.startfile(str(p))  # noqa: S606
            else:
                subprocess.Popen(["explorer", "/select,", str(p)])
        elif SYSTEM == "Darwin":
            subprocess.Popen(["open", "-R", str(p)])
        else:
            subprocess.Popen(["xdg-open", str(p if p.is_dir() else p.parent)])
    except OSError:
        pass


# ---------------------------------------------------------------- authentication
def _throttle(cfg: dict):
    wait = cfg.get("locked_until", 0) - time.time()
    if wait > 0:
        raise PermissionError(f"Too many failed attempts. Try again in {int(wait) + 1}s.")


def _fail(cfg: dict, what: str):
    cfg["failed"] = cfg.get("failed", 0) + 1
    if cfg["failed"] >= 3:  # 3 misses -> 30s wait, then it doubles each time, caps at 1hr. seems mean enough
        cfg["locked_until"] = time.time() + min(30 * 2 ** (cfg["failed"] - 3), 3600)
    save_config(cfg)
    log_event("fail", f"{what} (attempt {cfg['failed']})")


def _ok(cfg: dict):
    cfg["failed"] = 0
    cfg["locked_until"] = 0
    save_config(cfg)


def authenticate(cfg: dict, password: str):
    _throttle(cfg)
    if not check_credential(password, cfg["password"]):
        _fail(cfg, "Wrong password")
        raise PermissionError("Wrong password.")
    _ok(cfg)


def _check_reveal(cfg: dict, password: str):
    """reveal takes ur real pw OR the secret backup code. everything else only takes the real one, shh"""
    _throttle(cfg)
    if check_credential(password, cfg["password"]):
        _ok(cfg)
        return
    if cfg.get("trick") and check_credential(password, cfg["trick"]):
        _ok(cfg)
        return
    _fail(cfg, "Wrong password")
    raise PermissionError("Wrong password.")


# ---------------------------------------------------------------- core actions
def do_setup(password: str) -> str:
    """Create a new, empty vault. Returns the recovery key."""
    key = new_recovery_key()
    cfg = {"version": 2, "password": make_credential(password),
           "recovery": make_credential(normalize_key(key)),
           "failed": 0, "locked_until": 0, "items": [], "settings": dict(DEFAULT_SETTINGS)}
    save_config(cfg)
    log_event("setup", "Vault created")
    return key


def add_item(cfg: dict, path: str) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise FileNotFoundError(f"Not found: {p}")
    if APP_DIR.resolve() == p or APP_DIR.resolve() in p.parents:
        raise ValueError("Can't protect FileVault's own data folder.")
    for it in cfg["items"]:
        if Path(it["path"]) == p:
            raise ValueError(f"Already protected: {p.name}")
    it = {"id": secrets.token_hex(4), "path": str(p), "hidden": False, "added": time.time()}
    cfg["items"].append(it)
    save_config(cfg)
    log_event("added", f"Added {p.name}")
    return it


def remove_item(cfg: dict, password: str, item_id: str) -> str:
    authenticate(cfg, password)
    it = next((i for i in cfg["items"] if i["id"] == item_id), None)
    if not it:
        raise KeyError("No such item.")
    name = Path(it["path"]).name
    try:
        if item_state(it) == "hidden":
            unhide_item(it)
    except FileNotFoundError:
        pass
    cfg["items"] = [i for i in cfg["items"] if i["id"] != item_id]
    save_config(cfg)
    log_event("removed", f"Removed {name} (revealed and unprotected)")
    return f"Removed {name}."


def do_reveal(cfg: dict, password: str, ids=None) -> str:
    targets = [i for i in cfg["items"] if not ids or i["id"] in ids]
    try:
        _check_reveal(cfg, password)
    except PermissionError:
        if not any(i.get("decoy") for i in targets):
            raise
        # A stand-in is already sitting in the real item's place - just report success.
        return f"Revealed {len(targets)} item{'s' if len(targets) != 1 else ''}."
    n, errors = 0, []
    for it in targets:
        try:
            if item_state(it) == "hidden":
                unhide_item(it)
                n += 1
                log_event("reveal", f"Revealed {Path(it['path']).name}")
                if it.get("icon"):
                    _apply_saved_icon(it)
            it["revealed_at"] = time.time()
        except Exception as e:  # noqa: BLE001
            errors.append(f"{Path(it['path']).name}: {e}")
    save_config(cfg)
    msg = f"Revealed {n} item{'s' if n != 1 else ''}."
    return msg + (" Problems: " + "; ".join(errors) if errors else "")


def do_change_password(cfg: dict, old: str, new: str):
    authenticate(cfg, old)
    cfg["password"] = make_credential(new)
    save_config(cfg)
    log_event("password", "Password changed")


def do_new_recovery_key(cfg: dict, password: str) -> str:
    authenticate(cfg, password)
    key = new_recovery_key()
    cfg["recovery"] = make_credential(normalize_key(key))
    save_config(cfg)
    log_event("password", "New recovery key generated")
    return key


def do_recover(cfg: dict, recovery_key: str, new_password: str) -> str:
    """Reset the password with the recovery key. Returns a NEW recovery key."""
    _throttle(cfg)
    if not check_credential(normalize_key(recovery_key), cfg["recovery"]):
        _fail(cfg, "Invalid recovery key")
        raise PermissionError("Invalid recovery key.")
    new_key = new_recovery_key()
    cfg["password"] = make_credential(new_password)
    cfg["recovery"] = make_credential(normalize_key(new_key))
    _ok(cfg)
    log_event("password", "Password reset with recovery key")
    return new_key


def do_clear_log(cfg: dict, password: str):
    authenticate(cfg, password)
    LOG.unlink(missing_ok=True)
    log_event("log", "Activity log cleared")


def set_setting(key: str, value):
    cfg = load_config()
    cfg["settings"][key] = value
    save_config(cfg)


def _find_item(cfg: dict, item_id: str) -> dict:
    it = next((i for i in cfg["items"] if i["id"] == item_id), None)
    if not it:
        raise KeyError("No such item.")
    return it


# ---------------------------------------------------------------- custom icons
def _set_icon_os(p: Path, icon):
    """Apply a custom icon (or clear it when icon is None) with the platform's own mechanism."""
    if SYSTEM == "Linux":  # GNOME / Nautilus and most desktops that honour metadata::custom-icon
        if icon:
            _run(["gio", "set", str(p), "metadata::custom-icon", Path(icon).as_uri()])
        else:
            _run(["gio", "remove", str(p), "metadata::custom-icon"])
    elif SYSTEM == "Darwin":
        try:
            from AppKit import NSImage, NSWorkspace  # needs: pip install pyobjc-framework-Cocoa
        except ImportError:
            raise RuntimeError("Custom icons on macOS need PyObjC: pip install pyobjc-framework-Cocoa")
        img = NSImage.alloc().initWithContentsOfFile_(icon) if icon else None
        if not NSWorkspace.sharedWorkspace().setIcon_forFile_options_(img, str(p), 0):
            raise RuntimeError("macOS did not accept the icon.")
    elif SYSTEM == "Windows":
        # Windows only gives per-item icons to folders (via desktop.ini). Files use their type's icon.
        if not p.is_dir():
            raise RuntimeError("On Windows only folders can have their own icon. "
                               "Files show the icon of their file type.")
        ini = p / "desktop.ini"
        if icon:
            if Path(icon).suffix.lower() != ".ico":
                raise RuntimeError("On Windows the icon must be an .ico file.")
            ini.write_text(f"[.ShellClassInfo]\r\nIconResource={icon},0\r\n")
            _run(["attrib", "+h", "+s", str(ini)])
            _run(["attrib", "+s", str(p)])
        else:
            if ini.exists():
                _run(["attrib", "-h", "-s", str(ini)])
                ini.unlink()
            _run(["attrib", "-s", str(p)])


def _apply_saved_icon(it: dict):
    try:
        _set_icon_os(Path(it["path"]), it["icon"])
    except Exception:  # noqa: BLE001 - a missing icon must never block a reveal
        pass


def set_item_icon(cfg: dict, it: dict, icon):
    """Set or reset (icon=None) an item's icon. The item must be visible."""
    if icon:
        icon = str(Path(icon).expanduser().resolve())
        if not Path(icon).is_file():
            raise FileNotFoundError(f"Icon not found: {icon}")
    if item_state(it) != "visible":
        raise RuntimeError("Reveal the item first, then change its icon.")
    _set_icon_os(Path(it["path"]), icon)
    if icon:
        it["icon"] = icon
    else:
        it.pop("icon", None)
    save_config(cfg)
    log_event("icon", f"{'Changed' if icon else 'Reset'} icon for {Path(it['path']).name}")


# ---------------------------------------------------------------- stand-in and access code
def set_item_decoy(cfg: dict, it: dict, decoy):
    """Choose what takes the item's place on disk while it's hidden (None removes it).
    A copy of it sits at the item's real path for as long as the item stays hidden, so
    opening that path - from FileVault or directly - shows the stand-in, not the real item."""
    if item_state(it) != "visible":
        raise RuntimeError("Reveal the item first, then change its stand-in.")
    if decoy:
        p = Path(it["path"]).resolve()
        d = Path(decoy).expanduser().resolve()
        if not d.exists():
            raise FileNotFoundError(f"Not found: {d}")
        if d == p or p in d.parents or d in p.parents:
            raise ValueError("The stand-in can't be the protected item, contain it, or sit inside it.")
        if APP_DIR.resolve() == d or APP_DIR.resolve() in d.parents:
            raise ValueError("Can't use FileVault's own data folder as a stand-in.")
        it["decoy"] = str(d)
    else:
        it.pop("decoy", None)
    save_config(cfg)  # deliberately not logged, so the log doesn't reveal that a stand-in exists


def set_access_code(cfg: dict, code):
    """sets/clears the secret backup code (None = off). only works for reveal, nothing else, on purpose"""
    if code is None:
        cfg.pop("trick", None)
    else:
        if check_credential(code, cfg["password"]):
            raise ValueError("The access code must be different from your password.")
        cfg["trick"] = make_credential(code)
    save_config(cfg)  # deliberately not logged


# ---------------------------------------------------------------- startup entry
def _launcher_cmd() -> list:
    exe = sys.executable
    if SYSTEM == "Windows":
        pyw = Path(exe).with_name("pythonw.exe")
        if pyw.exists():
            exe = str(pyw)
    return [exe, str(Path(__file__).resolve()), "--hide"]


def startup_enable():
    cmd = _launcher_cmd()
    if SYSTEM == "Windows":
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                           r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "FileVault", 0, winreg.REG_SZ, " ".join(f'"{c}"' for c in cmd))
        winreg.CloseKey(k)
    elif SYSTEM == "Darwin":
        plist = Path.home() / "Library/LaunchAgents/com.filevault.hide.plist"
        plist.parent.mkdir(parents=True, exist_ok=True)
        plist.write_bytes(plistlib.dumps({"Label": "com.filevault.hide",
                                          "ProgramArguments": cmd, "RunAtLoad": True}))
    else:
        d = Path.home() / ".config/autostart"
        d.mkdir(parents=True, exist_ok=True)
        (d / "filevault.desktop").write_text(
            "[Desktop Entry]\nType=Application\nName=FileVault\n"
            f"Exec={' '.join(chr(34) + c + chr(34) for c in cmd)}\nX-GNOME-Autostart-enabled=true\n")


def startup_disable():
    if SYSTEM == "Windows":
        import winreg
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(k, "FileVault")
            winreg.CloseKey(k)
        except FileNotFoundError:
            pass
    elif SYSTEM == "Darwin":
        (Path.home() / "Library/LaunchAgents/com.filevault.hide.plist").unlink(missing_ok=True)
    else:
        (Path.home() / ".config/autostart/filevault.desktop").unlink(missing_ok=True)


def startup_is_enabled() -> bool:
    try:
        if SYSTEM == "Windows":
            import winreg
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Run")
            winreg.QueryValueEx(k, "FileVault")
            winreg.CloseKey(k)
            return True
        if SYSTEM == "Darwin":
            return (Path.home() / "Library/LaunchAgents/com.filevault.hide.plist").exists()
        return (Path.home() / ".config/autostart/filevault.desktop").exists()
    except OSError:
        return False


# ---------------------------------------------------------------- GUI
PALETTE = dict(
    bg="#0b1020", card="#151c33", card2="#1d2647", line="#2a3558",
    text="#e8ecf8", muted="#8b97b8", accent="#6c7bff", accent_h="#8793ff",
    ok="#34d399", warn="#fbbf24", bad="#f87171",
)

AUTO_HIDE_CHOICES = [("Off", 0), ("1 min", 1), ("5 min", 5), ("15 min", 15), ("30 min", 30), ("1 hr", 60)]

_UI_REV = "UnVkcmEgR3VwdGFfR2hvc3Q="  # ui schema tag, from an older build. leave as-is


def run_gui():
    import tkinter as tk
    from tkinter import filedialog

    if SYSTEM == "Windows":  # crisp text on high-DPI screens
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            pass

    C = PALETTE
    root = tk.Tk()
    root.title("FileVault")
    root.configure(bg=C["bg"])
    root.geometry("540x740")
    root.minsize(520, 680)

    fam = "Segoe UI" if SYSTEM == "Windows" else ("Helvetica Neue" if SYSTEM == "Darwin" else "DejaVu Sans")
    mono = "Consolas" if SYSTEM == "Windows" else ("Menlo" if SYSTEM == "Darwin" else "DejaVu Sans Mono")
    W = {}  # shared widget references

    def F(size, bold=False):
        return (fam, size, "bold" if bold else "normal")

    def short(p, n=46):
        p = str(p)
        return p if len(p) <= n else "…" + p[-(n - 1):]

    def fmt_time(ts):
        return time.strftime("%b %d, %H:%M", time.localtime(ts))

    # ------------------------------------------------------------ widgets
    class Btn(tk.Label):
        STYLES = {
            "primary": (C["accent"], C["accent_h"], "#ffffff"),
            "secondary": (C["card2"], C["line"], C["text"]),
            "ghost": (C["bg"], C["card"], C["muted"]),
            "danger": (C["card2"], "#4a2630", C["bad"]),
        }

        def __init__(self, parent, text, command, kind="primary", small=False, **kw):
            self.command, self.enabled = command, True
            self.bg, self.hv, self.fg = self.STYLES[kind]
            super().__init__(parent, text=text, bg=self.bg, fg=self.fg,
                             font=F(9 if small else 10, True),
                             padx=12 if small else 18, pady=6 if small else 11,
                             cursor="hand2", **kw)
            self.bind("<Enter>", lambda e: self.enabled and self.config(bg=self.hv))
            self.bind("<Leave>", lambda e: self.config(bg=self.bg if self.enabled else C["card"]))
            self.bind("<Button-1>", lambda e: self.enabled and self.command())

        def set_enabled(self, on):
            self.enabled = on
            if on:
                self.config(bg=self.bg, fg=self.fg, cursor="hand2")
            else:
                self.config(bg=C["card"], fg=C["line"], cursor="arrow")

        def set_kind(self, kind):
            self.bg, self.hv, self.fg = self.STYLES[kind]
            self.set_enabled(self.enabled)

    class Switch(tk.Canvas):
        def __init__(self, parent, value, command):
            super().__init__(parent, width=48, height=26, bg=C["card"],
                             highlightthickness=0, cursor="hand2")
            self.value, self.command = value, command
            self.bind("<Button-1>", lambda e: self.command(not self.value))
            self.draw()

        def set(self, v):
            self.value = v
            self.draw()

        def draw(self):
            self.delete("all")
            col = C["accent"] if self.value else C["line"]
            self.create_oval(0, 0, 26, 26, fill=col, outline=col)
            self.create_oval(22, 0, 48, 26, fill=col, outline=col)
            self.create_rectangle(13, 0, 35, 26, fill=col, outline=col)
            x = 24 if self.value else 2
            self.create_oval(x, 2, x + 22, 24, fill="#ffffff", outline="#ffffff")

    class Segmented(tk.Frame):
        def __init__(self, parent, options, value, command):
            super().__init__(parent, bg=C["card2"])
            self.options, self.command, self.labels = options, command, {}
            for label, val in options:
                lb = tk.Label(self, text=label, font=F(9, True), padx=8, pady=7, cursor="hand2")
                lb.pack(side="left", fill="x", expand=True)
                lb.bind("<Button-1>", lambda e, v=val: self.select(v, True))
                self.labels[val] = lb
            self.select(value, False)

        def select(self, value, fire):
            self.value = value
            for _, val in self.options:
                on = val == value
                self.labels[val].config(bg=C["accent"] if on else C["card2"],
                                        fg="#ffffff" if on else C["muted"])
            if fire:
                self.command(value)

    def card(parent, **kw):
        return tk.Frame(parent, bg=C["card"], highlightbackground=C["line"],
                        highlightthickness=1, **kw)

    # ------------------------------------------------------------ toast
    toast_job = [None]

    def toast(msg, kind="info"):
        lbl = W.get("toast")
        if lbl is None:
            return
        lbl.config(text=msg, fg={"ok": C["ok"], "err": C["bad"], "warn": C["warn"]}.get(kind, C["muted"]))
        if toast_job[0]:
            root.after_cancel(toast_job[0])
        toast_job[0] = root.after(6000, lambda: lbl.config(text=""))

    # ------------------------------------------------------------ shh (easter egg, don't tell anyone)
    X = [0, 0.0]  # click counter + last click time. couldn't think of a better name, X it is

    def _ghost_click(_=None):
        now = time.time()
        X[0] = X[0] + 1 if now - X[1] < 1.2 else 1
        X[1] = now
        if X[0] >= 5:
            X[0] = 0
            spook()

    def spook():
        gh = tk.Label(root, text="👻", bg=C["bg"], fg=C["text"], font=F(44))
        gh.place(relx=0.5, rely=0.42, anchor="center")
        root.after(1100, gh.destroy)
        toast("boo. you found the ghost 👻", "ok")

    # ------------------------------------------------------------ dialog helpers
    def modal(title):
        win = tk.Toplevel(root)
        win.title(title)
        win.configure(bg=C["bg"])
        win.transient(root)
        win.resizable(False, False)
        body = tk.Frame(win, bg=C["bg"], padx=26, pady=24)
        body.pack(fill="both", expand=True)
        tk.Frame(body, width=360, height=1, bg=C["bg"]).pack()  # fixes the width
        win.bind("<Escape>", lambda e: win.destroy())
        return win, body

    def center(win):
        win.update_idletasks()
        w, h = win.winfo_reqwidth(), win.winfo_reqheight()
        x = root.winfo_x() + (root.winfo_width() - w) // 2
        y = root.winfo_y() + (root.winfo_height() - h) // 3
        win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        try:
            win.wait_visibility()
            win.grab_set()
        except tk.TclError:
            pass
        win.focus_force()

    def heading(body, title, sub):
        tk.Label(body, text=title, bg=C["bg"], fg=C["text"], font=F(15, True),
                 anchor="w").pack(fill="x")
        tk.Label(body, text=sub, bg=C["bg"], fg=C["muted"], font=F(9), anchor="w",
                 justify="left", wraplength=360).pack(fill="x", pady=(4, 6))

    def field(parent, label, secret=False):
        tk.Label(parent, text=label, bg=C["bg"], fg=C["muted"], font=F(9),
                 anchor="w").pack(fill="x", pady=(12, 4))
        wrap = tk.Frame(parent, bg=C["line"], padx=1, pady=1)
        wrap.pack(fill="x")
        e = tk.Entry(wrap, show="•" if secret else "", bg=C["card"], fg=C["text"],
                     insertbackground=C["text"], relief="flat", font=F(11),
                     highlightthickness=0, bd=6)
        e.pack(fill="x")
        e.bind("<FocusIn>", lambda ev: wrap.config(bg=C["accent"]))
        e.bind("<FocusOut>", lambda ev: wrap.config(bg=C["line"]))
        return e

    def errlabel(parent):
        lbl = tk.Label(parent, text="", bg=C["bg"], fg=C["bad"], font=F(9),
                       anchor="w", justify="left", wraplength=360)
        lbl.pack(fill="x", pady=(10, 0))
        return lbl

    def strength_bar(parent, entry):
        row = tk.Frame(parent, bg=C["bg"])
        row.pack(fill="x", pady=(8, 0))
        segs = [tk.Frame(row, bg=C["line"], height=4) for _ in range(4)]
        for s in segs:
            s.pack(side="left", fill="x", expand=True, padx=2)
        lab = tk.Label(parent, text="", bg=C["bg"], fg=C["muted"], font=F(8), anchor="w")
        lab.pack(fill="x")

        def update(_=None):
            pw = entry.get()
            score = 0
            if pw:
                score = 1 + (len(pw) >= 8) + (len(pw) >= 12) + (
                    any(c.isdigit() for c in pw) and any(c.isalpha() for c in pw)) + any(
                    not c.isalnum() for c in pw)
                score = min(score, 4)
            col = {1: C["bad"], 2: C["warn"], 3: C["ok"], 4: C["ok"]}.get(score, C["line"])
            for i, s in enumerate(segs):
                s.config(bg=col if i < score else C["line"])
            lab.config(text=["", "Weak", "Okay", "Good", "Strong"][score])
        entry.bind("<KeyRelease>", update, add="+")

    def button_row(body, *buttons):
        row = tk.Frame(body, bg=C["bg"])
        row.pack(fill="x", pady=(20, 0))
        for b in reversed(buttons):
            b.pack(side="right", padx=(8, 0))
        return row

    # ------------------------------------------------------------ dialogs
    def password_dialog(title, sub, button, on_submit, danger=False):
        win, body = modal(title)
        heading(body, title, sub)
        e = field(body, "Password", secret=True)
        err = errlabel(body)

        def submit(_=None):
            pw = e.get()
            if not pw:
                err.config(text="Enter your password.")
                return
            msg = on_submit(pw)
            if msg:
                err.config(text=msg)
                e.delete(0, "end")
                e.focus_set()
            else:
                win.destroy()
        button_row(body, Btn(body, "Cancel", win.destroy, "ghost"),
                   Btn(body, button, submit, "danger" if danger else "primary"))
        e.bind("<Return>", submit)
        center(win)
        e.focus_set()

    def key_dialog(key, title="Save your recovery key"):
        win, body = modal(title)
        heading(body, title, "This is the ONLY way to reset a forgotten password. "
                             "Write it down and keep it somewhere safe.")
        box = tk.Frame(body, bg=C["card"], highlightbackground=C["accent"], highlightthickness=1)
        box.pack(fill="x", pady=(14, 10))
        tk.Label(box, text=key, font=(mono, 15, "bold"), bg=C["card"], fg=C["text"],
                 pady=18).pack()

        def copy():
            root.clipboard_clear()
            root.clipboard_append(key)
            copy_btn.config(text="Copied ✓")
        copy_btn = Btn(body, "Copy to clipboard", copy, "secondary")
        copy_btn.pack(fill="x")

        saved = tk.BooleanVar(value=False)
        done = Btn(body, "Done", win.destroy, "primary")
        done.set_enabled(False)
        tk.Checkbutton(body, text="I have saved this key", variable=saved,
                       command=lambda: done.set_enabled(saved.get()),
                       bg=C["bg"], fg=C["text"], selectcolor=C["card"],
                       activebackground=C["bg"], activeforeground=C["text"],
                       font=F(10), bd=0, highlightthickness=0).pack(anchor="w", pady=(16, 0))
        button_row(body, done)
        win.protocol("WM_DELETE_WINDOW", lambda: win.destroy() if saved.get() else None)
        win.unbind("<Escape>")
        center(win)

    def reveal_dialog(ids=None):
        cfg = load_config()
        targets = [i for i in cfg["items"] if not ids or i["id"] in ids]
        if not targets:
            return
        label = f"“{Path(targets[0]['path']).name}”" if len(targets) == 1 else f"{len(targets)} items"

        def go(pw):
            try:
                msg = do_reveal(load_config(), pw, ids)
            except PermissionError as ex:
                return str(ex)
            except Exception as ex:  # noqa: BLE001
                return f"Error: {ex}"
            toast(msg, "ok")
            if load_config()["settings"]["open_after_reveal"]:
                for it in targets[:3]:
                    open_location(it["path"])
            refresh_vault()
            return None
        password_dialog("Reveal", f"Enter your password to reveal {label}.", "Reveal", go)

    def remove_dialog(item_id):
        cfg = load_config()
        it = next((i for i in cfg["items"] if i["id"] == item_id), None)
        if not it:
            return

        def go(pw):
            try:
                msg = remove_item(load_config(), pw, item_id)
            except PermissionError as ex:
                return str(ex)
            except Exception as ex:  # noqa: BLE001
                return f"Error: {ex}"
            toast(msg, "ok")
            refresh_vault()
            return None
        password_dialog("Stop protecting",
                        f"“{Path(it['path']).name}” will be revealed and removed from FileVault. "
                        "Enter your password to confirm.", "Remove", go, danger=True)

    def change_password_dialog():
        win, body = modal("Change password")
        heading(body, "Change password", "Your recovery key stays the same.")
        old = field(body, "Current password", secret=True)
        p1 = field(body, "New password", secret=True)
        strength_bar(body, p1)
        p2 = field(body, "Confirm new password", secret=True)
        err = errlabel(body)

        def submit(_=None):
            if not old.get():
                err.config(text="Enter your current password.")
            elif len(p1.get()) < 4:
                err.config(text="Use at least 4 characters.")
            elif p1.get() != p2.get():
                err.config(text="The two new passwords don't match.")
            else:
                try:
                    do_change_password(load_config(), old.get(), p1.get())
                except PermissionError as ex:
                    err.config(text=str(ex))
                    return
                win.destroy()
                toast("Password changed.", "ok")
                refresh_security()
        button_row(body, Btn(body, "Cancel", win.destroy, "ghost"),
                   Btn(body, "Change password", submit, "primary"))
        p2.bind("<Return>", submit)
        center(win)
        old.focus_set()

    def new_key_dialog():
        def go(pw):
            try:
                key = do_new_recovery_key(load_config(), pw)
            except PermissionError as ex:
                return str(ex)
            key_dialog(key, "Your NEW recovery key")
            return None
        password_dialog("New recovery key",
                        "The old recovery key will stop working. Enter your password to continue.",
                        "Generate", go)

    def forgot_dialog():
        win, body = modal("Reset password")
        heading(body, "Forgot your password?",
                "Enter the recovery key you saved when you set this up.")
        k = field(body, "Recovery key")
        p1 = field(body, "New password", secret=True)
        strength_bar(body, p1)
        p2 = field(body, "Confirm new password", secret=True)
        err = errlabel(body)

        def submit(_=None):
            if len(p1.get()) < 4:
                err.config(text="Use at least 4 characters.")
            elif p1.get() != p2.get():
                err.config(text="The two passwords don't match.")
            else:
                try:
                    new_key = do_recover(load_config(), k.get(), p1.get())
                except PermissionError as ex:
                    err.config(text=str(ex))
                    return
                win.destroy()
                toast("Password reset.", "ok")
                key_dialog(new_key, "Your NEW recovery key")
                refresh_security()
        button_row(body, Btn(body, "Cancel", win.destroy, "ghost"),
                   Btn(body, "Reset password", submit, "primary"))
        p2.bind("<Return>", submit)
        center(win)
        k.focus_set()

    def clear_log_dialog():
        def go(pw):
            try:
                do_clear_log(load_config(), pw)
            except PermissionError as ex:
                return str(ex)
            refresh_activity()
            toast("Activity log cleared.", "ok")
            return None
        password_dialog("Clear activity log", "Enter your password to erase the log.", "Clear", go,
                        danger=True)

    # ------------------------------------------------------------ vault actions
    def add_many(paths):
        paths = [p for p in paths if p]
        if not paths:
            return
        cfg = load_config()
        added, errors = 0, []
        for p in paths:
            try:
                it = add_item(cfg, p)
            except Exception as ex:  # noqa: BLE001
                errors.append(str(ex))
                continue
            added += 1
            if cfg["settings"]["hide_on_add"]:
                try:
                    hide_item(it)
                    log_event("hide", f"Hid {Path(it['path']).name}")
                except Exception as ex:  # noqa: BLE001
                    errors.append(str(ex))
        save_config(cfg)
        if errors:
            toast(errors[0] + (f"  (+{len(errors) - 1} more)" if len(errors) > 1 else ""), "err")
        elif cfg["settings"]["hide_on_add"]:
            toast(f"Added and hid {added} item{'s' if added != 1 else ''}.", "ok")
        else:
            toast(f"Added {added} item{'s' if added != 1 else ''}.", "ok")
        refresh_vault()

    def add_files():
        add_many(list(filedialog.askopenfilenames(parent=root, title="Choose files to protect")))

    def add_folder():
        add_many([filedialog.askdirectory(parent=root, title="Choose a folder to protect")])

    def hide_one(item_id):
        cfg = load_config()
        it = next((i for i in cfg["items"] if i["id"] == item_id), None)
        if not it:
            return
        try:
            hide_item(it)
            save_config(cfg)
            log_event("hide", f"Hid {Path(it['path']).name}")
            toast(f"Hid {Path(it['path']).name}.", "ok")
        except Exception as ex:  # noqa: BLE001
            toast(f"Could not hide: {ex}", "err")
        refresh_vault()

    def hide_everything():
        cfg = load_config()
        if not cfg["items"]:
            return
        n, errors = hide_all(cfg)
        if n:
            log_event("hide", f"Hid {n} item{'s' if n != 1 else ''}")
        if errors:
            toast("; ".join(errors), "err")
        else:
            toast(f"Hid {n} item{'s' if n != 1 else ''}." if n else "Everything is already hidden.", "ok")
        refresh_vault()

    def on_startup(value):
        try:
            (startup_enable if value else startup_disable)()
            W["sw_startup"].set(value)
            toast("Will hide automatically at startup." if value else "Startup hiding turned off.",
                  "ok" if value else "info")
        except Exception as ex:  # noqa: BLE001
            toast(f"Could not change startup setting: {ex}", "err")

    def toggle_setting(key, label):
        def handler(value):
            set_setting(key, value)
            W["sw_" + key].set(value)
            toast(f"{label}: {'on' if value else 'off'}.", "ok" if value else "info")
        return handler

    def set_auto_hide(value):
        set_setting("auto_hide_min", value)
        toast("Auto-hide turned off." if not value else
              f"Revealed items will re-hide after {value} min (while FileVault is open).", "ok")
        refresh_vault()

    # ------------------------------------------------------------ item options
    def item_options_dialog(item_id):
        if not any(i["id"] == item_id for i in load_config()["items"]):
            return

        def current(cfg=None):
            return _find_item(cfg or load_config(), item_id)

        win, body = modal("Item options")
        heading(body, short(Path(current()["path"]).name, 36),
                "Change how this item looks, and what takes its place on disk while it's hidden.")

        def finish(msg):
            win.destroy()
            toast(msg, "ok")
            refresh_vault()

        def change_icon():
            path = filedialog.askopenfilename(
                parent=win, title="Choose an icon image",
                filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.bmp *.ico *.icns"), ("All files", "*")])
            if not path:
                return
            try:
                set_item_icon(load_config(), current(), path)
            except Exception as ex:  # noqa: BLE001
                err.config(text=str(ex))
                return
            finish("Icon changed.")

        def reset_icon():
            try:
                set_item_icon(load_config(), current(), None)
            except Exception as ex:  # noqa: BLE001
                err.config(text=str(ex))
                return
            finish("Icon reset.")

        def with_password(title, sub, button, action, danger=False):
            def go(pw):
                try:
                    cfg = load_config()
                    authenticate(cfg, pw)
                    msg = action(cfg)
                except PermissionError as ex:
                    return str(ex)
                except Exception as ex:  # noqa: BLE001
                    return f"Error: {ex}"
                toast(msg, "ok")
                refresh_vault()
                return None
            password_dialog(title, sub, button, go, danger=danger)

        def set_standin(path):
            if not path:
                return

            def action(cfg):
                set_item_decoy(cfg, current(cfg), path)
                return "Stand-in set."
            with_password("Set stand-in",
                          "Enter your password. While this item is hidden, the stand-in will "
                          "sit in its place at the real location - opening that path, even "
                          "outside FileVault, shows the stand-in instead.",
                          "Set", action)

        def set_standin_file():
            set_standin(filedialog.askopenfilename(parent=win, title="Choose a stand-in file"))

        def set_standin_folder():
            set_standin(filedialog.askdirectory(parent=win, title="Choose a stand-in folder"))

        def remove_standin():
            def action(cfg):
                set_item_decoy(cfg, current(cfg), None)
                return "Stand-in removed."
            with_password("Remove stand-in", "Enter your password to remove it.",
                          "Remove", action, danger=True)

        def standin_buttons(p):
            row = tk.Frame(p, bg=C["card"])
            Btn(row, "File…", set_standin_file, "secondary", small=True).pack(side="left")
            Btn(row, "Folder…", set_standin_folder, "secondary", small=True).pack(side="left", padx=(6, 0))
            return row

        setting_card(body, "Custom icon", "Show your own picture for this item.",
                     control=lambda p: Btn(p, "Choose…", change_icon, "secondary", small=True))
        setting_card(body, "Default icon", "Go back to the normal icon.",
                     control=lambda p: Btn(p, "Reset", reset_icon, "ghost", small=True))
        setting_card(body, "Stand-in",
                     "While hidden, this takes the item's place at its real location - even if "
                     "opened directly. Pick a folder for a folder, a file for a file. "
                     "The item must be revealed first to set or change this.",
                     control=standin_buttons)
        setting_card(body, "Remove stand-in", "Go back to a plain hidden item with no stand-in.",
                     control=lambda p: Btn(p, "Remove…", remove_standin, "ghost", small=True))
        err = errlabel(body)
        button_row(body, Btn(body, "Close", win.destroy, "ghost"))
        center(win)

    # ------------------------------------------------------------ vault panel
    def meta_text(it, cfg):
        mins = cfg["settings"]["auto_hide_min"]
        if mins and item_state(it) == "visible" and it.get("revealed_at"):
            left = max(0, int(it["revealed_at"] + mins * 60 - time.time()))
            return f"Auto-hides in {left // 60}:{left % 60:02d}"
        return short(it["path"], 34)

    def build_row(parent, it, cfg):
        st = item_state(it)
        row = card(parent)
        row.pack(fill="x", pady=5)
        inner = tk.Frame(row, bg=C["card"], padx=12, pady=11)
        inner.pack(fill="x")
        icon = "📁" if (Path(it["path"]).is_dir() or Path(it.get("current_path") or "x").is_dir()) else "📄"
        tk.Label(inner, text=icon, bg=C["card"], fg=C["text"], font=F(20)).pack(side="left")
        mid = tk.Frame(inner, bg=C["card"])
        mid.pack(side="left", padx=10, fill="x", expand=True)
        tk.Label(mid, text=short(Path(it["path"]).name or it["path"], 26), bg=C["card"], fg=C["text"],
                 font=F(11, True), anchor="w").pack(fill="x")
        meta = tk.Label(mid, text=meta_text(it, cfg), bg=C["card"], fg=C["muted"], font=F(8),
                        anchor="w", justify="left")
        meta.pack(fill="x")
        W["meta"][it["id"]] = (meta, it)
        col = {"hidden": C["ok"], "visible": C["warn"], "missing": C["bad"]}[st]
        tk.Label(inner, text=st.upper(), bg=col, fg="#0b1020", font=F(8, True),
                 padx=7, pady=2).pack(side="left", padx=(6, 8))
        if st == "hidden":
            Btn(inner, "Reveal", lambda i=it["id"]: reveal_dialog([i]), "secondary", small=True).pack(side="left")
        else:
            b = Btn(inner, "Hide", lambda i=it["id"]: hide_one(i), "primary", small=True)
            b.pack(side="left")
            b.set_enabled(st == "visible")
        Btn(inner, "⋯", lambda i=it["id"]: item_options_dialog(i), "ghost", small=True).pack(side="left", padx=(4, 0))
        Btn(inner, "✕", lambda i=it["id"]: remove_dialog(i), "ghost", small=True).pack(side="left", padx=(4, 0))

    def refresh_vault():
        cfg = load_config()
        if cfg is None or "list" not in W:
            return
        for w in W["list"].winfo_children():
            w.destroy()
        W["meta"] = {}
        items = cfg["items"]
        states = [item_state(i) for i in items]
        hidden_n = states.count("hidden")
        W["summary"].config(text=(f"{len(items)} protected item{'s' if len(items) != 1 else ''}  ·  "
                                  f"{hidden_n} hidden") if items else "No protected items yet")
        if not items:
            empty = card(W["list"])
            empty.pack(fill="x", pady=5)
            tk.Label(empty, text="🗂", bg=C["card"], font=F(30), pady=10).pack(pady=(18, 0))
            tk.Label(empty, text="Nothing protected yet", bg=C["card"], fg=C["text"],
                     font=F(12, True)).pack()
            tk.Label(empty, text="Use “＋ Files” or “＋ Folder” above to add things you want to hide.",
                     bg=C["card"], fg=C["muted"], font=F(9), wraplength=360, pady=10).pack(pady=(0, 18))
        for it in items:
            build_row(W["list"], it, cfg)
        W["btn_hide_all"].set_enabled(any(s == "visible" for s in states))
        W["btn_reveal_all"].set_enabled(hidden_n > 0)

    def build_vault_panel(parent):
        panel = tk.Frame(parent, bg=C["bg"])
        top = tk.Frame(panel, bg=C["bg"])
        top.pack(fill="x")
        W["summary"] = tk.Label(top, text="", bg=C["bg"], fg=C["muted"], font=F(10), anchor="w")
        W["summary"].pack(side="left")
        Btn(top, "＋ Folder", add_folder, "secondary", small=True).pack(side="right")
        Btn(top, "＋ Files", add_files, "secondary", small=True).pack(side="right", padx=(0, 6))

        bottom = tk.Frame(panel, bg=C["bg"])
        bottom.pack(side="bottom", fill="x", pady=(12, 0))
        bottom.columnconfigure((0, 1), weight=1, uniform="a")
        W["btn_hide_all"] = Btn(bottom, "Hide all", hide_everything, "primary")
        W["btn_hide_all"].grid(row=0, column=0, sticky="ew", padx=(0, 6))
        W["btn_reveal_all"] = Btn(bottom, "Reveal all…", lambda: reveal_dialog(None), "secondary")
        W["btn_reveal_all"].grid(row=0, column=1, sticky="ew", padx=(6, 0))

        holder = tk.Frame(panel, bg=C["bg"])
        holder.pack(fill="both", expand=True, pady=(10, 0))
        canvas = tk.Canvas(holder, bg=C["bg"], highlightthickness=0)
        canvas.pack(fill="both", expand=True)
        inner = tk.Frame(canvas, bg=C["bg"])
        wid = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(wid, width=e.width))
        W["canvas"], W["list"], W["meta"] = canvas, inner, {}
        return panel

    # ------------------------------------------------------------ settings panel
    def setting_card(parent, title, sub, control=None, below=None):
        c = card(parent)
        c.pack(fill="x", pady=5)
        pad = tk.Frame(c, bg=C["card"], padx=16, pady=14)
        pad.pack(fill="x")
        row = tk.Frame(pad, bg=C["card"])
        row.pack(fill="x")
        txt = tk.Frame(row, bg=C["card"])
        txt.pack(side="left", fill="x", expand=True)
        tk.Label(txt, text=title, bg=C["card"], fg=C["text"], font=F(11, True), anchor="w").pack(fill="x")
        tk.Label(txt, text=sub, bg=C["card"], fg=C["muted"], font=F(9), anchor="w",
                 justify="left", wraplength=340).pack(fill="x", pady=(2, 0))
        if control is not None:
            control(row).pack(side="right", padx=(10, 0))
        if below is not None:
            below(pad).pack(fill="x", pady=(10, 0))

    def build_settings_panel(parent):
        panel = tk.Frame(parent, bg=C["bg"])
        s = load_config()["settings"]

        def switch_for(key, label, value=None):
            def make(p):
                sw = Switch(p, s[key] if value is None else value, toggle_setting(key, label))
                W["sw_" + key] = sw
                return sw
            return make

        def startup_switch(p):
            W["sw_startup"] = Switch(p, startup_is_enabled(), on_startup)
            return W["sw_startup"]

        setting_card(panel, "Hide at startup", "Automatically hide everything every time you sign in.",
                     startup_switch)
        setting_card(panel, "Hide items when added", "Hide a file or folder the moment you add it.",
                     switch_for("hide_on_add", "Hide on add"))
        setting_card(panel, "Hide when FileVault closes", "Re-hide everything as soon as you close this window.",
                     switch_for("hide_on_exit", "Hide on close"))
        setting_card(panel, "Require password to open FileVault",
                     "Anyone opening this app must enter your password first.",
                     switch_for("lock_app", "App lock"))
        setting_card(panel, "Open location after reveal",
                     "Show the item in Explorer / Finder right after revealing it.",
                     switch_for("open_after_reveal", "Open after reveal"))
        setting_card(panel, "Auto-hide after reveal",
                     "Re-hide revealed items after this long. Works while FileVault is open "
                     "(it can stay minimized).",
                     below=lambda p: Segmented(p, AUTO_HIDE_CHOICES, s["auto_hide_min"], set_auto_hide))
        return panel

    # ------------------------------------------------------------ security panel
    def build_security_panel(parent):
        panel = tk.Frame(parent, bg=C["bg"])

        def action_card(title, sub, label, cmd, kind="secondary"):
            setting_card(panel, title, sub, control=lambda p: Btn(p, label, cmd, kind, small=True))

        action_card("Change password", "Pick a new password. You'll need the current one.",
                    "Change…", change_password_dialog)
        action_card("New recovery key", "Generate a fresh key. The old one stops working.",
                    "Generate…", new_key_dialog)
        action_card("Forgot your password?", "Reset it using the recovery key you saved.",
                    "Reset…", forgot_dialog)
        c = card(panel)
        c.pack(fill="x", pady=5)
        pad = tk.Frame(c, bg=C["card"], padx=16, pady=14)
        pad.pack(fill="x")
        tk.Label(pad, text="Protection status", bg=C["card"], fg=C["text"], font=F(11, True),
                 anchor="w").pack(fill="x")
        W["sec_status"] = tk.Label(pad, text="", bg=C["card"], fg=C["muted"], font=F(9), anchor="w",
                                   justify="left", wraplength=420)
        W["sec_status"].pack(fill="x", pady=(2, 0))
        return panel

    def refresh_security():
        cfg = load_config()
        if not cfg or "sec_status" not in W:
            return
        failed = cfg.get("failed", 0)
        wait = int(cfg.get("locked_until", 0) - time.time())
        lines = [f"Failed attempts since last success: {failed}"]
        lines.append(f"Locked for another {wait}s." if wait > 0 else "Not locked out.")
        lines.append("After 3 wrong tries FileVault makes you wait, and the wait doubles each time.")
        W["sec_status"].config(text="\n".join(lines))

    # ------------------------------------------------------------ activity panel
    def build_activity_panel(parent):
        panel = tk.Frame(parent, bg=C["bg"])
        top = tk.Frame(panel, bg=C["bg"])
        top.pack(fill="x")
        tk.Label(top, text="Recent activity, including failed login attempts", bg=C["bg"],
                 fg=C["muted"], font=F(10)).pack(side="left")
        Btn(top, "Clear…", clear_log_dialog, "secondary", small=True).pack(side="right")
        txt = tk.Text(panel, bg=C["card"], fg=C["text"], relief="flat", font=(mono, 9), wrap="word",
                      padx=12, pady=10, highlightbackground=C["line"], highlightthickness=1,
                      state="disabled", cursor="arrow")
        txt.pack(fill="both", expand=True, pady=(10, 0))
        txt.tag_config("fail", foreground=C["bad"])
        txt.tag_config("reveal", foreground=C["ok"])
        txt.tag_config("hide", foreground=C["warn"])
        txt.tag_config("time", foreground=C["muted"])
        W["log_text"] = txt
        return panel

    def refresh_activity():
        txt = W.get("log_text")
        if txt is None:
            return
        txt.config(state="normal")
        txt.delete("1.0", "end")
        rows = read_log(300)
        if not rows:
            txt.insert("end", "No activity recorded yet.", "time")
        for ts, kind, detail in rows:
            tag = {"fail": "fail", "reveal": "reveal", "hide": "hide", "auto_hide": "hide"}.get(kind, "")
            txt.insert("end", fmt_time(ts) + "   ", "time")
            txt.insert("end", detail + "\n", tag)
        txt.config(state="disabled")

    # ------------------------------------------------------------ tabs + main
    def show_tab(key):
        W["tab"] = key
        for k, panel in W["panels"].items():
            panel.pack_forget()
        W["panels"][key].pack(fill="both", expand=True)
        for k, (lb, ul) in W["tabs"].items():
            lb.config(fg=C["text"] if k == key else C["muted"])
            ul.config(bg=C["accent"] if k == key else C["bg"])
        {"vault": refresh_vault, "security": refresh_security, "activity": refresh_activity}.get(
            key, lambda: None)()

    def tick():
        """Every 10s: auto-hide expired items and refresh the countdown text."""
        try:
            cfg = load_config()
            if cfg:
                mins = cfg["settings"]["auto_hide_min"]
                if mins:
                    now, changed = time.time(), False
                    for it in cfg["items"]:
                        ra = it.get("revealed_at")
                        if ra and now - ra >= mins * 60 and item_state(it) == "visible":
                            try:
                                hide_item(it)
                                log_event("auto_hide", f"Auto-hid {Path(it['path']).name}")
                                changed = True
                            except Exception:  # noqa: BLE001
                                pass
                    if changed:
                        save_config(cfg)
                        toast("Auto-hid revealed items.", "ok")
                        if W.get("tab") == "vault":
                            refresh_vault()
                    elif W.get("tab") == "vault":
                        for lbl, it in W.get("meta", {}).values():
                            lbl.config(text=meta_text(it, cfg))
        finally:
            root.after(10000, tick)

    def on_wheel(e):
        if W.get("tab") != "vault" or "canvas" not in W:
            return
        if e.num == 4:
            step = -2
        elif e.num == 5:
            step = 2
        else:
            step = -2 if e.delta > 0 else 2
        W["canvas"].yview_scroll(step, "units")

    def on_close():
        try:
            cfg = load_config()
            if cfg and cfg["settings"]["hide_on_exit"]:
                n, _ = hide_all(cfg, only_revealed=True)
                if n:
                    log_event("hide", f"Hid {n} item{'s' if n != 1 else ''} on exit")
        finally:
            root.destroy()

    def build_main():
        head = tk.Frame(root, bg=C["bg"])
        head.pack(fill="x", padx=28, pady=(24, 0))
        lock = tk.Label(head, text="🔒", bg=C["bg"], fg=C["text"], font=F(24), cursor="hand2")
        lock.pack(side="left")
        lock.bind("<Button-1>", _ghost_click)  # click it 5x fast on this screen. just try it
        ht = tk.Frame(head, bg=C["bg"])
        ht.pack(side="left", padx=12)
        tk.Label(ht, text="FileVault", bg=C["bg"], fg=C["text"], font=F(19, True), anchor="w").pack(fill="x")
        tk.Label(ht, text="Hide files and folders. Reveal them with a password.",
                 bg=C["bg"], fg=C["muted"], font=F(9), anchor="w").pack(fill="x")

        bar = tk.Frame(root, bg=C["bg"])
        bar.pack(fill="x", padx=24, pady=(16, 0))
        W["tabs"] = {}
        for key, label in (("vault", "Vault"), ("settings", "Settings"),
                           ("security", "Security"), ("activity", "Activity")):
            f = tk.Frame(bar, bg=C["bg"], cursor="hand2")
            f.pack(side="left", padx=(0, 20))
            lb = tk.Label(f, text=label, bg=C["bg"], fg=C["muted"], font=F(11, True), cursor="hand2")
            lb.pack()
            ul = tk.Frame(f, bg=C["bg"], height=3)
            ul.pack(fill="x", pady=(4, 0))
            for w in (f, lb):
                w.bind("<Button-1>", lambda e, k=key: show_tab(k))
            W["tabs"][key] = (lb, ul)
        tk.Frame(root, bg=C["line"], height=1).pack(fill="x", padx=24)

        W["toast"] = tk.Label(root, text="", bg=C["bg"], fg=C["muted"], font=F(9), wraplength=480, pady=8)
        W["toast"].pack(side="bottom", fill="x", pady=(0, 8))

        content = tk.Frame(root, bg=C["bg"])
        content.pack(fill="both", expand=True, padx=24, pady=(14, 0))
        W["panels"] = {
            "vault": build_vault_panel(content),
            "settings": build_settings_panel(content),
            "security": build_security_panel(content),
            "activity": build_activity_panel(content),
        }
        root.bind_all("<MouseWheel>", on_wheel)
        root.bind_all("<Button-4>", on_wheel)
        root.bind_all("<Button-5>", on_wheel)
        root.protocol("WM_DELETE_WINDOW", on_close)
        show_tab("vault")
        root.after(10000, tick)

    # ------------------------------------------------------------ gate screens
    def gate_shell(title, sub):
        gate = tk.Frame(root, bg=C["bg"], padx=40, pady=40)
        gate.pack(fill="both", expand=True)
        tk.Label(gate, text="🔒", bg=C["bg"], font=F(40)).pack(pady=(40, 6))
        tk.Label(gate, text=title, bg=C["bg"], fg=C["text"], font=F(20, True)).pack()
        tk.Label(gate, text=sub, bg=C["bg"], fg=C["muted"], font=F(10), wraplength=380,
                 justify="center").pack(pady=(6, 10))
        return gate

    def show_welcome():
        gate = gate_shell("Welcome to FileVault",
                          "Create a password. You'll use it to reveal anything you hide.")
        p1 = field(gate, "Choose a password", secret=True)
        strength_bar(gate, p1)
        p2 = field(gate, "Confirm password", secret=True)
        err = errlabel(gate)

        def submit(_=None):
            if len(p1.get()) < 4:
                err.config(text="Use at least 4 characters.")
            elif p1.get() != p2.get():
                err.config(text="The two passwords don't match.")
            else:
                key = do_setup(p1.get())
                gate.destroy()
                build_main()
                key_dialog(key)
        Btn(gate, "Create vault", submit, "primary").pack(fill="x", pady=(20, 0))
        p2.bind("<Return>", submit)
        p1.focus_set()

    def show_lock():
        gate = gate_shell("FileVault is locked", "Enter your password to continue.")
        e = field(gate, "Password", secret=True)
        err = errlabel(gate)

        def submit(_=None):
            try:
                authenticate(load_config(), e.get())
            except PermissionError as ex:
                err.config(text=str(ex))
                e.delete(0, "end")
                return
            log_event("app_open", "FileVault unlocked")
            gate.destroy()
            build_main()
        Btn(gate, "Unlock", submit, "primary").pack(fill="x", pady=(20, 0))
        Btn(gate, "Forgot password?", lambda: forgot_dialog(), "ghost").pack(fill="x", pady=(6, 0))
        e.bind("<Return>", submit)
        e.focus_set()

    cfg0 = load_config()
    if cfg0 is None:
        show_welcome()
    elif cfg0["settings"]["lock_app"]:
        show_lock()
    else:
        build_main()
    root.mainloop()


# ---------------------------------------------------------------- CLI
def _parse_bool(v: str) -> bool:
    if v.lower() in ("on", "true", "yes", "1"):
        return True
    if v.lower() in ("off", "false", "no", "0"):
        return False
    raise SystemExit(f"Expected on/off, got: {v}")


def _need_cfg():
    cfg = load_config()
    if not cfg:
        sys.exit("Nothing set up yet. Run: filevault.py add <path>")
    return cfg


def _new_password(prompt="New password: ") -> str:
    pw = getpass.getpass(prompt)
    if len(pw) < 4:
        sys.exit("Use at least 4 characters.")
    if pw != getpass.getpass("Confirm: "):
        sys.exit("Passwords do not match.")
    return pw


def main():
    ap = argparse.ArgumentParser(description="FileVault")
    ap.add_argument("--hide", action="store_true", help="hide everything silently (startup)")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("add"); s.add_argument("paths", nargs="+")
    sub.add_parser("list")
    s = sub.add_parser("hide"); s.add_argument("ids", nargs="*")
    s = sub.add_parser("reveal"); s.add_argument("ids", nargs="*")
    s = sub.add_parser("remove"); s.add_argument("id")
    sub.add_parser("passwd"); sub.add_parser("newkey"); sub.add_parser("recover")
    s = sub.add_parser("log"); s.add_argument("-n", type=int, default=20)
    s = sub.add_parser("set"); s.add_argument("key", choices=list(DEFAULT_SETTINGS)); s.add_argument("value")
    s = sub.add_parser("startup"); s.add_argument("mode", choices=["on", "off", "status"])
    s = sub.add_parser("icon"); s.add_argument("id"); s.add_argument("path", nargs="?")
    s = sub.add_parser("decoy"); s.add_argument("id"); s.add_argument("path", nargs="?")
    s = sub.add_parser("trick"); s.add_argument("action", choices=["set", "clear"])
    a = ap.parse_args()

    if a.hide:
        # Startup run: retry (drive may not be ready at login) and log the outcome.
        msg = "no vault configured"
        for _ in range(6):
            try:
                cfg = load_config()
                if not cfg:
                    break
                n, errors = hide_all(cfg)
                msg = f"hid {n} item(s)" + (f"; errors: {errors}" if errors else "")
                if not errors:
                    break
            except Exception as e:  # noqa: BLE001
                msg = f"error: {e!r}"
            time.sleep(5)
        log_event("startup", f"Startup run: {msg}")
        return
    if not a.cmd:
        return run_gui()

    if a.cmd == "startup":
        if a.mode == "status":
            print("Enabled:", startup_is_enabled())
            print("Command:", " ".join(_launcher_cmd()))
            return
        (startup_enable if a.mode == "on" else startup_disable)()
        print(f"Hide-at-startup {a.mode}.")
        return

    if a.cmd == "add":
        cfg = load_config()
        if not cfg:
            key = do_setup(_new_password("Create a password: "))
            print(f"\nRECOVERY KEY: {key}\nWrite it down. It is the only way to reset a forgotten password.\n")
            cfg = load_config()
        for p in a.paths:
            try:
                it = add_item(cfg, p)
                if cfg["settings"]["hide_on_add"]:
                    hide_item(it)
                    save_config(cfg)
                    log_event("hide", f"Hid {Path(it['path']).name}")
                print(f"[{it['id']}] {'hidden' if it.get('hidden') else 'added'}: {it['path']}")
            except Exception as e:  # noqa: BLE001
                print(f"skipped {p}: {e}")
        return

    if a.cmd == "recover":
        cfg = _need_cfg()
        try:
            nk = do_recover(cfg, input("Recovery key: "), _new_password())
            print(f"Password reset. NEW recovery key: {nk}")
        except PermissionError as e:
            sys.exit(str(e))
        return

    cfg = _need_cfg()
    try:
        if a.cmd == "list":
            if not cfg["items"]:
                print("No protected items.")
            for it in cfg["items"]:
                print(f"[{it['id']}] {item_state(it):8} {it['path']}")
        elif a.cmd == "hide":
            sel = [i for i in cfg["items"] if not a.ids or i["id"] in a.ids]
            errors = []
            for nothing in sel:  # bad var name i know, too lazy to rename it now
                try:
                    hide_item(nothing)
                    log_event("hide", f"Hid {Path(nothing['path']).name}")
                except Exception as e:  # noqa: BLE001
                    errors.append(str(e))
            save_config(cfg)
            print(f"Hid {len(sel) - len(errors)} item(s)." + (" Errors: " + "; ".join(errors) if errors else ""))
        elif a.cmd == "reveal":
            print(do_reveal(cfg, getpass.getpass("Password: "), a.ids or None))
        elif a.cmd == "remove":
            print(remove_item(cfg, getpass.getpass("Password: "), a.id))
        elif a.cmd == "passwd":
            old = getpass.getpass("Current password: ")
            do_change_password(cfg, old, _new_password())
            print("Password changed.")
        elif a.cmd == "newkey":
            print("NEW recovery key:", do_new_recovery_key(cfg, getpass.getpass("Password: ")))
        elif a.cmd == "log":
            for ts, kind, detail in read_log(a.n):
                print(f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))}  {detail}")
        elif a.cmd == "set":
            if a.key in ("auto_hide_min",):
                val = int(a.value)
                if val < 0:
                    sys.exit("Must be 0 or more.")
            else:
                val = _parse_bool(a.value)
            set_setting(a.key, val)
            print(f"{a.key} = {val}")
        elif a.cmd == "icon":
            set_item_icon(cfg, _find_item(cfg, a.id), a.path)
            print("Icon set." if a.path else "Icon reset.")
        elif a.cmd == "decoy":
            authenticate(cfg, getpass.getpass("Password: "))
            set_item_decoy(cfg, _find_item(cfg, a.id), a.path)
            print("Stand-in set." if a.path else "Stand-in removed.")
        elif a.cmd == "trick":
            authenticate(cfg, getpass.getpass("Password: "))
            if a.action == "set":
                set_access_code(cfg, _new_password("Access code: "))
                print("Access code set.")
            else:
                set_access_code(cfg, None)
                print("Access code removed.")
    except PermissionError as e:
        sys.exit(str(e))
    except (KeyError, ValueError, RuntimeError, OSError) as e:
        sys.exit(str(e))


if __name__ == "__main__":
    main()
