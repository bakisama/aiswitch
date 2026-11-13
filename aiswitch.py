#!/usr/bin/env python3
"""aiswitch - a TcNo-Account-Switcher-style switcher for AI tool logins.

It freezes the login state of a tool (Claude Code, Codex CLI, Gemini CLI,
Claude Desktop, ...) per account, and swaps a saved copy back in on demand.
No passwords are ever asked for or stored by this tool: it only moves around
the credential files / OS keychain items the tools already create themselves.

Pure Python 3.9+, standard library only, no compiled code: it runs on any CPU
architecture. OS-specific pieces (fcntl, msvcrt, ctypes.windll, winreg) are
imported lazily so the module imports everywhere. OS tags used in the platform
registry: "darwin" (macOS), "windows" (native Windows), "linux" (Linux, the
BSDs, WSL, Android/Termux and other POSIX systems; they share XDG paths).

Platforms are defined by a small config (see DEFAULT_PLATFORMS, or run
`aiswitch init` and edit ~/.aiswitch/platforms.json).
"""
from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import copy
import datetime as dt
import errno
import glob
import hashlib
import json
import os
import platform as _platform
import re
import secrets
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
from pathlib import Path

VERSION = "0.3.0"
SNAPSHOT_SCHEMA = 2      # meta.json format (1 = legacy, path-derived keychain refs)
CONFIG_SCHEMA = 1        # platforms.json format (absent = legacy whole-entry replacement)
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$")
WIN_RESERVED = {"con", "prn", "aux", "nul", "conin$", "conout$",
                *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
KEEP_BACKUPS = 5
OSES = ("darwin", "linux", "windows")
VAULT_PREFIX = "aiswitch:"
DEBUG = False

CLAUDE_DIR = "{env:CLAUDE_CONFIG_DIR|~/.claude}"
CLAUDE_JSON = "{env:CLAUDE_CONFIG_DIR|~}/.claude.json"
CODEX_DIR = "{env:CODEX_HOME|~/.codex}"
GEMINI_DIR = "{env:GEMINI_CLI_HOME|~}/.gemini"
DESKTOP_DIR = {
    "darwin": "~/Library/Application Support/Claude",
    "windows": "{claude_desktop_win}",          # MSIX (Store) dir if present, else %APPDATA%\Claude
    "linux": "{xdg_config}/Claude",
}


def _desk(name, typ, rel, **kw):
    return {"name": name, "type": typ, "path": {o: f"{b}/{rel}" for o, b in DESKTOP_DIR.items()}, **kw}


def _web(label, url):
    return {"label": f"{label} (web, via browser profile)", "kind": "browser", "browser": "auto", "url": url}


# Artifact types:
#   file       copy one file
#   dir        copy a directory tree
#   json_keys  copy only some top-level keys of a JSON file (rest of the file is left alone)
#   keychain   an OS secret-store item: macOS Keychain generic password, Windows Credential
#              Manager generic credential (service = TargetName), or freedesktop Secret Service
#              item (service = "service" attribute). Optional "account" scopes it to one item.
# "primary": true marks the artifacts that mean "a login exists".
# "identity" lets aiswitch tell which saved account is currently live (so refreshed
# tokens are written back to the right snapshot, never the wrong one).
# "path"/"service"/"account" are templates (see resolve_path); "path" and "service" may also be
# dicts {"darwin": ..., "linux": ..., "windows": ...}; an artifact with no entry for this OS is
# skipped. "enabled_if" names a predicate in PREDICATES (artifact skipped when it is false).
# "preflight" names a check in PREFLIGHTS run before save/use/new.
# Process matching: "processes" = executable names, "process_paths" = substrings of the
# executable path (both "strong": used to quit apps), "process_match" = substrings of the whole
# command line (detection only), "process_exclude" = executable-path substrings never matched.
DEFAULT_PLATFORMS = {
    "claude-code": {
        "label": "Claude Code",
        "aliases": ["cc"],
        "kind": "login",
        "processes": ["claude"],
        "process_match": ["@anthropic-ai/claude-code"],
        "process_exclude": ["/Claude.app/", "/WindowsApps/Claude_", "/AnthropicClaude/",
                            "/claude-desktop", "/Claude Helper"],
        "login_hint": "run `claude`, then /login",
        "artifacts": [
            {"name": "keychain", "type": "keychain", "service": "Claude Code-credentials{claude_kc_suffix}",
             "primary": True, "os": ["darwin"]},
            # Linux/Windows store; on macOS the fallback when the Keychain refuses the write.
            {"name": "credentials", "type": "file", "path": f"{CLAUDE_DIR}/.credentials.json",
             "primary": True},
            {"name": "account", "type": "json_keys", "path": CLAUDE_JSON, "keys": ["oauthAccount"]},
        ],
        "identity": [
            {"file": CLAUDE_JSON, "path": "oauthAccount.emailAddress"},
            {"file": CLAUDE_JSON, "path": "oauthAccount.organizationUuid"},
        ],
    },
    "codex": {
        "label": "Codex CLI",
        "aliases": ["cx"],
        "kind": "login",
        "processes": ["codex"],
        "process_match": ["@openai/codex"],
        "login_hint": "run `codex login`",
        "preflight": "codex",
        "artifacts": [
            {"name": "auth", "type": "file", "path": f"{CODEX_DIR}/auth.json", "primary": True},
            {"name": "keyring", "type": "keychain", "service": "Codex Auth",
             "account": "cli|{codex_home_hash}", "primary": True, "os": ["darwin"],
             "enabled_if": "codex_keyring"},
        ],
        "identity": [
            # in keyring mode auth.json is gone; the keyring item holds the same JSON
            {"file": f"{CODEX_DIR}/auth.json", "artifact": "keyring", "path": "tokens.id_token",
             "jwt_claim": "email"},
            {"file": f"{CODEX_DIR}/auth.json", "artifact": "keyring", "path": "tokens.account_id"},
        ],
    },
    "gemini": {
        "label": "Gemini CLI",
        "aliases": ["gem"],
        "kind": "login",
        "processes": ["gemini"],
        "process_match": ["@google/gemini-cli"],
        "login_hint": "run `gemini` and choose 'Login with Google'",
        "preflight": "gemini",
        "artifacts": [
            {"name": "oauth", "type": "file", "path": f"{GEMINI_DIR}/oauth_creds.json", "primary": True},
            {"name": "accounts", "type": "file", "path": f"{GEMINI_DIR}/google_accounts.json"},
            # GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true: OS keychain via keytar, or an encrypted
            # file fallback (machine-bound key). Both are swapped when that mode is on.
            {"name": "encrypted", "type": "file", "path": f"{GEMINI_DIR}/gemini-credentials.json",
             "primary": True, "enabled_if": "gemini_encrypted"},
            {"name": "keychain", "type": "keychain", "account": "main-account", "primary": True,
             "service": {"darwin": "gemini-cli-oauth", "linux": "gemini-cli-oauth",
                         "windows": "gemini-cli-oauth/main-account"},
             "enabled_if": "gemini_keychain"},
        ],
        "identity": [
            {"file": f"{GEMINI_DIR}/google_accounts.json", "path": "active"},
        ],
    },
    "claude-desktop": {
        "label": "Claude Desktop (experimental)",
        "aliases": ["cd"],
        "kind": "app",
        "app": "Claude",
        "processes": {"darwin": ["Claude"], "linux": ["claude-desktop"], "windows": []},
        "process_paths": {"darwin": ["/Claude.app/Contents/MacOS/Claude"],
                          "windows": ["/WindowsApps/Claude_", "/AnthropicClaude/"],
                          "linux": ["/claude-desktop/", "/usr/bin/claude-desktop"]},
        "launch": {"linux": ["claude-desktop"]},
        "login_hint": "open Claude and sign in",
        "artifacts": [
            _desk("cookies", "file", "Cookies"),
            _desk("cookies-journal", "file", "Cookies-journal"),
            _desk("net-cookies", "file", "Network/Cookies"),
            _desk("net-cookies-journal", "file", "Network/Cookies-journal"),
            _desk("local-storage", "dir", "Local Storage"),
            _desk("session-storage", "dir", "Session Storage"),
            _desk("indexeddb", "dir", "IndexedDB"),
            _desk("oauth-cache", "json_keys", "config.json", keys=["oauth:tokenCache"]),
        ],
    },
    "claude-web": _web("Claude", "https://claude.ai"),
    "chatgpt-web": _web("ChatGPT", "https://chatgpt.com"),
    "gemini-web": _web("Gemini", "https://gemini.google.com"),
}


# --------------------------------------------------------------------------- utils
class Fatal(Exception):
    def __init__(self, msg, code="error"):
        super().__init__(msg)
        self.code = code


def die(msg, code="error"):
    raise Fatal(msg, code)


_COLOR = None
_WARNED = set()


def _enable_vt():
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        from ctypes import wintypes
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.GetStdHandle.argtypes = [wintypes.DWORD]
        k.GetStdHandle.restype = wintypes.HANDLE          # pointer-sized on x64/ARM64
        k.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k.GetConsoleMode.restype = wintypes.BOOL
        k.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k.SetConsoleMode.restype = wintypes.BOOL
        h = k.GetStdHandle(wintypes.DWORD(-11 & 0xFFFFFFFF))
        if not h or h == wintypes.HANDLE(-1).value:
            return False
        mode = wintypes.DWORD()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False


def color_ok():
    global _COLOR
    if _COLOR is None:
        _COLOR = (not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"
                  and hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and _enable_vt())
    return _COLOR


def c(txt, code):
    return f"\033[{code}m{txt}\033[0m" if color_ok() and sys.stdout.isatty() else str(txt)


GLYPHS = {"on": ("●", "*"), "off": ("○", "o"), "ok": ("✓", "+"), "no": ("·", "-")}


def glyph(name):
    fancy, plain = GLYPHS[name]
    enc = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        fancy.encode(enc)
        return fancy
    except (UnicodeEncodeError, LookupError):
        return plain


def warn(msg):
    with contextlib.suppress(OSError):
        print(c("warning:", "33"), msg, file=sys.stderr)


def warn_once(key, msg):
    if key not in _WARNED:
        _WARNED.add(key)
        warn(msg)


def setup_console():
    for s in (sys.stdout, sys.stderr):
        with contextlib.suppress(Exception):
            s.reconfigure(errors="replace")


def host_os():
    forced = os.environ.get("AISWITCH_FORCE_OS")
    if forced:
        return forced
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform in ("win32", "cygwin", "msys"):
        return "windows"
    return "linux"      # linux, android, freebsd*, openbsd*, netbsd*, sunos, aix, ...


def is_wsl():
    if host_os() != "linux" or not sys.platform.startswith("linux"):
        return False
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop"):
        return True
    with contextlib.suppress(Exception):
        return "microsoft" in _platform.uname().release.lower()
    return False


def sandbox_kind():
    """Name of the PID-namespaced sandbox we run in (processes outside it are invisible)."""
    if os.path.exists("/.flatpak-info"):
        return "flatpak"
    if os.path.exists("/run/.containerenv"):
        return "podman/toolbox"
    if os.path.exists("/.dockerenv"):
        return "docker"
    if os.environ.get("container"):
        return os.environ["container"]
    return None


def is_store_python():
    """Microsoft Store Python virtualises writes under %APPDATA%/%LOCALAPPDATA% - also when
    running from a venv created from it (the base interpreter is still the packaged one)."""
    if sys.platform != "win32":
        return False
    probe = " ".join([sys.executable, os.path.realpath(sys.executable), sys.prefix,
                      getattr(sys, "base_prefix", ""), getattr(sys, "base_exec_prefix", ""),
                      getattr(sys, "_base_executable", "") or ""])
    return "WindowsApps" in probe or "PythonSoftwareFoundation.Python" in probe


def home():
    # On native Windows $HOME is often set by Git Bash/MSYS to something the tools don't use;
    # the tools themselves use %USERPROFILE%, which is what Path.home() returns there.
    if sys.platform == "win32":
        return Path.home()
    return Path(os.environ.get("HOME") or str(Path.home()))


_TOKEN_RE = re.compile(r"\{([a-z_]+)(?::([^{}]*))?\}")
_VAR_RE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")


def _msix_claude_dir(env, home_dir):
    """Claude Desktop from the Microsoft Store/MSIX keeps its Roaming data virtualised under
    %LOCALAPPDATA%\\Packages\\Claude_<publisher>\\LocalCache\\Roaming\\Claude."""
    local = (env.get("LOCALAPPDATA") or home_dir + "/AppData/Local").replace("\\", "/")
    for d in sorted(glob.glob(glob.escape(local) + "/Packages/Claude_*/LocalCache/Roaming/Claude")):
        if os.path.exists(os.path.join(d, "Local State")):
            return d.replace("\\", "/")
    return (env.get("APPDATA") or home_dir + "/AppData/Roaming").replace("\\", "/") + "/Claude"


def resolve_path(tpl, os_tag, env, home_dir):
    """Template resolver for paths and secret-store names (pure apart from two FS probes noted
    below, so every OS tag is testable on any runner).

    tpl: string, or dict keyed by OS tag (optionally "default"); returns None if this
    OS has no entry. Tokens: ~, {home}, {appdata}, {localappdata}, {xdg_config},
    {chrome_config}, {env:VAR|default}, $VAR / ${VAR}, {claude_kc_suffix} (Claude Code's
    per-config-dir Keychain suffix), {codex_home_hash} (resolves symlinks of CODEX_HOME),
    {claude_desktop_win} (probes for the MSIX data dir). Returns '/'-separated strings."""
    if isinstance(tpl, dict):
        tpl = tpl.get(os_tag, tpl.get("default"))
    if tpl is None:
        return None
    home_dir = str(home_dir).replace("\\", "/")
    home_dir = home_dir.rstrip("/") or "/"

    def join_home(rest):
        rest = rest.lstrip("/\\")
        if not rest:
            return home_dir
        return ("/" if home_dir == "/" else home_dir + "/") + rest

    def tilde(s):
        if s == "~":
            return home_dir
        if s.startswith("~/") or s.startswith("~\\"):
            return join_home(s[2:])
        return s

    def env_or(var, fallback):
        v = env.get(var)
        return v.replace("\\", "/").rstrip("/") if v else fallback

    def tok(m):
        name, arg = m.group(1), m.group(2)
        if name == "home":
            return home_dir
        if name == "appdata":
            return env_or("APPDATA", join_home("AppData/Roaming"))
        if name == "localappdata":
            return env_or("LOCALAPPDATA", join_home("AppData/Local"))
        if name == "xdg_config":
            return env_or("XDG_CONFIG_HOME", join_home(".config"))
        if name == "chrome_config":
            return env_or("CHROME_CONFIG_HOME", env_or("XDG_CONFIG_HOME", join_home(".config")))
        if name == "env" and arg:
            var, _, default = arg.partition("|")
            v = env.get(var.strip())
            return v.replace("\\", "/") if v else tilde(default)
        if name == "claude_kc_suffix":
            # Claude Code: "Claude Code-credentials-<sha256(CLAUDE_CONFIG_DIR as set)[:8]>"
            v = env.get("CLAUDE_CONFIG_DIR")
            if not v:
                return ""
            return "-" + hashlib.sha256(unicodedata.normalize("NFC", v).encode("utf-8")).hexdigest()[:8]
        if name == "codex_home_hash":
            # Codex keyring account "cli|<sha256(canonical CODEX_HOME)[:16]>"
            ch = env.get("CODEX_HOME") or join_home(".codex")
            with contextlib.suppress(OSError):
                ch = os.path.realpath(ch)
            return hashlib.sha256(ch.encode("utf-8")).hexdigest()[:16]
        if name == "claude_desktop_win":
            return _msix_claude_dir(env, home_dir)
        raise Fatal(f"unknown template token '{m.group(0)}' in '{tpl}'")

    s = tilde(str(tpl))
    s = _TOKEN_RE.sub(tok, s)
    s = _VAR_RE.sub(lambda m: env.get(m.group(1) or m.group(2), m.group(0)), s)
    return tilde(s)


def expand_str(tpl):
    return resolve_path(tpl, host_os(), os.environ, home())


def expand(tpl):
    p = expand_str(tpl)
    return None if p is None else Path(p)


def root():
    return Path(os.environ.get("AISWITCH_HOME") or (home() / ".aiswitch"))


def now():
    return dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None


def dump_json(obj, indent=2):
    return json.dumps(obj, indent=indent, ensure_ascii=False).encode("utf-8")


def get_path(obj, dotted):
    for part in dotted.split("."):
        if isinstance(obj, dict) and part in obj:
            obj = obj[part]
        else:
            return None
    return obj


def jwt_claim(token, claim):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get(claim)
    except Exception:
        return None


# ------------------------------------------------------------------ file operations
_CHMOD_SOFT = {errno.EPERM, errno.EINVAL, getattr(errno, "ENOTSUP", 95), getattr(errno, "EOPNOTSUPP", 95)}


def _retry(fn, *a):
    """Windows: AV scanners / indexers briefly hold files open; retry PermissionError."""
    delay = 0.05
    for i in range(8):
        try:
            return fn(*a)
        except PermissionError:
            if sys.platform != "win32" or i == 7:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 0.8)


def _clear_readonly(p):
    """Windows: os.replace/unlink fail with ACCESS_DENIED on read-only targets."""
    if sys.platform == "win32":
        with contextlib.suppress(OSError):
            st_ = os.lstat(p)
            if not st_.st_mode & stat.S_IWRITE:
                os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
                return True
    return False


def replace_file(src, dst):
    if os.path.lexists(dst):
        _clear_readonly(dst)
    _retry(os.replace, str(src), str(dst))


def is_link(p):
    """Symlink, or an NTFS junction (which os.path.islink does not report)."""
    p = str(p)
    if os.path.islink(p):
        return True
    if sys.platform == "win32":
        isj = getattr(os.path, "isjunction", None)
        if isj is not None:
            return isj(p)
        with contextlib.suppress(OSError):
            return getattr(os.lstat(p), "st_reparse_tag", 0) == getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
    return False


def real_target(p):
    """Dotfile managers symlink credential files; write/delete the file the link points at."""
    p = Path(p)
    return Path(os.path.realpath(p)) if is_link(p) else p


def _chmod(path, mode):
    try:
        os.chmod(path, mode)
    except OSError as e:
        if e.errno not in _CHMOD_SOFT:
            raise
        warn_once("chmod", f"cannot set permissions on {path} ({e.strerror}); the filesystem has "
                  "no Unix permissions, so saved credentials may be readable by others")


def atomic_write_bytes(dest, data, mode=0o600):
    dest = real_target(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".aiswitch-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            with contextlib.suppress(OSError):
                os.fsync(f.fileno())
        if sys.platform != "win32":
            _chmod(tmp, mode)                  # before it becomes visible under its real name
        replace_file(tmp, dest)
        if sys.platform == "win32" and not mode & 0o200:
            _chmod(dest, mode)                 # read-only attribute only after the rename
    except BaseException:
        _clear_readonly(tmp)
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def remove_file(p):
    p = real_target(p)
    if os.path.lexists(p):
        _clear_readonly(p)
    with contextlib.suppress(FileNotFoundError):
        _retry(os.unlink, str(p))


def rmtree_force(p):
    """rmtree that clears read-only flags (Windows), removes links/junctions themselves rather
    than their targets, and tolerates vanished entries."""
    p = str(p)
    if not os.path.lexists(p):
        return
    if is_link(p):
        with contextlib.suppress(FileNotFoundError):
            if os.path.isdir(p) and not os.path.islink(p):
                os.rmdir(p)                    # junction
            else:
                os.unlink(p)
        return

    def fix(func, path, _exc):
        if not os.path.lexists(path):
            return
        if func is os.path.islink:             # rmtree met a junction inside the tree
            os.rmdir(path)
            return
        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD | (stat.S_IEXEC if os.path.isdir(path) else 0))
        func(path)
    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=fix)
    else:
        shutil.rmtree(p, onerror=fix)


def _ignore_for_copy(src, names):
    skip = {n for n in names if n == "LOCK" or n.startswith("Singleton")}
    if sys.platform == "win32":                # don't follow junctions into unrelated trees
        skip |= {n for n in names if not os.path.islink(os.path.join(src, n)) and is_link(os.path.join(src, n))}
    return skip


def copy_tree(src, dst):
    shutil.copytree(src, dst, symlinks=True, ignore=_ignore_for_copy)


def hidden_sibling(p, tag):
    p = Path(p)
    return p.parent / f".{p.name}.{tag}-{secrets.token_hex(4)}"


def _looks_like_store(r):
    try:
        entries = set(os.listdir(r))
    except OSError:
        return False
    return not entries or bool(entries & {".aiswitch", "state.json", "snapshots", "backups",
                                          "platforms.json", ".lock"})


def check_privileges():
    """Refuse to run as root with a user's $HOME (sudo): files would become root-owned."""
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return
    if os.environ.get("AISWITCH_ALLOW_ROOT"):
        return
    owner = None
    with contextlib.suppress(OSError):
        owner = os.stat(home()).st_uid
    if os.environ.get("SUDO_UID") or (owner is not None and owner != 0):
        die("don't run aiswitch with sudo / as root: it would make your credential files "
            "root-owned and unreadable by your tools. Run it as your normal user "
            "(set AISWITCH_ALLOW_ROOT=1 if you really manage root's own logins).")


def ensure_root():
    r = root()
    rr = Path(os.path.realpath(r))
    if rr == Path(os.path.realpath(home())) or rr == Path(rr.anchor):
        die(f"refusing to use {r} as the aiswitch store (it is your home directory or a drive root)")
    existed = r.exists()
    if existed and not _looks_like_store(r):
        die(f"{r} exists and does not look like an aiswitch store; refusing to use it. "
            "Point AISWITCH_HOME at an empty or new directory.")
    r.mkdir(parents=True, exist_ok=True)
    if not (r / ".aiswitch").exists():
        atomic_write_bytes(r / ".aiswitch", b"aiswitch store\n", 0o600)
    if os.name == "posix":
        _chmod(r, 0o700)
        with contextlib.suppress(OSError):
            if os.stat(r).st_mode & 0o077:
                warn_once("store-perms", f"{r} is on a filesystem without Unix permissions (e.g. "
                          "/mnt/c in WSL, FAT, SMB); saved credentials there are readable by others. "
                          "Set AISWITCH_HOME to a directory on a native filesystem.")


def _try_lock(f):
    if os.name == "nt":
        import msvcrt
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError as e:
            if e.errno in (errno.EACCES, errno.EDEADLK):
                return False
            die(f"cannot lock {f.name}: {e.strerror or e}")
    import fcntl
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as e:
        if e.errno in (errno.EWOULDBLOCK, errno.EAGAIN, errno.EACCES):
            return False
        die(f"cannot lock {f.name}: {e.strerror or e} (the filesystem may not support locks, "
            "e.g. NFS without a lock manager; set AISWITCH_HOME to a local directory)")


def _unlock(f):
    with contextlib.suppress(OSError):
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_UN)


@contextlib.contextmanager
def lock():
    f = open(root() / ".lock", "a+")
    pidf = root() / ".lock.pid"
    try:
        deadline = time.monotonic() + float(os.environ.get("AISWITCH_LOCK_WAIT", "3"))
        while not _try_lock(f):
            if time.monotonic() >= deadline:
                try:
                    holder = pidf.read_text().strip() or "?"
                except OSError:
                    holder = "?"
                die(f"another aiswitch is running (pid {holder}); wait for it to finish", "locked")
            time.sleep(0.1)
        try:
            with contextlib.suppress(OSError):
                pidf.write_text(str(os.getpid()))
            yield
        finally:
            with contextlib.suppress(OSError):
                pidf.unlink()
            _unlock(f)
    finally:
        f.close()


@contextlib.contextmanager
def signals_deferred():
    """While rolling back, don't let a second Ctrl-C / SIGTERM / SIGHUP abort us half-way."""
    import signal
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    saved = {}
    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            with contextlib.suppress(OSError, ValueError):
                saved[sig] = signal.signal(sig, signal.SIG_IGN)
    try:
        yield
    finally:
        for sig, h in saved.items():
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, h)


def install_signal_handlers():
    """SIGTERM/SIGHUP (kill, closing the terminal) unwind like Ctrl-C, so rollbacks run."""
    import signal

    def _raise(signum, frame):
        raise KeyboardInterrupt
    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            with contextlib.suppress(OSError, ValueError):
                signal.signal(sig, _raise)


# --------------------------------------------------------------------------- processes
INTERPRETERS = {"node", "nodejs", "bun", "deno", "python", "python3", "pythonw", "py"}
ARCH_SUFFIX_RE = r"-(?:x86_64|amd64|aarch64|arm64|armv7l?|armhf|i[36]86|riscv64|ppc64le|s390x)-[a-z0-9_.-]+"
Proc = collections.namedtuple("Proc", "pid exe argv cmdline")
_PROC_CACHE = None
_PROC_TIME = 0.0
PROC_PROVIDER = None     # tests: a callable returning [Proc | (pid, exe, argv)] or None
NO_WINDOW = 0x08000000   # CREATE_NO_WINDOW: no console flash under pythonw.exe


def _base(path):
    return re.split(r"[\\/]", path.rstrip("\\/"))[-1] if path else ""


def _fold():
    return host_os() == "windows"      # NTFS-style case-insensitive names; macOS names keep case


def _norm(name):
    if _fold():
        name = name.lower()
    for ext in (".exe", ".cmd", ".bat", ".js", ".mjs", ".cjs", ".py"):
        if name.lower().endswith(ext):
            return name[: -len(ext)]
    return name


def _npath(s):
    s = (s or "").replace("\\", "/")
    return s.lower() if _fold() else s


def _run_quiet(cmd, timeout=15, env=None):
    kw = {}
    if sys.platform == "win32":
        kw["creationflags"] = NO_WINDOW
    try:
        r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           timeout=timeout, encoding="utf-8", errors="replace", env=env, **kw)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _procs_linux():
    uid = os.getuid()
    out = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit() or int(pid) == os.getpid():
            continue
        try:
            if os.stat(f"/proc/{pid}").st_uid != uid:
                continue
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
            try:
                exe = os.readlink(f"/proc/{pid}/exe")
                if exe.endswith(" (deleted)"):
                    exe = exe[:-10]
            except OSError:
                exe = argv[0] if argv else ""
            if not argv:
                with open(f"/proc/{pid}/comm", "rb") as f:
                    exe = exe or f.read().decode("utf-8", "replace").strip()
        except OSError:
            continue
        out.append(Proc(int(pid), exe, argv, " ".join(argv)))
    return out


def _procs_ps():
    """BSD/macOS/busybox ps. -ww and no COLUMNS so long command lines are not truncated; stdin
    detached so BSD ps can't take the width from the terminal. comm is the full executable path
    on macOS (it may contain spaces, so it is the last column and never split); argv[0] comes
    from args (it can differ from the executable: process.title, symlinks, exec -a)."""
    uid = str(os.getuid())
    env = {k: v for k, v in os.environ.items() if k != "COLUMNS"}
    env["LC_ALL"] = "C"

    def ps(fields):
        cmd = ["ps", "-A", "-ww"] + [x for f in fields for x in ("-o", f + "=")]
        out = _run_quiet(cmd, env=env)
        if out is None:                        # busybox ps rejects -ww
            out = _run_quiet([c_ for c_ in cmd if c_ != "-ww"], env=env)
        return out

    comm = ps(["pid", "uid", "comm"])
    args = ps(["pid", "args"])
    if comm is None:
        return None
    argmap = {}
    for line in (args or "").splitlines():
        parts = line.strip().split(None, 1)
        if parts and parts[0].isdigit():
            argmap[int(parts[0])] = parts[1] if len(parts) > 1 else ""
    out = []
    for line in comm.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit() or parts[1] != uid:
            continue
        pid, exe = int(parts[0]), parts[2]
        if pid == os.getpid():
            continue
        cmdline = argmap.get(pid) or exe
        if cmdline.startswith(exe):            # macOS: argv[0] is the (space-containing) exec path
            argv = [exe] + cmdline[len(exe):].split()
        else:
            argv = cmdline.split() or [exe]
        out.append(Proc(pid, exe, argv, cmdline))
    return out


def _win_tool(*rel):
    return os.path.join(os.environ.get("SystemRoot") or r"C:\Windows", "System32", *rel)


def _pwsh():
    """PowerShell 7 from its absolute install location only (never the cwd / relative PATH)."""
    for base in (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles")):
        if base:
            p = os.path.join(base, "PowerShell", "7", "pwsh.exe")
            if os.path.isfile(p):
                return p
    return None


def _procs_windows():
    """Returns (procs, partial). Absolute System32 paths (no cwd/PATH hijack)."""
    tasklist = _win_tool("tasklist.exe")
    me = os.getpid()

    def parse(out):
        got = {}
        for line in (out or "").splitlines():
            cols = re.findall(r'"([^"]*)"', line)
            if len(cols) >= 2 and cols[1].isdigit():
                got[int(cols[1])] = cols[0]
        return got

    user = os.environ.get("USERNAME", "")
    mine = parse(_run_quiet([tasklist, "/FO", "CSV", "/NH", "/FI", f"USERNAME eq {user}"])) if user else {}
    if me not in mine:                         # filter didn't match our own token user: don't trust it
        mine = parse(_run_quiet([tasklist, "/FO", "CSV", "/NH"]))
        if me not in mine:
            return None, False
    script = ("[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
              "Get-CimInstance Win32_Process | Select-Object ProcessId,ExecutablePath,CommandLine | "
              "ConvertTo-Json -Compress")
    cmdlines, ok = {}, False
    for shell in (_win_tool("WindowsPowerShell", "v1.0", "powershell.exe"), _pwsh()):
        if not shell or not os.path.exists(shell):
            continue
        ps = _run_quiet([shell, "-NoProfile", "-NonInteractive", "-Command", script], timeout=25)
        try:
            data = json.loads(ps.lstrip("﻿")) if ps else None
        except ValueError:
            data = None
        if data is None:
            continue
        for p in data if isinstance(data, list) else [data]:
            with contextlib.suppress(TypeError, ValueError, KeyError, AttributeError):
                cmdlines[int(p["ProcessId"])] = (p.get("ExecutablePath") or "", p.get("CommandLine") or "")
        ok = True
        break
    out = []
    for pid, image in mine.items():
        if pid == me:
            continue
        path, cl = cmdlines.get(pid, ("", ""))
        argv = [a[1:-1] if len(a) > 1 and a[0] == a[-1] == '"' else a
                for a in re.findall(r'"[^"]*"|\S+', cl)] if cl else [path or image]
        out.append(Proc(pid, path or image, argv, cl or path or image))
    # Without command lines, node-hosted CLIs look like bare node.exe: "not found" means unknown.
    return out, not ok


class ProcTable:
    def __init__(self, procs, partial=False, pathless=False):
        self.procs = None if procs is None else [p if isinstance(p, Proc) else
                                                 Proc(p[0], p[1], list(p[2]), " ".join(p[2]))
                                                 for p in procs]
        self.partial = partial         # True: processes outside our view exist (sandbox, no cmdlines)
        self.pathless = pathless       # True: entries may be bare image names (Windows tasklist fallback)

    @staticmethod
    def _has_path(p):
        return any(sep in (p.exe or "") or sep in (p.argv[0] if p.argv else "") for sep in ("/", "\\"))

    def _hit(self, p, names, paths, match, exclude):
        exe, argv0 = _npath(p.exe), _npath(p.argv[0] if p.argv else "")
        if any(_npath(x) in exe or _npath(x) in argv0 for x in exclude):
            return None
        hit = None
        for cand in {_norm(_base(p.exe)), _norm(_base(p.argv[0] if p.argv else ""))} - {""}:
            for n in names:
                n = _norm(n)
                if cand == n or re.fullmatch(re.escape(n) + ARCH_SUFFIX_RE, cand):
                    hit = "strong"
            if not hit and cand in INTERPRETERS:
                script = next((a for a in p.argv[1:] if not a.startswith("-")), "")
                if script and _norm(_base(script)) in {_norm(n) for n in names}:
                    hit = "strong"
        if hit and exclude and self.pathless and not self._has_path(p):
            # e.g. a bare "claude.exe" image name: the desktop-app path excludes can't be checked
            return "ambiguous"
        if hit:
            return hit
        if any(_npath(x) in exe or _npath(x) in argv0 for x in paths):
            return "strong"
        if match and any(_npath(x) in _npath(p.cmdline) for x in match):
            return "weak"
        return None

    def find(self, names=(), paths=(), match=(), exclude=()):
        """[(pid, 'strong'|'weak'|'ambiguous', argv)] or None when detection is unavailable."""
        if self.procs is None:
            return None
        out = []
        for p in self.procs:
            h = self._hit(p, names, paths, match, exclude)
            if h:
                out.append((p.pid, h, p.argv))
        return out

    def matches(self, name, patterns=()):
        hits = self.find([name], (), patterns)
        return None if hits is None else [h[0] for h in hits if h[1] != "ambiguous"]

    def running(self, name, patterns=()):
        hits = self.find([name], (), patterns)
        if hits is None:
            return None
        if any(h[1] != "ambiguous" for h in hits):
            return True
        return None if (self.partial or hits) else False


def proc_table(refresh=False, max_age=None):
    global _PROC_CACHE, _PROC_TIME
    fresh = max_age is not None and _PROC_CACHE is not None and time.monotonic() - _PROC_TIME < max_age
    if _PROC_CACHE is None or (refresh and not fresh):
        partial = False
        if PROC_PROVIDER is not None:
            procs = PROC_PROVIDER()
        elif host_os() == "windows":
            procs, partial = _procs_windows() if sys.platform == "win32" else (None, False)
        elif os.path.isfile("/proc/self/cmdline") and sys.platform.startswith(("linux", "android")):
            procs = _procs_linux()
            partial = bool(sandbox_kind())
        elif hasattr(os, "getuid"):
            procs = _procs_ps()
        else:
            procs = None
        _PROC_CACHE = ProcTable(procs, partial, pathless=partial and host_os() == "windows")
        _PROC_TIME = time.monotonic()
    return _PROC_CACHE


def _per_os(v, default=()):
    if isinstance(v, dict):
        v = v.get(host_os(), v.get("default", default))
    return list(v or default)


def proc_spec(pcfg):
    names = _per_os(pcfg.get("processes"))
    paths = _per_os(pcfg.get("process_paths"))
    if not names and not paths and pcfg.get("app") and "processes" not in pcfg:
        names = [pcfg["app"]]
    return {"names": names, "paths": paths, "match": _per_os(pcfg.get("process_match")),
            "exclude": _per_os(pcfg.get("process_exclude"))}


def running_state(pcfg, pt=None):
    """Return (list of running process names, unknown: bool)."""
    pt = pt or proc_table()
    spec = proc_spec(pcfg)
    hits = pt.find(**spec)
    if hits is None:
        return [], bool(spec["names"] or spec["paths"])
    if any(h[1] != "ambiguous" for h in hits):
        label = (spec["names"] or [pcfg.get("app") or pcfg["label"]])[0]
        return [label], False
    return [], bool(hits) or (pt.partial and bool(spec["names"] or spec["paths"]))


def running_pids(pcfg, pt=None):
    pt = pt or proc_table()
    return [h[0] for h in (pt.find(**proc_spec(pcfg)) or []) if h[1] != "ambiguous"]


def _quit_targets(pcfg):
    """PIDs safe to ask to quit: strong (executable) matches only, never Electron helpers
    (they exit with the main process), never ourselves, our parent or our process group."""
    hits = proc_table(refresh=True).find(**proc_spec(pcfg)) or []
    skip = {os.getpid()}
    with contextlib.suppress(AttributeError, OSError):
        skip.add(os.getppid())
    pgrp = None
    with contextlib.suppress(AttributeError, OSError):
        pgrp = os.getpgrp()
    out = []
    for pid, kind, argv in hits:
        if kind != "strong" or pid in skip or any(a.startswith("--type=") for a in argv):
            continue
        if pgrp is not None:
            with contextlib.suppress(OSError):
                if os.getpgid(pid) == pgrp:
                    continue
        out.append(pid)
    return out


def quit_app(pcfg):
    app = pcfg.get("app")
    if host_os() == "darwin" and app:
        r = subprocess.run(["osascript", "-e", f'tell application "{app}" to quit'],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return
        err = (r.stderr or "").strip()
        if "-1743" in err or "Not authorized" in err:
            die(f"macOS did not allow this terminal to quit {app}. Allow it in System Settings > "
                f"Privacy & Security > Automation, or quit {app} yourself and retry.")
        warn(f"could not ask {app} to quit ({err or 'osascript failed'}); sending it SIGTERM")
    for pid in _quit_targets(pcfg):
        if host_os() == "windows":
            subprocess.run([_win_tool("taskkill.exe"), "/PID", str(pid), "/T"], capture_output=True,
                           creationflags=NO_WINDOW if sys.platform == "win32" else 0)
        else:
            import signal
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)


def wait_until_quit(pcfg, timeout=15.0):
    """True once the app is definitely gone. 'Unknown' (detection failed on a poll) is never
    taken as 'quit'."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(0.5)
        hits = proc_table(refresh=True).find(**proc_spec(pcfg))
        # Gone = a working scan with no match at all (a partial view still saw the app before,
        # so no match now means it exited); a failed scan or an ambiguous match is not "gone".
        if hits is not None and not hits:
            return True
    return False


def _launch_argv(cmd):
    """Only the executable (and args that look like paths/tokens) are template-expanded; URLs
    and flags pass through untouched."""
    if isinstance(cmd, str):
        if host_os() == "windows":
            cmd = [a[1:-1] if len(a) > 1 and a[0] == a[-1] == '"' else a for a in shlex.split(cmd, posix=False)]
        else:
            cmd = shlex.split(cmd)
    out = []
    for i, a in enumerate(cmd):
        if i == 0 or a.startswith("~") or _TOKEN_RE.search(a):
            a = expand_str(a)
        out.append(a)
    return out


def launch_app(pcfg):
    """Returns True if a launch was started."""
    try:
        if host_os() == "darwin" and pcfg.get("app"):
            r = subprocess.run(["open", "-a", pcfg["app"]], capture_output=True, text=True)
            if r.returncode != 0:
                warn(f"could not open {pcfg['app']}: {r.stderr.strip()}")
                return False
            return True
        cmd = pcfg.get("launch")
        if isinstance(cmd, dict):
            cmd = cmd.get(host_os())
        if not cmd:
            warn(f"don't know how to launch {pcfg['label']} on this OS; start it yourself")
            return False
        if host_os() == "windows" and isinstance(cmd, str) and (re.match(r"^[a-z][a-z0-9+.-]+:", cmd, re.I)
                                                            or cmd.lower().startswith("shell:")):
            os.startfile(cmd)  # noqa  (URL / shell:AppsFolder target)
            return True
        argv = _launch_argv(cmd)
        if host_os() == "windows" and isinstance(cmd, str) and len(argv) == 1:
            os.startfile(argv[0])  # noqa
            return True
        _spawn_detached(argv)
        return True
    except (OSError, ValueError, Fatal) as e:
        warn(f"could not launch {pcfg['label']}: {e}")
        return False


def _spawn_detached(cmd):
    kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        kw["creationflags"] = 0x00000008 | 0x00000200   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    return subprocess.Popen(cmd, **kw)


# --------------------------------------------------------------------- secret stores
class SecretStore:
    """OS secret store. Items are addressed by `service`, optionally narrowed by `account`
    (account=None means "the item for this service"; "" means an item without an account).
    account(service, account=None) -> the item's account, or None if definitely absent.
    read(service, account=None)    -> {"account", "secret"[, "meta"]}, or None if definitely
                                      absent. "meta" is an opaque JSON-able dict of backend
                                      properties (attributes, encoding, persistence) needed to
                                      recreate the item exactly; it travels live -> vault -> live.
    write(service, account, secret, meta=None)                  create or update in place.
    replace(service, account, secret, meta=None, exclusive=True) write, then (exclusive) remove
                                      other items of the service. Write first, delete after.
    delete(service, account=None)  -> True if something was deleted, False if absent.
    Any other failure (locked keychain, denied prompt, no session bus, no GUI) raises Fatal - it
    must never be reported as "absent", or aiswitch would skip a backup and overwrite a login."""

    name = "abstract"
    max_secret = None          # bytes, if the backend has a hard cap

    def delete_all(self, service, account=None):
        for _ in range(20):
            if not self.delete(service, account):
                return
        die(f"could not remove all secret-store items for '{service}'", "keychain")

    def replace(self, service, account, secret, meta=None, exclusive=True):
        self.write(service, account, secret, meta)
        if exclusive:
            for _ in range(20):
                other = self._other_account(service, account)
                if other is None:
                    return
                self.delete(service, other)
            die(f"could not remove stale secret-store items for '{service}'", "keychain")

    def _other_account(self, service, account):
        return None


class MemoryStore(SecretStore):
    """In-process store for tests: {service: {account: {"secret", "meta"}}}."""
    name = "memory"

    def __init__(self):
        self.items = {}
        self.fail = set()       # ops to fail, for tests: {"read", "write", "delete"}

    def _chk(self, op):
        if op in self.fail:
            die(f"simulated keychain failure on {op}", "keychain")

    def _pick(self, service, account):
        d = self.items.get(service) or {}
        if account is None:
            return next(iter(d.items()), None)
        return (account, d[account]) if account in d else None

    def account(self, service, account=None):
        self._chk("read")
        got = self._pick(service, account)
        return None if got is None else got[0]

    def read(self, service, account=None):
        self._chk("read")
        got = self._pick(service, account)
        if got is None:
            return None
        out = {"account": got[0], "secret": got[1]["secret"]}
        if got[1].get("meta"):
            out["meta"] = got[1]["meta"]
        return out

    def write(self, service, account, secret, meta=None):
        self._chk("write")
        if self.max_secret is not None and len(secret.encode("utf-8")) > self.max_secret:
            die(f"secret for '{service}' is too large for this store", "keychain")
        self.items.setdefault(service, {})[account if account is not None else ""] = \
            {"secret": secret, **({"meta": meta} if meta else {})}

    def _other_account(self, service, account):
        return next((a for a in self.items.get(service) or {} if a != account), None)

    def delete(self, service, account=None):
        self._chk("delete")
        got = self._pick(service, account)
        if got is None:
            return False
        del self.items[service][got[0]]
        if not self.items[service]:
            del self.items[service]
        return True

    # test helpers
    def put(self, service, account, secret):
        self.items.setdefault(service, {})[account] = {"secret": secret}

    def get(self, service, account=None):
        got = self._pick(service, account)
        return None if got is None else got[1]["secret"]


class FileStore(SecretStore):
    """A plain directory (AISWITCH_KEYCHAIN_DIR), for tests and experiments only."""
    name = "file"

    def __init__(self, d):
        self.d = Path(d)

    def _f(self, service):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", service)[:60]
        return self.d / f"{safe}-{hashlib.sha1(service.encode()).hexdigest()[:10]}.json"

    def _load(self, service):
        f = self._f(service)
        try:
            raw = f.read_bytes()
        except FileNotFoundError:
            return []
        except OSError as e:
            die(f"cannot read secret file {f}: {e}", "keychain")
        data = self._decode(raw, f)
        if isinstance(data, dict) and "items" in data:
            data = data["items"]
        elif isinstance(data, dict):                 # 0.2 format: one item
            data = [data]
        if not isinstance(data, list) or not all(isinstance(i, dict) and "secret" in i for i in data):
            die(f"unreadable secret file {f}", "keychain")
        return data

    def _decode(self, raw, f):
        try:
            return json.loads(raw.decode("utf-8-sig"))
        except ValueError:
            die(f"unreadable secret file {f}", "keychain")

    def _encode(self, obj):
        return dump_json(obj, None)

    def _save(self, service, items):
        f = self._f(service)
        if items:
            atomic_write_bytes(f, self._encode({"items": items}))
        else:
            remove_file(f)

    def _pick(self, items, account):
        for i in items:
            if account is None or i.get("account", "") == account:
                return i
        return None

    def account(self, service, account=None):
        it = self._pick(self._load(service), account)
        return None if it is None else it.get("account", "")

    def read(self, service, account=None):
        it = self._pick(self._load(service), account)
        if it is None:
            return None
        out = {"account": it.get("account", ""), "secret": it["secret"]}
        if it.get("meta"):
            out["meta"] = it["meta"]
        return out

    def write(self, service, account, secret, meta=None):
        account = account if account is not None else ""
        items = [i for i in self._load(service) if i.get("account", "") != account]
        items.append({"account": account, "secret": secret, **({"meta": meta} if meta else {})})
        self._save(service, items)

    def _other_account(self, service, account):
        return next((i.get("account", "") for i in self._load(service)
                     if i.get("account", "") != account), None)

    def delete(self, service, account=None):
        items = self._load(service)
        it = self._pick(items, account)
        if it is None:
            return False
        items.remove(it)
        self._save(service, items)
        return True


class MacKeychain(SecretStore):
    """macOS Keychain via /usr/bin/security (absolute path: a `security` earlier on PATH must
    not receive secrets, and Keychain ACLs trust that exact binary).
    Exit 44 (errSecItemNotFound) means absent; every other non-zero exit is a hard error.
    Passwords are read with -g (the -w form prints non-printable data as bare hex, which is
    indistinguishable from a hex secret). Secrets are written through `security -i` on stdin,
    hex encoded, so they never appear in a process argv visible to `ps`. `security -i` reads
    commands into a 4096-byte buffer and silently splits longer lines, so longer secrets are
    never sent that way: they use argv (with a warning) unless AISWITCH_NO_ARGV_SECRETS=1.
    Accounts: None = unspecified (any item of the service); "" = the item whose account is
    empty/<NULL>; both are kept distinct (-a "" is passed for "")."""
    name = "macos-keychain"
    NOT_FOUND = 44
    SECURITY = "/usr/bin/security"
    LINE_MAX = 4000

    def __init__(self):
        self.used_argv_fallback = False

    def _sec(self, args, stdin=None):
        if not os.path.exists(self.SECURITY):
            die(f"{self.SECURITY} not found - the keychain features need macOS", "keychain")
        try:
            return subprocess.run([self.SECURITY, *args], input=stdin.encode("utf-8") if stdin else None,
                                  capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            die("`security` timed out (is a keychain prompt waiting for an answer?). Nothing was "
                "changed.", "keychain")

    @staticmethod
    def _txt(b):
        return (b or b"").decode("utf-8", "replace")

    @staticmethod
    def _a(account):
        return ["-a", account] if account is not None else []

    def _fail(self, what, service, r):
        die(f"keychain {what} for '{service}' failed (security exit {r.returncode}: "
            f"{self._txt(r.stderr).strip() or 'no message'}). The keychain may be locked, access was "
            "denied, or there is no GUI session (SSH).", "keychain")

    @staticmethod
    def _parse_attr(out, attr):
        m = re.search(r'^\s*"' + re.escape(attr) + r'"<blob>=(.*)$', out, re.M)
        if not m:
            return None
        v = m.group(1).strip()
        if v == "<NULL>":
            return ""
        h = re.match(r"^0x([0-9A-Fa-f]+)", v)
        if h:
            return bytes.fromhex(h.group(1)).decode("utf-8", "surrogateescape")
        q = re.match(r'^"(.*)"$', v)
        return q.group(1) if q else None

    @classmethod
    def _parse_acct(cls, out):
        return cls._parse_attr(out, "acct")

    @staticmethod
    def _parse_pw(err):
        m = re.search(r"^password: ?(.*)$", err, re.M)
        if not m:
            return None
        v = m.group(1).rstrip("\r")
        if v == "":
            return ""
        h = re.match(r"^0x([0-9A-Fa-f]+)(?:\s|$)", v)
        if h:
            try:
                return bytes.fromhex(h.group(1)).decode("utf-8")
            except UnicodeDecodeError:
                die("keychain item holds binary (non-UTF-8) data; not supported", "keychain")
        q = re.match(r'^"(.*)"$', v)
        return q.group(1) if q else None

    def _find(self, service, account, with_pw):
        r = self._sec(["find-generic-password", "-s", service] + self._a(account) + (["-g"] if with_pw else []))
        if r.returncode == self.NOT_FOUND:
            return None
        if r.returncode != 0:
            self._fail("lookup", service, r)
        out = self._txt(r.stdout) + "\n" + self._txt(r.stderr)
        acct = self._parse_acct(out)
        if acct is None:
            die(f"could not parse the keychain item for '{service}' (unexpected `security` "
                "output); nothing was changed", "keychain")
        pw = None
        if with_pw:
            pw = self._parse_pw(self._txt(r.stderr))
            if pw is None:
                die(f"could not parse the keychain password for '{service}'; nothing was changed",
                    "keychain")
        return acct, pw

    def account(self, service, account=None):
        got = self._find(service, account, False)
        return None if got is None else got[0]

    def read(self, service, account=None):
        got = self._find(service, account, True)
        return None if got is None else {"account": got[0], "secret": got[1]}

    def _secret_of(self, service, account):
        got = self._find(service, account, True)
        return None if got is None else got[1]

    def accounts(self, service):
        """Accounts of every generic-password item of `service`, from an attribute-only
        `dump-keychain` (no -d: no passwords read, no prompts). None if unavailable."""
        r = self._sec(["dump-keychain"])
        if r.returncode != 0:
            return None
        out = []
        for block in re.split(r'(?m)^keychain: ', self._txt(r.stdout)):
            if 'class: "genp"' in block and self._parse_attr(block, "svce") == service:
                a = self._parse_attr(block, "acct")
                if a is not None:
                    out.append(a)
        return out

    @staticmethod
    def _q(s):
        if s is None or any(ch in s for ch in '"\\\n\r'):
            return None
        return f'"{s}"'

    def write(self, service, account, secret, meta=None):
        if account is None:                      # update whichever item exists, keeping its account
            account = self.account(service)
        qs, qa = self._q(service), self._q(account) if account is not None else ""
        line = None
        if qs and qa is not None:
            line = (f"add-generic-password -U -s {qs}" + (f" -a {qa}" if account is not None else "")
                    + f" -X {secret.encode('utf-8').hex()}\n")
        if line and len(line.encode("utf-8")) < self.LINE_MAX:
            r = self._sec(["-i"], line)
            if self._secret_of(service, account) == secret:
                return
            err = self._txt(r.stderr).strip()
            if err:
                # `security` reported a real error (ACL denial, bad keychain): retrying the same
                # write with the secret on argv would only expose it.
                die(f"keychain write for '{service}' failed ({err})", "keychain")
            why = "the stdin write did not verify"
        elif line:
            why = f"the secret ({len(secret)} bytes) is too long for `security -i`"
        else:
            why = "the service/account name contains a quote, backslash or newline"
        if os.environ.get("AISWITCH_NO_ARGV_SECRETS"):
            die(f"keychain write for '{service}' cannot go through stdin ({why}) and "
                "AISWITCH_NO_ARGV_SECRETS is set; nothing was written.", "keychain")
        self.used_argv_fallback = True
        warn_once("kc-argv", f"{why}; passing the secret on the `security` command line instead "
                             "(briefly visible to other processes of your user via `ps`)")
        r = self._sec(["add-generic-password", "-U", "-s", service] + self._a(account) + ["-w", secret])
        if r.returncode != 0:
            self._fail("write", service, r)
        if self._secret_of(service, account) != secret:
            die(f"keychain write for '{service}' did not verify", "keychain")

    def replace(self, service, account, secret, meta=None, exclusive=True):
        if account is None:
            account = self.account(service)
        self.write(service, account, secret)                 # write first ...
        if not exclusive:
            return
        mine = account if account is not None else ""
        others = self.accounts(service)
        if others is None:                                   # no dump: peel off first-found items
            for _ in range(20):
                a = self.account(service)
                if a is None or a == mine:
                    break
                self.delete(service, a)
            warn_once("kc-enum", f"could not list keychain items (security dump-keychain failed); other "
                      f"accounts' items of '{service}' may remain")
            return
        for a in others:                                     # ... delete the other accounts after
            if a != mine:
                self.delete(service, a)
        left = [a for a in (self.accounts(service) or []) if a != mine]
        if left:
            warn(f"could not remove other keychain items of '{service}' (accounts: {', '.join(left)})")

    def delete(self, service, account=None):
        r = self._sec(["delete-generic-password", "-s", service] + self._a(account))
        if r.returncode == self.NOT_FOUND:
            return False
        if r.returncode != 0:
            self._fail("delete", service, r)
        return True


class SecretServiceStore(SecretStore):
    """freedesktop Secret Service (GNOME Keyring, KWallet, KeePassXC, ...) via `secret-tool`
    (libsecret-tools). `service` is the item's "service" attribute; the account is its
    "username" (keyring-rs, Python keyring) or "account" (keytar) attribute. Secrets travel on
    stdin/stdout only. `lookup` and `clear` exit 1 silently both for "no match" and for a locked
    item whose unlock prompt was dismissed, so existence and removal are always confirmed with
    `search --all` (which lists locked items too).
    Note: keyring-rs "persistent" clients (e.g. Codex on Linux) also cache secrets in the
    kernel keyutils keyring, so swapping only the Secret Service item does not reach them."""
    name = "secret-service"
    ACCT_KEYS = ("username", "account", "user")
    META_ATTR = "aiswitch-meta"
    max_secret = 8191                 # secret-tool truncates stdin at 8192 bytes

    def __init__(self, vault=False):
        self.vault = vault
        self._exe = None

    def _tool(self):
        if self._exe:
            return self._exe
        exe = shutil.which("secret-tool")
        if not exe:
            die("`secret-tool` not found; install it (Debian/Ubuntu: libsecret-tools; Fedora, Arch, "
                "Alpine, FreeBSD: libsecret). Nothing was changed.", "keychain")
        rt = os.environ.get("XDG_RUNTIME_DIR")
        if not (os.environ.get("DBUS_SESSION_BUS_ADDRESS") or (rt and os.path.exists(os.path.join(rt, "bus")))
                or os.environ.get("DISPLAY")):
            die("no D-Bus session bus, so the Secret Service (GNOME Keyring / KWallet / KeePassXC) "
                "is unreachable - typical over SSH, in containers, WSL or cron. Run aiswitch in your "
                "desktop session. Nothing was changed.", "keychain")
        self._exe = exe
        return exe

    @staticmethod
    def _pairs(attrs):
        out = []
        for k, v in attrs.items():
            k, v = str(k), str(v)
            if not k or k.startswith("-") or v.startswith("-"):
                die(f"attribute {k!r}={v!r} cannot be passed to secret-tool (leading '-')", "keychain")
            out += [k, v]
        return out

    def _run(self, args, stdin=None):
        try:
            return subprocess.run([self._tool(), *args], input=stdin,
                                  stdin=None if stdin is not None else subprocess.DEVNULL,
                                  capture_output=True, timeout=60)
        except subprocess.TimeoutExpired:
            die("`secret-tool` timed out (is an unlock prompt waiting?). Nothing was changed.", "keychain")
        except OSError as e:
            die(f"cannot run secret-tool: {e}", "keychain")

    def _fail(self, what, service, msg):
        die(f"secret service {what} for '{service}' failed ({(msg or '').strip() or 'no message'}). "
            "The keyring may be locked, the unlock prompt dismissed, or no keyring daemon is "
            "running.", "keychain")

    def _search(self, attrs):
        """(number of matching items, (attrs, label) of the single match or None)."""
        r = self._run(["search", "--all", *self._pairs(attrs)])
        out, err = r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
        if r.returncode != 0:
            self._fail("search", attrs.get("service", "?"), err)
        n = len(re.findall(r"^\[/[^\]\n]*\]$", out, re.M))
        if n != 1:
            return n, None
        # xdg:schema is deliberately not tracked: `search` prints it inconsistently (it can be
        # missing from one call to the next), and `secret-tool store` always sets it itself.
        got = {k: v for k, v in re.findall(r"^attribute\.(.+?) = (.*)$", err, re.M) if k != "xdg:schema"}
        label = re.search(r"^label = (.*)$", out, re.M)
        if not all(got.get(k) == str(v) for k, v in attrs.items()):
            self._fail("search", attrs.get("service", "?"), "could not parse `secret-tool search` output")
        return 1, (got, label.group(1) if label else "")

    def _find(self, service, account):
        base = {"service": service}
        tries = [base] if account is None else [{**base, k: account} for k in self.ACCT_KEYS]
        for attrs in tries:
            n, got = self._search(attrs)
            if n == 1:
                return got
            if n > 1:
                die(f"several Secret Service items match service={service!r}"
                    + (f" and account {account!r}" if account is not None else "")
                    + "; set \"account\" for this artifact in platforms.json", "keychain")
        return None

    def _acct(self, attrs):
        for k in self.ACCT_KEYS:
            if k in attrs:
                return k, attrs[k]
        return "username", ""

    def account(self, service, account=None):
        got = self._find(service, account)
        return None if got is None else self._acct(got[0])[1]

    def read(self, service, account=None):
        got = self._find(service, account)
        if got is None:
            return None
        attrs, label = got
        r = self._run(["lookup", *self._pairs(attrs)])
        if r.returncode != 0:           # the item exists, so silence means locked / dismissed
            self._fail("read", service, r.stderr.decode("utf-8", "replace") or "item exists but is locked")
        try:
            secret = r.stdout.decode("utf-8")
        except UnicodeDecodeError:
            die(f"secret for '{service}' is not UTF-8 text; not supported", "keychain")
        if self.vault:
            try:
                meta = json.loads(attrs.get(self.META_ATTR) or "null")
            except ValueError:
                die(f"corrupt {self.META_ATTR} on saved item '{service}'", "keychain")
        else:
            meta = {"kind": self.name, "attrs": attrs, "label": label}
        out = {"account": self._acct(attrs)[1], "secret": secret}
        if meta:
            out["meta"] = meta
        return out

    def _target(self, service, account, meta):
        if self.vault:
            attrs = {"service": service, "username": account or "", "application": "aiswitch"}
            if meta:
                attrs[self.META_ATTR] = json.dumps(meta, separators=(",", ":"), sort_keys=True)
            return attrs, f"aiswitch saved copy ({service})"
        m = meta if isinstance(meta, dict) and meta.get("kind") == self.name else {}
        attrs = {k: v for k, v in (m.get("attrs") or {}).items() if k != "xdg:schema"}
        label = m.get("label")
        if not attrs:
            prior = self._find(service, account)
            if prior:
                attrs, label = dict(prior[0]), label or prior[1]
        attrs["service"] = service
        # Only set an account attribute the item already has (or a non-empty account): an item
        # created without one must be recreated without one.
        if any(k in attrs for k in self.ACCT_KEYS) or account:
            attrs[self._acct(attrs)[0]] = account or ""
        return attrs, label or (f"{service} ({account})" if account else service)

    def _store(self, service, attrs, label, secret):
        data = secret.encode("utf-8")
        if len(data) > self.max_secret:
            die(f"secret for '{service}' is {len(data)} bytes; secret-tool accepts at most "
                f"{self.max_secret}. Nothing was changed.", "keychain")
        r = self._run(["store", f"--label={label}", *self._pairs(attrs)], stdin=data)
        if r.returncode != 0:
            self._fail("write", service, r.stderr.decode("utf-8", "replace"))
        chk = self._run(["lookup", *self._pairs(attrs)])
        if chk.returncode != 0 or chk.stdout != data:
            die(f"secret service write for '{service}' did not verify", "keychain")

    def _clear(self, service, attrs):
        r = self._run(["clear", *self._pairs(attrs)])
        err = r.stderr.decode("utf-8", "replace").strip()
        if r.returncode != 0 and err:
            self._fail("delete", service, err)
        if self._search(attrs)[0]:    # exit 1 + silence also means "locked, prompt dismissed"
            self._fail("delete", service, "the item is still there (locked keyring?)")

    def write(self, service, account, secret, meta=None):
        attrs, label = self._target(service, account, meta)
        self._store(service, attrs, label, secret)

    def replace(self, service, account, secret, meta=None, exclusive=True):
        attrs, label = self._target(service, account, meta)
        prior = self._find(service, None if exclusive else account)
        prior = prior[0] if prior and prior[0] != attrs else None
        # When one attribute set contains the other, the two operations overlap: `clear prior`
        # would also delete the new item (prior <= attrs), and `store attrs` replaces the old
        # item in place (attrs <= prior), which a later `clear prior` would then delete. In both
        # cases the old item goes first; its secret is kept to put it back if the store fails.
        early = prior is not None and (prior.items() <= attrs.items() or attrs.items() <= prior.items())
        if early:
            r = self._run(["lookup", *self._pairs(prior)])
            old = r.stdout if r.returncode == 0 else None
            self._clear(service, prior)
            try:
                self._store(service, attrs, label, secret)
            except BaseException:
                if old is not None:
                    with contextlib.suppress(Fatal):
                        self._run(["store", f"--label={label}", *self._pairs(prior)], stdin=old)
                raise
        else:
            self._store(service, attrs, label, secret)
            if prior is not None:
                try:
                    self._clear(service, prior)
                except Fatal:
                    with contextlib.suppress(Fatal):  # back to how it was: only the prior item
                        self._clear(service, attrs)
                    raise
        chk = self._run(["lookup", *self._pairs(attrs)])                 # the outcome, not the steps
        if chk.returncode != 0 or chk.stdout != secret.encode("utf-8"):
            die(f"secret service item '{service}' is not in place after the switch", "keychain")

    def delete(self, service, account=None):
        got = self._find(service, account)
        if got is None:
            return False
        self._clear(service, got[0])
        return True


_WINCRED = None


def _wincred():
    """advapi32 Cred* bindings (lazy; Windows only). WinDLL = stdcall on x86; explicit
    argtypes/restype keep pointers full width on x64/ARM64."""
    global _WINCRED
    if _WINCRED is None:
        import ctypes
        from ctypes import wintypes

        class FILETIME(ctypes.Structure):
            _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

        class CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
            _fields_ = [("Keyword", wintypes.LPWSTR), ("Flags", wintypes.DWORD),
                        ("ValueSize", wintypes.DWORD), ("Value", ctypes.POINTER(ctypes.c_ubyte))]

        class CREDENTIALW(ctypes.Structure):
            _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD),
                        ("TargetName", wintypes.LPWSTR), ("Comment", wintypes.LPWSTR),
                        ("LastWritten", FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
                        ("Persist", wintypes.DWORD), ("AttributeCount", wintypes.DWORD),
                        ("Attributes", ctypes.POINTER(CREDENTIAL_ATTRIBUTEW)),
                        ("TargetAlias", wintypes.LPWSTR), ("UserName", wintypes.LPWSTR)]

        PCRED = ctypes.POINTER(CREDENTIALW)
        adv = ctypes.WinDLL("advapi32", use_last_error=True)
        adv.CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(PCRED)]
        adv.CredReadW.restype = wintypes.BOOL
        adv.CredWriteW.argtypes = [PCRED, wintypes.DWORD]
        adv.CredWriteW.restype = wintypes.BOOL
        adv.CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
        adv.CredDeleteW.restype = wintypes.BOOL
        adv.CredFree.argtypes = [ctypes.c_void_p]
        adv.CredFree.restype = None
        _WINCRED = collections.namedtuple("WinCred", "ct wt CRED ATTR PCRED adv")(
            ctypes, wintypes, CREDENTIALW, CREDENTIAL_ATTRIBUTEW, PCRED, adv)
    return _WINCRED


class WinCredStore(SecretStore):
    """Windows Credential Manager, CRED_TYPE_GENERIC. `service` is the exact TargetName shown by
    `cmdkey /list` (keyring-rs: "<user>.<service>"; keytar: "<service>/<account>"; Python keyring:
    "<service>"); the account is UserName. Target names are unique, so an account-scoped
    artifact only ever sees a credential whose UserName matches. Blob bytes, flags and
    application attributes round-trip exactly (meta records the blob encoding: UTF-16LE for
    keyring-rs / Python keyring, UTF-8 for keytar)."""
    name = "windows-credential-manager"
    TYPE_GENERIC = 1
    PERSIST_LOCAL_MACHINE = 2
    max_secret = 2560                # CRED_MAX_CREDENTIAL_BLOB_SIZE (bytes of the encoded blob)
    ERROR_NOT_FOUND = 1168
    HINTS = {1312: "no credential store in this logon session (SSH key login, service account or "
                   "scheduled task without a loaded profile)",
             87: "invalid parameter (blob over 2560 bytes, or bad target name)",
             5: "access denied"}

    def __init__(self, default_enc="utf-16-le"):
        self.default_enc = default_enc

    def _fail(self, what, service, err):
        ct = _wincred().ct
        msg = self.HINTS.get(err) or ct.FormatError(err).strip()
        die(f"Credential Manager {what} for '{service}' failed (Windows error {err}: {msg}).", "keychain")

    def _get(self, service):
        w = _wincred()
        ct = w.ct
        p = w.PCRED()
        if not w.adv.CredReadW(service, self.TYPE_GENERIC, 0, ct.byref(p)):
            err = ct.get_last_error()
            if err == self.ERROR_NOT_FOUND:
                return None
            self._fail("read", service, err)
        try:
            cr = p.contents
            n = cr.CredentialBlobSize
            blob = ct.string_at(cr.CredentialBlob, n) if n and cr.CredentialBlob else b""
            attrs = []
            for i in range(cr.AttributeCount):
                a = cr.Attributes[i]
                val = ct.string_at(a.Value, a.ValueSize) if a.ValueSize and a.Value else b""
                attrs.append({"keyword": a.Keyword or "", "flags": a.Flags,
                              "value": base64.b64encode(val).decode("ascii")})
            return {"account": cr.UserName or "", "blob": blob, "persist": cr.Persist,
                    "comment": cr.Comment, "alias": cr.TargetAlias, "flags": cr.Flags, "attrs": attrs}
        finally:
            w.adv.CredFree(ct.cast(p, ct.c_void_p))

    @staticmethod
    def _decode(blob):
        # Strict decodes are bijective, so re-encoding with the recorded codec restores the bytes.
        if len(blob) % 2 == 0 and b"\x00" in blob:
            with contextlib.suppress(UnicodeDecodeError):
                return blob.decode("utf-16-le"), "utf-16-le"
        with contextlib.suppress(UnicodeDecodeError):
            return blob.decode("utf-8"), "utf-8"
        return base64.b64encode(blob).decode("ascii"), "base64"

    @staticmethod
    def _encode(secret, enc):
        return base64.b64decode(secret) if enc == "base64" else secret.encode(enc)

    def _mine(self, service, account):
        it = self._get(service)
        if it is None or (account is not None and it["account"] != account):
            return None
        return it

    def account(self, service, account=None):
        it = self._mine(service, account)
        return None if it is None else it["account"]

    def read(self, service, account=None):
        it = self._mine(service, account)
        if it is None:
            return None
        secret, enc = self._decode(it["blob"])
        return {"account": it["account"], "secret": secret,
                "meta": {"kind": self.name, "enc": enc, "persist": it["persist"], "comment": it["comment"],
                         "alias": it["alias"], "flags": it["flags"], "attrs": it["attrs"]}}

    def _meta_of(self, it):
        return {"enc": self._decode(it["blob"])[1], "persist": it["persist"], "comment": it["comment"],
                "alias": it["alias"], "flags": it["flags"], "attrs": it["attrs"]}

    def write(self, service, account, secret, meta=None):
        w = _wincred()
        ct = w.ct
        m = meta if isinstance(meta, dict) and meta.get("kind") == self.name else {}
        prior = self._get(service)
        if not m and prior:
            m = self._meta_of(prior)
        if account is None:
            account = prior["account"] if prior else ""
        blob = self._encode(secret, m.get("enc") or self.default_enc)
        if len(blob) > self.max_secret:
            die(f"secret for '{service}' is {len(blob)} bytes; Windows Credential Manager holds at "
                f"most {self.max_secret}. Nothing was changed.", "keychain")
        cr = w.CRED()
        cr.Type = self.TYPE_GENERIC
        cr.Flags = int(m.get("flags") or 0)
        cr.TargetName = service
        cr.UserName = account or None
        cr.Comment = m.get("comment")
        cr.TargetAlias = m.get("alias") or None
        cr.Persist = int(m.get("persist") or self.PERSIST_LOCAL_MACHINE)
        cr.CredentialBlobSize = len(blob)
        keep = []                                    # buffers must outlive CredWriteW
        if blob:
            buf = (ct.c_ubyte * len(blob)).from_buffer_copy(blob)
            keep.append(buf)
            cr.CredentialBlob = ct.cast(buf, ct.POINTER(ct.c_ubyte))
        attrs = m.get("attrs") or []
        if attrs:
            arr = (w.ATTR * len(attrs))()
            for i, a in enumerate(attrs):
                val = base64.b64decode(a.get("value") or "")
                arr[i].Keyword = a.get("keyword") or ""
                arr[i].Flags = int(a.get("flags") or 0)
                arr[i].ValueSize = len(val)
                if val:
                    vb = (ct.c_ubyte * len(val)).from_buffer_copy(val)
                    keep.append(vb)
                    arr[i].Value = ct.cast(vb, ct.POINTER(ct.c_ubyte))
            keep.append(arr)
            cr.AttributeCount = len(attrs)
            cr.Attributes = ct.cast(arr, ct.POINTER(w.ATTR))
        if not w.adv.CredWriteW(ct.byref(cr), 0):
            self._fail("write", service, ct.get_last_error())
        del keep
        got = self._get(service)
        if not got or got["blob"] != blob or got["account"] != (account or ""):
            die(f"Credential Manager write for '{service}' did not verify", "keychain")

    def replace(self, service, account, secret, meta=None, exclusive=True):
        # Target names are unique: exclusive replace is a plain overwrite. A scoped artifact must
        # never take over a credential that belongs to another account.
        if not exclusive and account is not None:
            it = self._get(service)
            if it is not None and it["account"] != account:
                die(f"Credential Manager target '{service}' belongs to account '{it['account']}', not "
                    f"'{account}'; refusing to overwrite it.", "keychain")
        self.write(service, account, secret, meta)

    def delete(self, service, account=None):
        w = _wincred()
        if account is not None and self._mine(service, account) is None:
            return False
        if w.adv.CredDeleteW(service, self.TYPE_GENERIC, 0):
            return True
        err = w.ct.get_last_error()
        if err == self.ERROR_NOT_FOUND:
            return False
        self._fail("delete", service, err)


def _dpapi(data, protect):
    """CryptProtectData / CryptUnprotectData, current-user scope, no UI (Windows only)."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    fn.argtypes = [ctypes.POINTER(DATA_BLOB), ctypes.c_void_p, ctypes.POINTER(DATA_BLOB),
                   ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DATA_BLOB)]
    fn.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p

    def blob(b):
        buf = ctypes.create_string_buffer(b, len(b))
        return DATA_BLOB(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    b_in, keep1 = blob(data)
    b_ent, keep2 = blob(b"aiswitch-vault-v1")
    out = DATA_BLOB()
    if not fn(ctypes.byref(b_in), None, ctypes.byref(b_ent), None, None, 0x1, ctypes.byref(out)):
        err = ctypes.get_last_error()
        die(f"DPAPI {'encrypt' if protect else 'decrypt'} failed (Windows error {err}: "
            f"{ctypes.FormatError(err).strip()})", "keychain")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))


class DpapiFileStore(FileStore):
    """aiswitch's own secret copies on Windows: DPAPI-encrypted (current user) files under
    ~/.aiswitch/vault. No 2560-byte cap. They do not decrypt for another user or machine."""
    name = "dpapi-file"

    def _f(self, service):
        return super()._f(service).with_suffix(".dpapi")

    def _decode(self, raw, f):
        try:
            return json.loads(_dpapi(raw, protect=False).decode("utf-8"))
        except ValueError:
            die(f"unreadable vault file {f}", "keychain")

    def _encode(self, obj):
        return _dpapi(dump_json(obj, None), protect=True)


class NoStore(SecretStore):
    name = "none"

    def _no(self, *a, **kw):
        die("no OS secret store is available on this platform (supported: macOS Keychain, Windows "
            "Credential Manager, freedesktop Secret Service; set AISWITCH_KEYCHAIN_DIR for testing)",
            "keychain")

    account = read = write = delete = _no


Stores = collections.namedtuple("Stores", "live vault")
STORE_FACTORY = None     # tests: a callable returning Stores


def stores():
    """Live store (where the tools keep their secrets) and vault (where aiswitch keeps copies).
    Construction is free of I/O; backends fail on first use, so platforms without keychain
    artifacts are unaffected."""
    if STORE_FACTORY is not None:
        return STORE_FACTORY()
    d = os.environ.get("AISWITCH_KEYCHAIN_DIR")
    if d:
        s = FileStore(d)
        return Stores(s, s)
    me = host_os()
    if me == "darwin":
        s = MacKeychain()
        return Stores(s, s)
    if me == "windows":
        if sys.platform == "win32":
            # Credential Manager blobs are capped at 2560 bytes: keep aiswitch's copies in
            # DPAPI-encrypted files instead (same per-user protection, no cap, no clutter).
            return Stores(WinCredStore(), DpapiFileStore(root() / "vault"))
        return Stores(NoStore(), NoStore())
    if os.name == "posix":
        return Stores(SecretServiceStore(), SecretServiceStore(vault=True))
    return Stores(NoStore(), NoStore())


# ------------------------------------------------------------- tool-specific modes
def codex_store_mode():
    """Codex `cli_auth_credentials_store` (file | keyring | auto | ephemeral), from
    $CODEX_HOME/config.toml, top level or any profile. Default: file. `-c` overrides on the
    command line can't be seen, so this is a best-effort detection."""
    try:
        text = expand(f"{CODEX_DIR}/config.toml").read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return "file"
    modes = {m.lower() for m in re.findall(
        r"""^\s*cli_auth_credentials_store\s*=\s*["']([A-Za-z_]+)["']""", text, re.M)}
    for m in ("ephemeral", "keyring", "auto"):
        if m in modes:
            return m
    return "file"


def gemini_encrypted():
    return os.environ.get("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE") == "true"


def gemini_keychain():
    # Gemini CLI uses the OS keychain (keytar) in encrypted mode, except when forced to its
    # encrypted-file fallback or under WSL.
    return gemini_encrypted() and os.environ.get("GEMINI_FORCE_FILE_STORAGE") != "true" and not is_wsl()


PREDICATES = {
    "codex_keyring": lambda: codex_store_mode() in ("keyring", "auto"),
    "gemini_encrypted": gemini_encrypted,
    "gemini_keychain": gemini_keychain,
}


def _preflight_codex(pcfg):
    mode = codex_store_mode()
    if mode == "ephemeral":
        die("Codex is configured with cli_auth_credentials_store = \"ephemeral\": the login only "
            "lives in memory, so there is nothing to save or switch.")
    if mode in ("keyring", "auto") and host_os() != "darwin":
        die(f"Codex is configured with cli_auth_credentials_store = \"{mode}\", which keeps the login "
            "in the OS keyring. On this OS aiswitch can only switch Codex logins kept in auth.json "
            "(Codex's Linux keyring cache and its Windows encrypted store can't be swapped safely). "
            f"Set cli_auth_credentials_store = \"file\" in {expand(CODEX_DIR + '/config.toml')}, "
            "run `codex login`, then save.")


def _preflight_gemini(pcfg):
    if gemini_encrypted():
        warn_once("gemini-enc", "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true: switching Gemini's keychain "
                  "/ encrypted-file login is experimental (the encrypted file is machine-bound and "
                  "may also hold MCP tokens, which are switched along with the account).")


PREFLIGHTS = {"codex": _preflight_codex, "gemini": _preflight_gemini}


def preflight(pcfg):
    fn = PREFLIGHTS.get(pcfg.get("preflight") or "")
    if fn:
        fn(pcfg)


# ------------------------------------------------------------------------- config
def _bad_name(n):
    return n.endswith(".") or n.split(".")[0].lower() in WIN_RESERVED


def _validate_platform(k, v):
    if not NAME_RE.match(k) or _bad_name(k):
        die(f"platforms.json: '{k}' is not a valid platform id (letters, digits, '.', '_', '-'; "
            "no Windows reserved names)")
    if v.get("kind") not in ("login", "app", "browser"):
        die(f"platforms.json: '{k}' needs \"kind\": \"login\", \"app\" or \"browser\"")
    if not isinstance(v.get("label"), str):
        v["label"] = k
    if v["kind"] == "browser" and not isinstance(v.get("url"), str):
        die(f"platforms.json: browser platform '{k}' needs a \"url\"")
    seen = set()
    for a in v.get("artifacts", []):
        if not isinstance(a, dict) or not isinstance(a.get("name"), str) or \
                not ARTIFACT_NAME_RE.match(a["name"]) or a["name"] in ("meta", "pending-refs") or \
                _bad_name(a["name"]):
            die(f"platforms.json: '{k}' has an artifact with a missing or invalid name")
        if a["name"].lower() in seen:
            die(f"platforms.json: '{k}' has two artifacts named '{a['name']}'")
        seen.add(a["name"].lower())
        if a.get("type") not in ("file", "dir", "json_keys", "keychain"):
            die(f"platforms.json: '{k}/{a['name']}' has unknown type '{a.get('type')}'")
        if a["type"] == "keychain" and not a.get("service"):
            die(f"platforms.json: '{k}/{a['name']}' needs a \"service\"")
        if a["type"] != "keychain" and not a.get("path"):
            die(f"platforms.json: '{k}/{a['name']}' needs a \"path\"")
        if a["type"] == "json_keys" and not isinstance(a.get("keys"), list):
            die(f"platforms.json: '{k}/{a['name']}' needs a \"keys\" list")
        if a.get("enabled_if") and a["enabled_if"] not in PREDICATES:
            die(f"platforms.json: '{k}/{a['name']}' has unknown enabled_if '{a['enabled_if']}' "
                f"(known: {', '.join(PREDICATES)})")


def load_platforms():
    plats = copy.deepcopy(DEFAULT_PLATFORMS)
    user = read_json(root() / "platforms.json")
    if (root() / "platforms.json").exists() and not isinstance(user, dict):
        die(f"cannot parse {root() / 'platforms.json'}")
    if isinstance(user, dict):
        if "schema" in user:
            entries, merge = user.get("platforms") or {}, True
        else:
            entries, merge = user, False
            warn_once("legacy-config", f"{root() / 'platforms.json'} uses the old format, which "
                      "replaces built-in platforms wholesale (and freezes their paths). Move your "
                      "changes into a fresh `aiswitch init --force` file.")
        lowered = {k.lower(): k for k in plats}
        for k, v in entries.items():
            if not isinstance(v, dict) or k.startswith("_"):
                continue
            if k not in plats and k.lower() in lowered:
                die(f"platforms.json: '{k}' differs from platform '{lowered[k.lower()]}' only by case")
            if v.get("disabled"):
                plats.pop(k, None)
                continue
            base_name = v.get("extends") or (k if merge else None)
            if v.get("extends") and v["extends"] not in plats:
                die(f"platforms.json: '{k}' extends unknown platform '{v['extends']}'")
            base = copy.deepcopy(plats.get(base_name, {})) if base_name else {}
            base.update({kk: vv for kk, vv in v.items() if kk != "extends"})
            plats[k] = base
            lowered[k.lower()] = k
    me = host_os()
    out = {}
    for k, v in plats.items():
        if me in v.get("os", [me]):
            _validate_platform(k, v)
            out[k] = v
    return out


def resolve(token):
    plats = load_platforms()
    if token in plats:
        return token, plats[token]
    for k, v in plats.items():
        if token in v.get("aliases", []):
            return k, v
    matches = [k for k in plats if k.startswith(token)]
    if len(matches) == 1:
        return matches[0], plats[matches[0]]
    if matches:
        die(f"'{token}' is ambiguous: {', '.join(matches)}")
    die(f"unknown platform '{token}'. Known: {', '.join(plats)}")


def _is_within(p, parent):
    try:
        Path(p).relative_to(parent)
        return True
    except ValueError:
        return False


def spec_path(spec):
    """Resolved, validated live path of a file/dir/json_keys artifact (None if not on this OS)."""
    p = expand(spec["path"])
    if p is None:
        return None
    if not p.is_absolute():
        die(f"artifact '{spec['name']}' path must be absolute: {p}")
    rp = Path(os.path.realpath(p))
    store = Path(os.path.realpath(root()))
    h = Path(os.path.realpath(home()))
    if rp == Path(rp.anchor) or rp == h or _is_within(rp, store) or _is_within(store, rp) \
            or (spec["type"] == "dir" and _is_within(h, rp)):
        die(f"refusing to manage '{p}' for artifact '{spec['name']}': it is a drive root, your "
            "home directory, or overlaps the aiswitch store. Fix platforms.json.")
    if is_store_python():
        for var in ("APPDATA", "LOCALAPPDATA"):
            base = os.environ.get(var)
            if base and _is_within(rp, Path(os.path.realpath(base))):
                die(f"'{p}' is under %{var}%, which the Microsoft Store build of Python redirects "
                    "into its own private folder: changes would silently not reach the app. Use "
                    "Python from python.org or winget instead.")
    return p


def spec_service(spec):
    return expand_str(spec["service"])


def spec_account(spec):
    return expand_str(spec["account"]) if spec.get("account") is not None else None


def artifacts(pcfg):
    me = host_os()
    out = []
    for a in pcfg.get("artifacts", []):
        if me not in a.get("os", [me]):
            continue
        if a["type"] == "keychain":
            if (a["service"].get(me, a["service"].get("default")) if isinstance(a["service"], dict)
                    else a["service"]) is None:
                continue
        elif expand(a["path"]) is None:
            continue
        if a.get("enabled_if") and not PREDICATES[a["enabled_if"]]():
            continue
        out.append(a)
    return out


def check_name(name):
    if not NAME_RE.match(name) or name.endswith("."):
        die("account names may use letters, digits, '.', '_' and '-' (max 40, must start with a "
            "letter/digit, must not end with '.')")
    if name.split(".")[0].lower() in WIN_RESERVED:
        die(f"'{name}' is a reserved file name on Windows; pick another name")


def check_case_collision(plat, name):
    for n, _ in list_accounts(plat):
        if n != name and n.lower() == name.lower():
            die(f"'{name}' differs from existing account '{n}' only by case; that breaks on "
                "case-insensitive file systems. Use the same spelling or a different name.")


def canonical_name(plat, name):
    """On-disk spelling of a saved account (case-insensitive file systems accept any case)."""
    if (snap_dir(plat, name) / "meta.json").exists():
        hits = [n for n, _ in list_accounts(plat) if n.lower() == name.lower()]
        if len(hits) == 1:
            return hits[0]
    return name


# ------------------------------------------------------------- snapshot locations
def snap_dir(plat, name):
    return root() / "snapshots" / plat / name


def backup_root(plat):
    return root() / "backups" / plat


def load_state():
    st = read_json(root() / "state.json")
    if not isinstance(st, dict):
        st = {}
    if not isinstance(st.get("active"), dict):
        st["active"] = {}
    return st


def save_state(st):
    atomic_write_bytes(root() / "state.json", dump_json(st))


def list_accounts(plat):
    base = root() / "snapshots" / plat
    out = []
    if base.is_dir():
        for d in sorted(base.iterdir()):
            if d.name.startswith(".") or not d.is_dir():
                continue
            meta = read_json(d / "meta.json")
            if isinstance(meta, dict):
                out.append((d.name, meta))
    return out


def find_by_identity(plat, ident, exclude=None):
    for name, meta in list_accounts(plat):
        if name != exclude and meta.get("identity") and meta["identity"] == ident:
            return name
    return None


# ----------------------------------------------------------------- vault references
def vault_key(d, name, ent):
    if ent.get("ref"):
        return VAULT_PREFIX + ent["ref"]
    # schema 1: the key was derived from the snapshot's path (breaks on rename)
    return VAULT_PREFIX + str(Path(d).relative_to(root())) + ":" + name


def snapshot_refs(d):
    d = Path(d)
    refs = set()
    meta = read_json(d / "meta.json") or {}
    for name, ent in (meta.get("artifacts") or {}).items():
        if isinstance(ent, dict) and ent.get("type") == "keychain" and ent.get("present"):
            if ent.get("ref") or not d.name.startswith("."):
                refs.add(vault_key(d, name, ent))
    pend = read_json(d / "pending-refs.json")
    if isinstance(pend, list):
        refs.update(r for r in pend if isinstance(r, str) and r.startswith(VAULT_PREFIX))
    return refs


def _record_refs(d, refs):
    d = Path(d)
    cur = read_json(d / "pending-refs.json")
    cur = cur if isinstance(cur, list) else []
    atomic_write_bytes(d / "pending-refs.json", dump_json(sorted(set(cur) | set(refs))))


def stash_refs(d):
    """Before renaming a snapshot dir, record its vault keys (schema-1 keys depend on the path)."""
    refs = snapshot_refs(d)
    if refs:
        _record_refs(d, refs)


def purge_dir(d, st, quiet=False):
    """Delete a snapshot dir's vault secrets, then the dir. On secret-delete failure, keep the
    dir (so the refs are not orphaned) and return False."""
    try:
        for ref in snapshot_refs(d):
            st.vault.delete(ref)
    except Fatal as e:
        if not quiet:
            warn(f"could not delete saved keychain items for {d.name} ({e}); will retry later")
        return False
    rmtree_force(d)
    return True


def sweep_live_leftovers(pcfg):
    """Finish live-side operations interrupted by a crash / SIGKILL / power loss: a dir artifact
    renamed away for replacement but not yet replaced (".aiswitch-old-") is moved back; dirs being
    deleted (".aiswitch-del-") or staged (".aiswitch-new-") and stale temp files are removed."""
    for spec in artifacts(pcfg):
        if spec["type"] == "keychain":
            continue
        try:
            p = real_target(spec_path(spec))
        except Fatal:
            continue
        parent = p.parent
        try:
            names = os.listdir(parent)
        except OSError:
            continue
        pat = re.compile(r"\." + re.escape(p.name) + r"\.aiswitch-(old|new|del)-[0-9a-f]{8}")
        hits = [(n, m.group(1)) for n in names if (m := pat.fullmatch(n))]
        olds = sorted((n for n, kind in hits if kind == "old"), key=lambda n: os.lstat(parent / n).st_mtime)
        if olds and not os.path.lexists(p):
            replace_file(parent / olds.pop(), p)       # crash between "rename away" and "rename in"
            warn(f"restored {p} from an interrupted switch")
        for n in olds + [n for n, kind in hits if kind in ("new", "del")]:
            rmtree_force(parent / n)
        for n in names:
            if re.fullmatch(r"\.aiswitch-[A-Za-z0-9_]{8}", n) and os.path.isfile(parent / n):
                remove_file(parent / n)                # temp file of an interrupted atomic write


def cleanup_trash(plat, st, pcfg=None):
    """Finish deletions/swaps interrupted earlier (hidden .tmp-/.old-/.del- dirs)."""
    for base in (root() / "snapshots" / plat, backup_root(plat)):
        if base.is_dir():
            for d in base.iterdir():
                if d.is_dir() and d.name.startswith(".") and re.search(r"\.(tmp|old|del)-[0-9a-f]+$", d.name):
                    purge_dir(d, st, quiet=True)
    if pcfg is not None:
        sweep_live_leftovers(pcfg)


# --------------------------------------------------------------- artifact handling
def capture(spec, dest, st):
    t, name = spec["type"], spec["name"]
    if t == "file":
        p = spec_path(spec)
        if p.is_file():
            atomic_write_bytes(dest / name, p.read_bytes())
            return {"type": t, "present": True}
        return {"type": t, "present": False}
    if t == "dir":
        p = spec_path(spec)
        if p.is_dir():
            copy_tree(p, dest / name)
            return {"type": t, "present": True}
        return {"type": t, "present": False}
    if t == "json_keys":
        p = spec_path(spec)
        data = read_json(p)
        if data is None and p.exists():
            die(f"cannot parse {p}; refusing to snapshot it")
        data = data if isinstance(data, dict) else {}
        got = {k: data[k] for k in spec["keys"] if k in data}
        if got:
            atomic_write_bytes(dest / (name + ".json"), dump_json(got, None))
        return {"type": t, "present": bool(got)}
    if t == "keychain":
        item = st.live.read(spec_service(spec), spec_account(spec))   # raises on anything but "absent"
        if item:
            ref = uuid.uuid4().hex
            _record_refs(dest, [VAULT_PREFIX + ref])   # recorded first, so a crash can't orphan it
            st.vault.write(VAULT_PREFIX + ref, item["account"], item["secret"], item.get("meta"))
            return {"type": t, "present": True, "ref": ref}
        return {"type": t, "present": False}
    die(f"unknown artifact type '{t}'")


def restore(spec, src, ent, st):
    t, name = spec["type"], spec["name"]
    present = bool(ent and ent.get("present"))
    if t == "file":
        p = spec_path(spec)
        if present:
            atomic_write_bytes(p, (src / name).read_bytes())
        else:
            remove_file(p)
    elif t == "dir":
        p = real_target(spec_path(spec))
        old = p.parent / f".{p.name}.aiswitch-old-{secrets.token_hex(4)}"
        if present:
            new = p.parent / f".{p.name}.aiswitch-new-{secrets.token_hex(4)}"
            p.parent.mkdir(parents=True, exist_ok=True)
            try:
                copy_tree(src / name, new)
                if os.path.lexists(p):
                    replace_file(p, old)
                replace_file(new, p)
            except BaseException:
                if os.path.lexists(old) and not os.path.lexists(p):
                    replace_file(old, p)
                rmtree_force(new)
                raise
            rmtree_force(old)
        elif os.path.lexists(p):
            gone = p.parent / f".{p.name}.aiswitch-del-{secrets.token_hex(4)}"   # never restored by the sweep
            replace_file(p, gone)
            rmtree_force(gone)
    elif t == "json_keys":
        p = spec_path(spec)
        live = read_json(p)
        if live is None:
            if p.exists():
                die(f"cannot parse {p}; refusing to modify it")
            if not present:
                return
            live = {}
        if not isinstance(live, dict):
            die(f"{p} is not a JSON object; refusing to modify it")
        for k in spec["keys"]:
            live.pop(k, None)
        if present:
            live.update(json.loads((src / (name + ".json")).read_text(encoding="utf-8-sig")))
        rp = real_target(p)
        mode = (rp.stat().st_mode & 0o777) if rp.exists() else 0o600
        atomic_write_bytes(p, dump_json(live), mode)
    elif t == "keychain":
        svc, acct = spec_service(spec), spec_account(spec)
        if present:
            item = st.vault.read(vault_key(src, name, ent))
            if not item:
                die(f"saved keychain entry for '{name}' is missing")
            # Unscoped artifacts own the whole service (one item); account-scoped ones (e.g.
            # Codex per CODEX_HOME) must never touch the service's other accounts.
            st.live.replace(svc, acct if acct is not None else item["account"], item["secret"],
                            item.get("meta"), exclusive=acct is None)
        else:
            st.live.delete_all(svc, acct)


def probe(spec, st):
    t = spec["type"]
    if t == "keychain":   # no password read: no keychain prompt
        return st.live.account(spec_service(spec), spec_account(spec)) is not None
    p = spec_path(spec)
    if t == "file":
        return p.is_file()
    if t == "dir":
        return p.is_dir()
    if t == "json_keys":
        data = read_json(p)
        return isinstance(data, dict) and any(k in data for k in spec["keys"])
    return False


def live_has_login(pcfg, st):
    specs = artifacts(pcfg)
    primary = [s for s in specs if s.get("primary")]
    return any(probe(s, st) for s in (primary or specs))


def _identity_source(pcfg, part, st, cache):
    """JSON the identity part reads: its file, else (only when a store is passed, i.e. during
    save/use/new which read secrets anyway - never in ls/gui, which must not cause keychain
    prompts) the JSON secret of the artifact named by part["artifact"]."""
    f = expand(part["file"]) if part.get("file") else None
    data = read_json(f) if f else None
    if isinstance(data, dict) or not part.get("artifact") or st is None:
        return data
    name = part["artifact"]
    if name not in cache:
        cache[name] = None
        spec = next((a for a in artifacts(pcfg) if a["name"] == name and a["type"] == "keychain"), None)
        if spec is not None:
            item = st.live.read(spec_service(spec), spec_account(spec))
            with contextlib.suppress(ValueError, TypeError):
                cache[name] = json.loads(item["secret"]) if item else None
    return cache[name]


def live_identity(pcfg, st=None):
    parts = pcfg.get("identity")
    if not parts:
        return None
    vals, cache = [], {}
    for i, part in enumerate(parts):
        data = _identity_source(pcfg, part, st, cache)
        v = get_path(data, part["path"]) if isinstance(data, dict) else None
        if v is not None and part.get("jwt_claim"):
            v = jwt_claim(v, part["jwt_claim"])
        if v is None or v == "":
            if i == 0:
                return None
            v = ""
        vals.append(str(v))
    return "|".join(vals)


def swap_in(tmp, final, st):
    """Replace `final` with the fully written `tmp`: rename old away, rename new in, then
    delete old (secrets first). A failure before the second rename restores the old dir."""
    old = None
    if final.exists():
        stash_refs(final)
        old = hidden_sibling(final, "old")
        replace_file(final, old)
    try:
        replace_file(tmp, final)
    except BaseException:
        if old is not None:
            replace_file(old, final)
        raise
    if old is not None:
        purge_dir(old, st)


def take_snapshot(pcfg, final, st, extra=None):
    final = Path(final)
    final.parent.mkdir(parents=True, exist_ok=True)
    tmp = hidden_sibling(final, "tmp")
    tmp.mkdir(mode=0o700)
    try:
        info = {s["name"]: capture(s, tmp, st) for s in artifacts(pcfg)}
        meta = {"schema": SNAPSHOT_SCHEMA, "saved_at": now(), "identity": live_identity(pcfg, st),
                "os": host_os(), "artifacts": info}
        meta.update(extra or {})
        atomic_write_bytes(tmp / "meta.json", dump_json(meta))
        remove_file(tmp / "pending-refs.json")
    except BaseException:
        purge_dir(tmp, st, quiet=True)
        raise
    swap_in(tmp, final, st)
    return meta


def write_meta_dir(final, meta, st):
    final = Path(final)
    final.parent.mkdir(parents=True, exist_ok=True)
    tmp = hidden_sibling(final, "tmp")
    tmp.mkdir(mode=0o700)
    atomic_write_bytes(tmp / "meta.json", dump_json(meta))
    swap_in(tmp, final, st)


PREDICATE_HINTS = {
    "codex_keyring": 'cli_auth_credentials_store = "keyring" or "auto" in Codex\'s config.toml',
    "gemini_encrypted": "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true",
    "gemini_keychain": "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true (without GEMINI_FORCE_FILE_STORAGE, outside WSL)",
}


def check_mode(pcfg, meta, what):
    """Refuse when a snapshot holds credentials (present artifacts) that the current settings
    don't manage (an enabled_if predicate is false now): switching would leave the other
    account's credentials live, and syncing would drop and purge the saved ones."""
    enabled = {a["name"] for a in artifacts(pcfg)}
    recorded = (meta or {}).get("artifacts") or {}
    me = host_os()
    bad = [a for a in pcfg.get("artifacts", [])
           if a.get("enabled_if") and me in a.get("os", [me]) and a["name"] not in enabled
           and isinstance(recorded.get(a["name"]), dict) and recorded[a["name"]].get("present")]
    if bad:
        why = "; ".join(f"'{a['name']}' (saved while {PREDICATE_HINTS.get(a['enabled_if'], a['enabled_if'])})"
                        for a in bad)
        die(f"{what} was saved with credentials that the current settings don't manage: {why}. "
            "Switching now would leave another account's credentials live. Use the same setting "
            "as when it was saved, or re-save the account under the new setting.", "mode")


def restore_all(pcfg, src, st, meta):
    """Make the live state equal to the snapshot. Artifacts the snapshot doesn't know about
    (added in a later aiswitch version, or enabled since) are restored as absent, so stale
    credentials of another account can't survive the switch."""
    check_mode(pcfg, meta, f"'{Path(src).name}'")
    arts = (meta or {}).get("artifacts") or {}
    for spec in artifacts(pcfg):
        restore(spec, Path(src), arts.get(spec["name"]), st)


def clear_all(pcfg, st):
    for spec in artifacts(pcfg):
        restore(spec, Path("."), None, st)


def delete_snapshot(d, st):
    """Rename away first (so it vanishes from listings atomically), delete secrets, rmtree.
    If the secrets cannot be deleted, rename back and raise."""
    d = Path(d)
    stash_refs(d)
    gone = hidden_sibling(d, "del")
    replace_file(d, gone)
    try:
        for ref in snapshot_refs(gone):
            st.vault.delete(ref)
    except BaseException:
        replace_file(gone, d)
        raise
    rmtree_force(gone)


_BACKUP_RE = re.compile(r"^(\d{8}-\d{6})(?:-(\d+))?$")


def backup_dirs(plat):
    br = backup_root(plat)
    if not br.is_dir():
        return []
    ds = [(m, p) for p in br.iterdir() if p.is_dir() and (m := _BACKUP_RE.match(p.name))]
    ds.sort(key=lambda x: (x[0].group(1), int(x[0].group(2) or 1)))
    return [p for _, p in ds]


def prune_backups(plat, st, keep=None):
    """Keep the newest KEEP_BACKUPS backups; never the one just taken (`keep`), whatever the
    clock did (DST, time-zone travel and NTP steps can make a new name sort as oldest)."""
    dirs = backup_dirs(plat)
    excess = len(dirs) - KEEP_BACKUPS
    for d in dirs:
        if excess <= 0:
            break
        if keep is not None and d == Path(keep):
            continue
        try:
            delete_snapshot(d, st)
            excess -= 1
        except Fatal as e:
            warn(f"could not prune backup {d.name}: {e}")
            excess -= 1


def new_backup_dir(plat):
    base = time.strftime("%Y%m%d-%H%M%S", time.gmtime())     # UTC: no DST jumps
    b, n = backup_root(plat) / base, 1
    while b.exists():
        n += 1
        b = backup_root(plat) / f"{base}-{n}"
    return b


# ------------------------------------------------------------------ switching core
def check_processes(pcfg, do_quit):
    pt = proc_table(refresh=True)
    names, unknown = running_state(pcfg, pt)
    if pcfg["kind"] == "app":
        label = pcfg.get("app") or pcfg["label"]
        if unknown and not names:
            why = f" (inside a {sandbox_kind()} sandbox)" if sandbox_kind() else ""
            warn_once("proc-unknown", f"cannot tell whether {label} is running{why}; make sure it is "
                      "closed before switching")
            return
        if names:
            if not do_quit:
                die(f"{label} is running. Quit it first, or pass --quit to let aiswitch close it.",
                    "app_running")
            if host_os() != "darwin" and not _quit_targets(pcfg):
                die(f"{label} appears to be running (pids {', '.join(map(str, running_pids(pcfg, pt)))}), "
                    "but none of those processes is one aiswitch can safely ask to quit. Close it "
                    "yourself and retry.")
            quit_app(pcfg)
            if not wait_until_quit(pcfg):
                left = running_pids(pcfg, proc_table(refresh=True))
                die(f"could not confirm that {label} has quit"
                    + (f" (still running: pids {', '.join(map(str, left))})" if left else "")
                    + "; close it manually and retry")
    else:
        if names:
            warn(f"{', '.join(names)} appears to be running. Existing sessions keep the old login "
                 "in memory and may write it back - restart them after switching.")
        elif unknown:
            warn_once("proc-unknown", "cannot detect all running processes here; restart any open "
                      f"{pcfg['label']} sessions after switching")


def leave_current(plat, pcfg, st, force, do_quit, writeback=False, target=None):
    """Prepare to replace the live login: stop-check, write refreshed tokens back to the
    matching saved account, and back the live state up.
    Returns (matched, synced, backup_dir)."""
    check_processes(pcfg, do_quit)
    state = load_state()
    has = live_has_login(pcfg, st)
    ident = live_identity(pcfg, st)
    active = state["active"].get(plat)
    matched, synced, known = None, False, False
    if ident:
        hits = [n for n, m in list_accounts(plat) if m.get("identity") == ident]
        known = bool(hits)
        if active in hits:                  # the account last switched to is the live one
            matched = active
        elif len(hits) == 1:
            matched = hits[0]
        elif hits:
            print(f"  the live login matches several saved accounts ({', '.join(hits)}); not syncing "
                  "it back into any of them. It is kept in a backup.")
        synced = bool(matched)
    elif has and not pcfg.get("identity"):
        # No way to verify which account is live: the user may have signed into a different
        # account inside the app. Only write back when explicitly asked to.
        if active and (snap_dir(plat, active) / "meta.json").exists():
            matched = active
            synced = writeback
            if not writeback:
                print(f"  not syncing the live login back into '{active}' (aiswitch can't verify which "
                      "account it is; pass --writeback if you're sure). It is kept in a backup.")
    if matched and synced:
        old = read_json(snap_dir(plat, matched) / "meta.json") or {}
        recorded = old.get("artifacts") or {}
        # Only sync a complete live login: identity files can outlive the credentials.
        missing = [s["name"] for s in artifacts(pcfg) if s.get("primary")
                   and (recorded.get(s["name"]) or {}).get("present") and not probe(s, st)]
        if not has or missing:
            synced = False
            print(f"  not syncing back into '{matched}': its credentials are no longer on this machine"
                  + (f" ({', '.join(missing)} missing)" if missing else "") + "; its saved copy is kept.")
        else:
            check_mode(pcfg, old, f"'{matched}'")
            take_snapshot(pcfg, snap_dir(plat, matched), st,
                          {"created": old.get("created", old.get("saved_at")), "kind": pcfg["kind"]})
            print(f"  synced current login back into '{matched}'")
    if not (matched or known) and has and not force:
        die("the login currently on this machine isn't saved under any account name.\n"
            f"  Save it first:  aiswitch save {plat} <name>\n"
            "  or pass --force to replace it (a backup is kept in ~/.aiswitch/backups).", "unsaved")
    backup = None
    if has:
        backup = new_backup_dir(plat)
        take_snapshot(pcfg, backup, st, {"backup": True})
        prune_backups(plat, st, keep=backup)
    return matched, synced, backup


def apply_or_rollback(pcfg, st, backup, action):
    """Run action(); on failure put back the backup (or an all-absent state if there was no
    login before). The original error is always reported; signals can't interrupt the rollback."""
    try:
        action()
    except BaseException as e:
        err = str(e) if isinstance(e, Fatal) else (f"{type(e).__name__}: {e}".rstrip(": ")
                                                   if str(e) else type(e).__name__)
        with signals_deferred():
            try:
                if backup:
                    bmeta = read_json(Path(backup) / "meta.json")
                    if not isinstance(bmeta, dict):
                        raise Fatal(f"backup {backup} is missing or unreadable")
                    restore_all(pcfg, backup, st, bmeta)
                    outcome = "previous login restored"
                else:
                    clear_all(pcfg, st)
                    outcome = "left logged out (there was no login before)"
            except BaseException as e2:
                where = f" A copy of the previous login is in {backup}." if backup else ""
                die(f"switch failed ({err}); rolling back ALSO failed ({e2}).{where}")
        die(f"switch failed ({err}); {outcome}")


# ------------------------------------------------------------------------ browsers
# Chromium-family browsers: per OS, an ordered list of (launcher, user-data dir) variants.
# Profile listing and launching always use the SAME variant, so a profile name read from one
# browser's "Local State" is never passed to another browser.
_PF64 = "{env:ProgramW6432|C:/Program Files}"            # real Program Files even under 32-bit Python
_PF86 = "{env:ProgramFiles(x86)|C:/Program Files (x86)}"
BROWSERS = {
    "chrome": {
        "label": "Google Chrome", "mac_app": "Google Chrome",
        "darwin": [{"data": "~/Library/Application Support/Google/Chrome"}],
        "linux": [
            {"bin": ["google-chrome", "google-chrome-stable"], "data": "{chrome_config}/google-chrome"},
            {"flatpak": "com.google.Chrome", "data": "~/.var/app/com.google.Chrome/config/google-chrome"},
            {"wsl": True, "bin": ["{wsl_pf64}/Google/Chrome/Application/chrome.exe",
                                  "{wsl_pf86}/Google/Chrome/Application/chrome.exe",
                                  "{wsl_local}/Google/Chrome/Application/chrome.exe"],
             "data": "{wsl_local}/Google/Chrome/User Data"},
        ],
        "windows": [{"bin": ["{localappdata}/Google/Chrome/Application/chrome.exe",
                             f"{_PF64}/Google/Chrome/Application/chrome.exe",
                             f"{_PF86}/Google/Chrome/Application/chrome.exe", "apppath:chrome.exe"],
                     "data": "{localappdata}/Google/Chrome/User Data"}],
    },
    "edge": {
        "label": "Microsoft Edge", "mac_app": "Microsoft Edge",
        "darwin": [{"data": "~/Library/Application Support/Microsoft Edge"}],
        "linux": [
            {"bin": ["microsoft-edge", "microsoft-edge-stable"], "data": "{chrome_config}/microsoft-edge"},
            {"flatpak": "com.microsoft.Edge", "data": "~/.var/app/com.microsoft.Edge/config/microsoft-edge"},
            {"wsl": True, "bin": ["{wsl_pf86}/Microsoft/Edge/Application/msedge.exe",
                                  "{wsl_pf64}/Microsoft/Edge/Application/msedge.exe"],
             "data": "{wsl_local}/Microsoft/Edge/User Data"},
        ],
        "windows": [{"bin": [f"{_PF86}/Microsoft/Edge/Application/msedge.exe",
                             f"{_PF64}/Microsoft/Edge/Application/msedge.exe", "apppath:msedge.exe"],
                     "data": "{localappdata}/Microsoft/Edge/User Data"}],
    },
    "chromium": {
        "label": "Chromium", "mac_app": "Chromium",
        "darwin": [{"data": "~/Library/Application Support/Chromium"}],
        "linux": [
            {"bin": ["/snap/bin/chromium"], "data": "~/snap/chromium/common/chromium"},
            # "chrome" is the binary name of the FreeBSD/OpenBSD Chromium port
            {"bin": ["chromium", "chromium-browser", "chrome"], "data": "{chrome_config}/chromium"},
            {"flatpak": "org.chromium.Chromium", "data": "~/.var/app/org.chromium.Chromium/config/chromium"},
        ],
        "windows": [{"bin": ["{localappdata}/Chromium/Application/chrome.exe"],
                     "data": "{localappdata}/Chromium/User Data"}],
    },
    "brave": {
        "label": "Brave", "mac_app": "Brave Browser",
        "darwin": [{"data": "~/Library/Application Support/BraveSoftware/Brave-Browser"}],
        "linux": [
            {"bin": ["brave-browser", "brave"], "data": "{chrome_config}/BraveSoftware/Brave-Browser"},
            {"flatpak": "com.brave.Browser", "data": "~/.var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser"},
        ],
        "windows": [{"bin": ["{localappdata}/BraveSoftware/Brave-Browser/Application/brave.exe",
                             f"{_PF64}/BraveSoftware/Brave-Browser/Application/brave.exe",
                             "apppath:brave.exe"],
                     "data": "{localappdata}/BraveSoftware/Brave-Browser/User Data"}],
    },
}
AUTO_BROWSERS = ("chrome", "edge", "chromium", "brave")
Browser = collections.namedtuple("Browser", "preset label launcher data pass_user_data mac")
_WSL_WIN = None


def _wsl_windows_dirs():
    """{"wsl_local": ..., "wsl_pf64": ..., "wsl_pf86": ...} as Linux paths (WSL interop).
    Failures are cached briefly (not forever), so a long-running GUI retries."""
    global _WSL_WIN
    if _WSL_WIN is not None and (_WSL_WIN[0] or time.monotonic() - _WSL_WIN[1] < 30):
        return _WSL_WIN[0]
    got = {}
    cmd = shutil.which("cmd.exe") or "/mnt/c/Windows/System32/cmd.exe"
    raw = b""
    if os.path.exists(cmd):
        with contextlib.suppress(OSError, ValueError, subprocess.SubprocessError):
            raw = subprocess.run([cmd, "/c", "chcp 65001 >nul & echo %LOCALAPPDATA%& echo %ProgramW6432%& "
                                  "echo %ProgramFiles(x86)%"], capture_output=True, timeout=15,
                                 cwd="/mnt/c" if os.path.isdir("/mnt/c") else None,
                                 stdin=subprocess.DEVNULL).stdout or b""
    text = raw.decode("utf-8", "replace")
    for key, val in zip(("wsl_local", "wsl_pf64", "wsl_pf86"), text.splitlines()):
        val = val.strip()
        if val and "%" not in val and "�" not in val and shutil.which("wslpath"):
            p = _run_quiet(["wslpath", "-u", val])
            if p and p.strip():
                got[key] = p.strip()
    _WSL_WIN = (got, time.monotonic())
    return got


def _app_path(exe):
    """Windows 'App Paths' registry entry (custom install locations), 64-bit view first."""
    if sys.platform != "win32":
        return None
    import winreg
    sub = r"Software\Microsoft\Windows\CurrentVersion\App Paths" + "\\" + exe
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (getattr(winreg, "KEY_WOW64_64KEY", 0), 0):
            with contextlib.suppress(OSError):
                with winreg.OpenKey(hive, sub, 0, winreg.KEY_READ | view) as k:
                    v = winreg.QueryValueEx(k, None)[0].strip().strip('"')
                    if v and os.path.isfile(v):
                        return v
    return None


def _btpl(tpl, wsl):
    """Expand a browser template; None if it needs WSL values we don't have."""
    if wsl:
        for k, v in _wsl_windows_dirs().items():
            tpl = tpl.replace("{" + k + "}", v)
        if "{wsl_" in tpl:
            return None
    return expand(tpl)


@contextlib.contextmanager
def mock_env(key, value):
    """Temporarily set an environment variable."""
    old = os.environ.get(key)
    os.environ[key] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old


def _which_safe(name):
    """shutil.which, but on Windows never from the current directory or relative PATH entries."""
    if os.name != "nt":
        return shutil.which(name)
    path = os.pathsep.join(d for d in os.environ.get("PATH", "").split(os.pathsep) if d and os.path.isabs(d))
    with mock_env("NoDefaultCurrentDirectoryInExePath", "1"):
        hit = shutil.which(name, path=path)
    return hit if hit and os.path.isabs(hit) else None


def _find_launcher(var):
    if var.get("flatpak"):
        fp = _which_safe("flatpak")
        return [fp, "run", var["flatpak"]] if fp else None
    for cand in var.get("bin", []):
        if cand.startswith("apppath:"):
            hit = _app_path(cand[8:])
            if hit:
                return [hit]
        elif "/" in cand or "\\" in cand or "{" in cand:
            p = _btpl(cand, var.get("wsl"))
            if p and p.is_file():
                return [str(p)]
        elif _which_safe(cand):
            return [_which_safe(cand)]
    return None


def _mac_launcher(app):
    """`open -na <app>`: <app> is a name LaunchServices knows, or a path to a .app bundle."""
    if app.endswith(".app") or "/" in app:
        p = expand(app)
        return ["open", "-na", str(p), "--args"] if p and p.is_dir() else None
    for base in ("/Applications", str(home() / "Applications")):
        if os.path.isdir(f"{base}/{app}.app"):
            return ["open", "-na", app, "--args"]
    if host_os() == "darwin" and sys.platform == "darwin":
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            if subprocess.run(["open", "-Ra", app], capture_output=True, timeout=10).returncode == 0:
                return ["open", "-na", app, "--args"]
    return None


def browser_variants(pcfg):
    """Candidate (browser, data dir) pairs for this platform, best first.
    "browser": auto | chrome | edge | chromium | brave | a legacy macOS app name ("Google
    Chrome"...) | any other app name (custom browser: needs "user_data", plus "browser_bin" off
    macOS). "user_data" / "browser_bin" refine a preset instead of replacing it."""
    me = host_os()
    sel = pcfg.get("browser") or "auto"
    known = {}
    for k, b in BROWSERS.items():
        known[b["mac_app"].lower()] = known[b["label"].lower()] = known[k] = k
    preset = "auto" if sel == "auto" else known.get(str(sel).lower())
    ud = pcfg.get("user_data")
    data_over = expand(ud) if ud else None
    bins = pcfg.get("browser_bin")
    bins = bins.get(me) if isinstance(bins, dict) else bins
    bins = [bins] if isinstance(bins, str) else list(bins or [])

    def custom_launcher(mac_app):
        if me == "darwin":
            return _mac_launcher(bins[0]) if bins else _mac_launcher(mac_app)
        return _find_launcher({"bin": bins})

    if bins and preset == "auto" and data_over is None:
        die("platforms.json: \"browser_bin\" needs \"browser\" (chrome, edge, chromium, brave) or "
            "\"user_data\", so aiswitch knows which profile directory that binary uses")
    if preset is None:
        if data_over is None:
            die(f"platforms.json: browser '{sel}' is not one of auto, {', '.join(BROWSERS)}; a custom "
                "browser needs \"user_data\" (its profile directory) and, outside macOS, \"browser_bin\"")
        return [Browser("custom", str(sel), custom_launcher(str(sel)), data_over, True, me == "darwin")]
    out = []
    for name in (AUTO_BROWSERS if preset == "auto" else (preset,)):
        b = BROWSERS[name]
        for var in b.get(me, []):
            if var.get("wsl") and not is_wsl():
                continue
            data = data_over or _btpl(var["data"], var.get("wsl"))
            if bins:
                launcher = custom_launcher(b["mac_app"])
            elif me == "darwin":
                launcher = _mac_launcher(b["mac_app"])
            else:
                launcher = _find_launcher(var)
            # a custom binary is told explicitly which profile directory we listed
            out.append(Browser(name, b["label"], launcher, data, bool(data_over or bins), me == "darwin"))
    return out


def select_browser(pcfg, prefer=None):
    """The browser to list profiles from and launch. `prefer` = a saved account's meta: then
    exactly the browser + data dir it was saved with, or an error (never another browser,
    whose profile of the same directory name may belong to someone else)."""
    vs = browser_variants(pcfg)
    if prefer and prefer.get("browser"):
        for v in vs:
            if (v.preset == prefer["browser"] or prefer["browser"] == "custom") and \
                    str(v.data) == prefer.get("user_data"):
                return v
        die(f"this account was saved with {prefer.get('browser_label') or prefer['browser']} "
            f"(profile data in {prefer.get('user_data')}), which isn't available with the current "
            "settings. Restore that browser / setting, or save the account again.", "browser")
    has_state = [v for v in vs if v.data and (v.data / "Local State").is_file()]
    for pool in ([v for v in has_state if v.launcher], has_state, [v for v in vs if v.launcher], vs):
        if pool:
            return pool[0]
    return None


def chrome_profiles(pcfg_or_browser):
    b = pcfg_or_browser if isinstance(pcfg_or_browser, Browser) else select_browser(pcfg_or_browser)
    ls = read_json(b.data / "Local State") if b and b.data else None
    cache = get_path(ls, "profile.info_cache") if isinstance(ls, dict) else None
    if not isinstance(cache, dict):
        return {}
    return {k: (v.get("name") or k) for k, v in cache.items() if isinstance(v, dict)}


def resolve_profile(b, wanted):
    profiles = chrome_profiles(b)
    if wanted in profiles:
        return wanted, profiles[wanted]
    for k, n in profiles.items():
        if n.lower() == wanted.lower():
            return k, n
    if not profiles:
        if b and b.data and (b.data / wanted).is_dir():
            return wanted, wanted
        where = f" in {b.data}" if b and b.data else ""
        die(f"no {b.label if b else 'browser'} profiles found{where}. Open the browser once, or set "
            "\"browser\" / \"user_data\" for this platform in platforms.json.")
    opts = ", ".join(f"{n} ({k})" for k, n in profiles.items())
    die(f"no {b.label} profile '{wanted}'. Available: {opts}")


def open_browser_profile(b, profile, url):
    """Returns None on success, or an error message."""
    if b is None or not b.launcher:
        name = b.label if b else "a Chromium-based browser"
        return (f"could not find {name}; install it, or set \"browser\" (chrome, edge, chromium, "
                "brave) or \"browser_bin\" for this platform in platforms.json")
    if b.data and chrome_profiles(b) and profile not in chrome_profiles(b) and not (b.data / profile).is_dir():
        return f"profile directory '{profile}' no longer exists in {b.data}"
    args = [f"--profile-directory={profile}"]
    win_exe = (not b.mac) and b.launcher[0].lower().endswith(".exe")
    if b.pass_user_data and b.data:
        ud = str(b.data)
        if win_exe and is_wsl():                     # a Windows browser needs a Windows path
            conv = _run_quiet(["wslpath", "-w", ud]) if shutil.which("wslpath") else None
            if not conv or not conv.strip():
                return f"cannot convert {ud} to a Windows path (wslpath failed)"
            ud = conv.strip()
        args.append(f"--user-data-dir={ud}")
    try:
        if b.mac:
            r = subprocess.run(b.launcher + args + [url], capture_output=True, text=True)
            return None if r.returncode == 0 else (r.stderr.strip() or f"open exited {r.returncode}")
        if host_os() == "linux" and not win_exe and not (os.environ.get("DISPLAY") or
                                                         os.environ.get("WAYLAND_DISPLAY")):
            return "no graphical session (DISPLAY / WAYLAND_DISPLAY are not set)"
        proc = _spawn_detached(b.launcher + args + [url])
        for _ in range(15):                  # catch an immediate crash (e.g. no display)
            time.sleep(0.1)
            rc = proc.poll()
            if rc is not None:
                return None if rc == 0 else f"{b.label} exited with status {rc}"
        return None
    except OSError as e:
        return str(e)


# ---------------------------------------------------------------------- commands
def cmd_platforms(args):
    for k, v in load_platforms().items():
        al = f"  (alias: {', '.join(v['aliases'])})" if v.get("aliases") else ""
        print(f"{k:16} {v['label']}{al}")


CONFIG_SKELETON = {
    "schema": CONFIG_SCHEMA,
    "_help": [
        "Entries under 'platforms' are merged field-by-field over the built-in definitions,",
        "so built-in path fixes in new aiswitch versions still reach you.",
        "Disable a platform:        \"gemini\": {\"disabled\": true}",
        "Override one field:        \"codex\": {\"processes\": [\"codex\", \"codex-dev\"]}",
        "Add a variant:             \"codex-work\": {\"extends\": \"codex\", \"label\": \"Codex (work)\", ...}",
        "Pick a browser:            \"claude-web\": {\"browser\": \"edge\"}  (auto, chrome, edge, chromium, brave)",
        "Path tokens: ~ {home} {appdata} {localappdata} {xdg_config} {chrome_config} {env:VAR|default};",
        "a path may also be {\"darwin\": ..., \"linux\": ..., \"windows\": ...}.",
        "See the built-in definitions with: aiswitch init --show-defaults",
    ],
    "platforms": {},
}


def cmd_init(args):
    if args.show_defaults:
        sys.stdout.write(json.dumps(DEFAULT_PLATFORMS, indent=2, ensure_ascii=False) + "\n")
        return
    p = root() / "platforms.json"
    if p.exists() and not args.force:
        die(f"{p} already exists (use --force to overwrite)")
    if p.exists():
        bak = p.with_name(f"platforms.json.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(p, bak)
        print(f"previous file kept as {bak}")
    atomic_write_bytes(p, dump_json(CONFIG_SKELETON), 0o644)
    print(f"wrote {p}\nAdd overrides under \"platforms\"; they are merged over the built-in definitions.")


def current_account(plat, pcfg, state):
    if pcfg["kind"] == "browser":
        return None, False
    ident = live_identity(pcfg)
    if ident:
        return find_by_identity(plat, ident), True
    if pcfg.get("identity"):
        return None, False
    n = state["active"].get(plat)
    if n and (snap_dir(plat, n) / "meta.json").exists():
        return canonical_name(plat, n), False
    return None, False


def _browser_detail(meta):
    label = meta.get("browser_label") or "Chrome"
    return f"{label} profile: {meta.get('profile_name')}"


def cmd_ls(args):
    state = load_state()
    plats = load_platforms()
    if args.platform:
        k, v = resolve(args.platform)
        plats = {k: v}
    any_saved = False
    for k, v in plats.items():
        accounts = list_accounts(k)
        any_saved = any_saved or bool(accounts)
        if not args.platform and not accounts:
            continue
        print(c(f"{v['label']}", "1") + f"  [{k}]")
        cur, _ = current_account(k, v, state)
        if not accounts:
            print("  (no saved accounts)")
        for name, meta in accounts:
            dot = c(glyph("on"), "32") if name == cur else glyph("off")
            detail = _browser_detail(meta) if meta.get("kind") == "browser" else meta.get("identity") or ""
            print(f"  {dot} {name:16} {detail:34} saved {meta.get('saved_at', '?')}")
    if not any_saved and not args.platform:
        print("No saved accounts yet. Log in to a tool, then: aiswitch save <platform> <name>")
        print("Platforms: aiswitch platforms")


def cmd_current(args):
    state = load_state()
    if args.platform:
        k, v = resolve(args.platform)
        plats = {k: v}
    else:
        plats = load_platforms()
    for k, v in plats.items():
        if v["kind"] == "browser":
            continue
        name, verified = current_account(k, v, state)
        if name:
            print(f"{k:16} {name}" + ("" if verified else "  (unverified: from last switch)"))
        elif args.platform:
            print(f"{k:16} (none / unsaved login)")


def cmd_profiles(args):
    for k, v in load_platforms().items():
        if v["kind"] != "browser" or (args.platform and resolve(args.platform)[0] != k):
            continue
        b = select_browser(v)
        if b is None:
            print("no supported browser found")
            break
        print(f"{b.label} profiles ({b.data}):")
        profs = chrome_profiles(b)
        for d, n in profs.items():
            print(f"  {n}  ({d})")
        if not profs:
            print("  (none found)")
        break


def cmd_save(args):
    plat, pcfg = resolve(args.platform)
    check_name(args.name)
    st = stores()
    with lock():
        cleanup_trash(plat, st, pcfg if pcfg["kind"] != "browser" else None)
        check_case_collision(plat, args.name)
        dest = snap_dir(plat, args.name)
        if dest.exists() and not args.force:
            die(f"'{args.name}' already exists for {plat} (use --force to overwrite)")
        if pcfg["kind"] == "browser":
            b = select_browser(pcfg)
            if b is None:
                die("no supported browser found (Chrome, Edge, Chromium or Brave); set \"browser\" "
                    "or \"user_data\" for this platform in platforms.json")
            if not args.profile:
                profs = ", ".join(chrome_profiles(b).values()) if b else ""
                die(f"pass --profile <browser profile name>. Profiles: {profs or '(none found)'}")
            if b.data is None:
                die(f"don't know where {b.label} keeps its profiles here; set \"user_data\" for this "
                    "platform in platforms.json")
            pdir, pname = resolve_profile(b, args.profile)
            write_meta_dir(dest, {"schema": SNAPSHOT_SCHEMA, "kind": "browser", "profile": pdir,
                                  "profile_name": pname, "browser": b.preset, "browser_label": b.label,
                                  "user_data": str(b.data), "saved_at": now(), "artifacts": {}}, st)
            print(f"saved {plat}/{args.name} -> {b.label} profile '{pname}'")
            return
        preflight(pcfg)
        if pcfg["kind"] == "app":
            # SQLite / LevelDB files copied while the app runs can be inconsistent.
            check_processes(pcfg, args.quit)
        if not live_has_login(pcfg, st) and not args.allow_empty:
            die(f"no {pcfg['label']} login found on this machine ({pcfg.get('login_hint', 'log in first')}). "
                "Run `aiswitch doctor` to see where aiswitch looked, or pass --allow-empty to save "
                "a logged-out state.", "empty")
        ident = live_identity(pcfg, st)
        if ident and not args.allow_duplicate:
            other = find_by_identity(plat, ident, exclude=args.name)
            if other:
                die(f"this login ({ident}) is already saved as '{other}'. Refresh it with "
                    f"`aiswitch save {plat} {other} --force`, or pass --allow-duplicate.", "duplicate")
        old = read_json(dest / "meta.json") or {}
        meta = take_snapshot(pcfg, dest, st, {"created": old.get("created") or now(),
                                              "kind": pcfg["kind"]})
        state = load_state()
        state["active"][plat] = args.name
        save_state(state)
        who = f" ({meta['identity']})" if meta.get("identity") else ""
        print(f"saved current {pcfg['label']} login as '{args.name}'{who}")


def cmd_use(args):
    check_name(args.name)
    plat, pcfg = resolve(args.platform)
    name = canonical_name(plat, args.name)
    st = stores()
    with lock():
        d = snap_dir(plat, name)
        meta = read_json(d / "meta.json")
        if not meta:
            names = ", ".join(n for n, _ in list_accounts(plat)) or "none saved"
            die(f"no account '{args.name}' for {plat} (saved: {names})")
        if pcfg["kind"] == "browser":
            b = select_browser(pcfg, prefer=meta)
            err = open_browser_profile(b, meta["profile"], pcfg["url"])
            if err:
                die(f"could not open the browser: {err}")
            print(f"opened {pcfg['url']} in {b.label} profile '{meta['profile_name']}'")
            return
        cleanup_trash(plat, st, pcfg)
        preflight(pcfg)
        check_mode(pcfg, meta, f"'{name}'")
        matched, synced, backup = leave_current(plat, pcfg, st, args.force, args.quit,
                                                getattr(args, "writeback", False), target=name)
        if matched == name and synced:
            print(f"'{name}' is already the active {pcfg['label']} account")
        else:
            apply_or_rollback(pcfg, st, backup, lambda: restore_all(pcfg, d, st, meta))
            print(f"switched {pcfg['label']} -> '{name}'")
        state = load_state()
        state["active"][plat] = name
        save_state(state)
    if args.launch and pcfg["kind"] == "app":
        if launch_app(pcfg):
            print(f"launched {pcfg.get('app') or pcfg['label']}")


def cmd_new(args):
    plat, pcfg = resolve(args.platform)
    if pcfg["kind"] == "browser":
        die("for web accounts, create a browser profile, sign in there, then: "
            f"aiswitch save {plat} <name> --profile <profile>")
    check_name(args.name)
    st = stores()
    with lock():
        cleanup_trash(plat, st, pcfg)
        check_case_collision(plat, args.name)
        if snap_dir(plat, args.name).exists():
            die(f"'{args.name}' already exists; use `aiswitch use {plat} {args.name}`")
        preflight(pcfg)
        _, _, backup = leave_current(plat, pcfg, st, args.force, args.quit,
                                     getattr(args, "writeback", False))
        apply_or_rollback(pcfg, st, backup, lambda: clear_all(pcfg, st))
        state = load_state()
        state["active"].pop(plat, None)
        save_state(state)
    print(f"{pcfg['label']} is now logged out locally (previous account saved/backed up).")
    print(f"Next: {pcfg.get('login_hint') or 'log in with the tool'}, then run:  aiswitch save {plat} {args.name}")


def cmd_rm(args):
    check_name(args.name)
    plat, pcfg = resolve(args.platform)
    name = canonical_name(plat, args.name)
    d = snap_dir(plat, name)
    if not (d / "meta.json").exists():
        die(f"no account '{args.name}' for {plat}")
    if not args.yes:
        if input(f"Delete saved account {plat}/{name}? This cannot be undone. [y/N] ").lower() != "y":
            print("cancelled")
            return
    st = stores()
    with lock():
        delete_snapshot(d, st)
        state = load_state()
        if (state["active"].get(plat) or "").lower() == name.lower():
            state["active"].pop(plat)
            save_state(state)
    print(f"removed {plat}/{name}")


def cmd_purge(args):
    r = root()
    print(f"This deletes every saved account and backup in {r}, including the saved keychain\n"
          "copies. Your current live logins are NOT touched.")
    if not args.yes and input("Type 'purge' to continue: ").strip() != "purge":
        print("cancelled")
        return
    st = stores()
    failed = []
    with lock():
        for base in (r / "snapshots", r / "backups"):
            if not base.is_dir():
                continue
            for plat_dir in base.iterdir():
                if not plat_dir.is_dir():
                    continue
                for d in plat_dir.iterdir():
                    if d.is_dir():
                        stash_refs(d)
                        if not purge_dir(d, st):
                            failed.append(d)
    if failed:
        die(f"could not delete the saved keychain items for {len(failed)} snapshot(s); "
            f"left them in {r}. Unlock the keychain and run purge again.")
    for name in ("snapshots", "backups", "vault", "state.json", "platforms.json"):
        p = r / name
        if p.is_dir():
            rmtree_force(p)
        elif p.exists():
            remove_file(p)
    print(f"purged {r}. Remove the folder itself with your file manager if you like.")


def describe_host():
    bits = struct.calcsize("P") * 8
    extra = []
    if is_wsl():
        extra.append("WSL")
    if sandbox_kind():
        extra.append(f"sandbox={sandbox_kind()}")
    if is_store_python():
        extra.append("Microsoft Store Python")
    return (f"os={host_os()} ({sys.platform}, {_platform.machine() or '?'}), python={sys.version.split()[0]} "
            f"{bits}-bit" + (f", {', '.join(extra)}" if extra else ""))


def cmd_doctor(args):
    st = stores()
    print(f"aiswitch {VERSION}  {describe_host()}")
    print(f"store={root()}  secret stores: live={st.live.name} vault={st.vault.name}")
    if os.name == "posix":
        mode = oct(root().stat().st_mode & 0o777)
        print(f"store permissions: {mode} {'ok' if mode == '0o700' else '(expected 0o700)'}")
    else:
        print("store permissions: not checked on Windows (mode bits don't apply; files are "
              "protected only by your user profile's ACLs)")
    pt = proc_table(refresh=True)
    if pt.procs is None:
        print("process detection: unavailable (running-app checks are disabled)")
    elif pt.partial:
        print("process detection: partial (" + (f"inside a {sandbox_kind()} sandbox" if sandbox_kind()
                                                  else "command lines unavailable") + ")")
    for var in ("CLAUDE_CONFIG_DIR", "CODEX_HOME", "GEMINI_CLI_HOME", "CHROME_CONFIG_HOME",
                "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE", "GEMINI_FORCE_FILE_STORAGE"):
        if os.environ.get(var):
            print(f"{var}={os.environ[var]} (honoured)")
    if "CLAUDE_SECURESTORAGE_CONFIG_DIR" in os.environ:
        warn("CLAUDE_SECURESTORAGE_CONFIG_DIR is set; aiswitch does not know how Claude Code uses it "
             "and ignores it. Check below that the credential store it shows is the one in use.")
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                "OPENAI_API_KEY", "CODEX_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        if os.environ.get(var):
            warn(f"{var} is set: it overrides the stored login of the matching tool, so switching "
                 "accounts may have no visible effect")
    if is_wsl():
        print("WSL: CLI tools are managed on the Linux side; browser profiles may use the Windows "
              "browser. Run Windows Python to manage Windows-side apps (Claude Desktop).")
    for k, v in load_platforms().items():
        print(c(f"\n{v['label']} [{k}]", "1"))
        if v["kind"] == "browser":
            b = select_browser(v)
            if b is None:
                print("  no supported browser found")
            else:
                print(f"  browser: {b.label}{'' if b.launcher else ' (launcher NOT found)'}  data: {b.data}")
                print(f"  profiles found: {len(chrome_profiles(b))}")
            continue
        if k == "codex" or v.get("preflight") == "codex":
            print(f"  credential store mode: {codex_store_mode()}")
        try:
            preflight(v)
        except Fatal as e:
            print(f"  ! {e}")
        for spec in artifacts(v):
            try:
                if spec["type"] == "keychain":
                    acct = spec_account(spec)
                    where = f"{st.live.name}:{spec_service(spec)}" + (f" [{acct}]" if acct else "")
                else:
                    where = str(expand(spec["path"]))
                mark = glyph("ok") if probe(spec, st) else glyph("no")
            except Fatal as e:
                mark = "!"
                where = f"{spec.get('path') or spec.get('service')}  ({e})"
            print(f"  {mark} {spec['name']:22} {where}")
        if v.get("identity"):
            print(f"  identity: {live_identity(v) or '(not logged in / unreadable)'}")
        names, unknown = running_state(v, pt)
        if names:
            print(f"  running: {', '.join(names)}")
        elif unknown:
            print("  running: unknown")


# ------------------------------------------------------------------------------ GUI
GUI_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>aiswitch</title>
<style>
:root{--bg:#14181c;--panel:#1e2327;--panel2:#272d33;--line:#343b42;--text:#e6e9ec;--dim:#8d97a1;
--acc:#4f9dff;--ok:#3ccf7a;--bad:#ff5d5d;--warn:#f0b34a}
@media (prefers-color-scheme:light){:root{--bg:#f2f4f6;--panel:#fff;--panel2:#eef1f4;--line:#d7dce1;--text:#1b2025;--dim:#667380;--acc:#1d6fe0;--ok:#16a05a;--bad:#d93636;--warn:#b57a10}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
header{display:flex;align-items:center;gap:12px;padding:14px 20px;border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:2}
header h1{font-size:16px;margin:0;font-weight:650}header span{color:var(--dim)}
main{max-width:1000px;margin:0 auto;padding:20px 16px 80px;display:grid;gap:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.ch{display:flex;align-items:center;gap:10px;padding:12px 16px;border-bottom:1px solid var(--line)}
.ch h2{font-size:15px;margin:0;font-weight:600}.tag{font-size:11px;color:var(--dim);border:1px solid var(--line);border-radius:99px;padding:1px 8px}
.tag.run{color:var(--warn);border-color:var(--warn)}.sp{flex:1}
.acc{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--line)}
.acc:last-of-type{border-bottom:0}.acc.on{background:color-mix(in srgb,var(--ok) 9%,transparent)}
.dot{width:10px;height:10px;border-radius:50%;border:2px solid var(--dim);flex:none}.on .dot{background:var(--ok);border-color:var(--ok)}
.nm{font-weight:600}.sub{color:var(--dim);font-size:12px;overflow-wrap:anywhere}.grow{flex:1;min-width:0}
.empty{padding:14px 16px;color:var(--dim)}
.foot{display:flex;gap:8px;flex-wrap:wrap;padding:12px 16px;background:var(--panel2);align-items:center}
button,input,select{font:inherit;color:var(--text);background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:6px 12px}
.foot input,.foot select{background:var(--panel);min-width:130px}
button{cursor:pointer}button:hover{border-color:var(--acc)}button.p{background:var(--acc);border-color:var(--acc);color:#fff}
button.d:hover{border-color:var(--bad);color:var(--bad)}button:disabled{opacity:.5;cursor:default}
.hint{font-size:12px;color:var(--dim);padding:0 16px 12px;background:var(--panel2)}
#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--acc);
border-radius:8px;padding:10px 16px;max-width:90vw;box-shadow:0 8px 30px #0006;display:none;white-space:pre-wrap;z-index:5}
#toast.err{border-left-color:var(--bad)}#toast.ok{border-left-color:var(--ok)}
dialog{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:12px;max-width:440px;padding:20px}
dialog::backdrop{background:#0008}dialog p{margin:0 0 16px;white-space:pre-wrap}dialog .row{display:flex;gap:8px;justify-content:flex-end}
</style></head><body>
<header><h1>aiswitch</h1><span>switch accounts for your AI tools</span><div class="sp"></div><button id="refresh">Refresh</button></header>
<main id="main"><div class="empty">Loading…</div></main>
<div id="toast"></div>
<dialog id="dlg"><p id="dmsg"></p><div class="row"><button id="dno">Cancel</button><button id="dyes" class="p">Continue</button></div></dialog>
<script>
const TOKEN=new URLSearchParams(location.search).get("t")||sessionStorage.getItem("t")||"";
try{sessionStorage.setItem("t",TOKEN)}catch(e){}
history.replaceState(null,"",location.pathname);
const $=(t,a={},...k)=>{const e=document.createElement(t);for(const[x,v]of Object.entries(a)){if(x==="class")e.className=v;else if(x.startsWith("on"))e.addEventListener(x.slice(2),v);else if(v!==false&&v!=null)e.setAttribute(x,v===true?"":v)}
for(const c of k.flat())if(c!=null)e.append(c.nodeType?c:document.createTextNode(c));return e};
async function api(path,body){const r=await fetch(path,{method:body?"POST":"GET",headers:{"X-Token":TOKEN,"Content-Type":"application/json"},body:body?JSON.stringify(body):undefined});
const j=await r.json().catch(()=>({ok:false,error:"bad response"}));return j}
let tt;function toast(m,k){const t=document.getElementById("toast");t.textContent=m;t.className=k||"";t.style.display="block";clearTimeout(tt);tt=setTimeout(()=>t.style.display="none",k==="err"?7000:3500)}
function confirmDlg(msg,yes){return new Promise(res=>{const d=document.getElementById("dlg");document.getElementById("dmsg").textContent=msg;
const y=document.getElementById("dyes"),n=document.getElementById("dno");y.textContent=yes||"Continue";
const done=v=>{y.onclick=n.onclick=null;d.close();res(v)};y.onclick=()=>done(true);n.onclick=()=>done(false);d.oncancel=()=>done(false);d.showModal()})}
async function act(body){
  let r=await api("/api/action",body);
  for(let i=0;i<2&&!r.ok;i++){
    if(r.code==="unsaved"&&await confirmDlg("The login currently on this machine isn't saved under any name.\nReplace it anyway? A backup is kept.","Replace")){body={...body,force:true};r=await api("/api/action",body)}
    else if(r.code==="app_running"&&await confirmDlg(r.error.split(".")[0]+".\nQuit it now and continue?","Quit & continue")){body={...body,quit:true};r=await api("/api/action",body)}
    else break}
  if(r.ok){toast(r.message||"Done","ok")}else if(r.code!=="unsaved"&&r.code!=="app_running"){toast(r.error||"Failed","err")}
  load()}
function card(p){
  const foot=$("div",{class:"foot"});
  if(p.kind==="browser"){
    const sel=$("select",{},$("option",{value:""},"Browser profile…"),p.profiles.map(x=>$("option",{value:x.dir},x.name)));
    const nm=$("input",{placeholder:"account name"});
    foot.append(sel,nm,$("button",{onclick:()=>{if(!sel.value||!nm.value)return toast("Pick a profile and enter a name","err");act({op:"save",platform:p.id,name:nm.value.trim(),profile:sel.value})}},"Link profile"));
  }else{
    const nm=$("input",{placeholder:"name for current login"});
    foot.append(nm,$("button",{class:"p",onclick:()=>{if(!nm.value)return toast("Enter a name","err");act({op:"save",platform:p.id,name:nm.value.trim()})}},"Save current login"),
      $("button",{onclick:async()=>{const n=prompt("Name for the NEW account (you'll log in to it next):");if(n)act({op:"new",platform:p.id,name:n.trim()})}},"Add new account…"));
  }
  const list=p.accounts.length?p.accounts.map(a=>$("div",{class:"acc"+(a.name===p.current?" on":"")},$("span",{class:"dot"}),
    $("div",{class:"grow"},$("div",{class:"nm"},a.name),$("div",{class:"sub"},a.detail||"",a.detail?" · ":"","saved ",a.saved_at||"?")),
    $("button",{class:"p",disabled:a.name===p.current&&p.kind!=="browser",onclick:()=>act({op:"use",platform:p.id,name:a.name,launch:p.kind==="app"})},p.kind==="browser"?"Open":(a.name===p.current?"Active":"Switch")),
    $("button",{class:"d",title:"Delete saved account",onclick:async()=>{if(await confirmDlg(`Delete saved account "${a.name}" (${p.label})? This can't be undone.`,"Delete"))act({op:"rm",platform:p.id,name:a.name})}},"✕")))
    :[$("div",{class:"empty"},"No saved accounts yet.")];
  const hint=p.kind==="login"?$("div",{class:"hint"},"To add another account: “Add new account”, then "+p.login_hint+", then “Save current login”."):null;
  return $("section",{class:"card"},$("div",{class:"ch"},$("h2",{},p.label),p.running?$("span",{class:"tag run"},"running"):(p.running===null?$("span",{class:"tag",title:"aiswitch cannot see all processes here"},"running?"):null),$("div",{class:"sp"}),$("span",{class:"tag"},p.id)),list,hint,foot)}
async function load(){const r=await api("/api/state");const m=document.getElementById("main");m.textContent="";
  if(!r.ok){m.append($("div",{class:"empty"},r.error||"Cannot reach aiswitch. Re-open it with `aiswitch gui`."));return}
  r.platforms.forEach(p=>m.append(card(p)))}
document.getElementById("refresh").onclick=load;load();
document.addEventListener("visibilitychange",()=>{if(!document.hidden)load()});
</script></body></html>"""


def gui_state():
    state = load_state()
    pt = proc_table(refresh=True, max_age=3)   # tasklist/PowerShell is slow on Windows
    out = []
    for k, v in load_platforms().items():
        accounts = []
        for name, meta in list_accounts(k):
            detail = _browser_detail(meta) if meta.get("kind") == "browser" else meta.get("identity") or ""
            accounts.append({"name": name, "detail": detail.replace("|", " · "), "saved_at": meta.get("saved_at")})
        cur, _ = current_account(k, v, state)
        b = select_browser(v) if v["kind"] == "browser" else None
        running = False
        if v["kind"] != "browser":
            names, unknown = running_state(v, pt)
            running = True if names else (None if unknown else False)
        out.append({
            "id": k, "label": v["label"], "kind": v["kind"], "accounts": accounts, "current": cur,
            "login_hint": v.get("login_hint", ""), "running": running,
            "profiles": ([{"dir": d, "name": n} for d, n in chrome_profiles(b).items()] if b else []),
        })
    return out


def gui_action(body):
    import io
    op = body.get("op")
    if op not in ("use", "save", "new", "rm"):
        die("unknown action")
    ns = argparse.Namespace(platform=str(body.get("platform", "")), name=str(body.get("name", "")),
                            force=bool(body.get("force")), quit=bool(body.get("quit")),
                            launch=bool(body.get("launch")), profile=body.get("profile"), yes=True,
                            writeback=False, allow_duplicate=False, allow_empty=False)
    fn = {"use": cmd_use, "save": cmd_save, "new": cmd_new, "rm": cmd_rm}[op]
    buf = io.StringIO()
    # redirect_stdout is process-global: the HTTP server handles one request at a time.
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        fn(ns)
    lines = [re.sub(r"\x1b\[[0-9;]*m", "", ln).strip() for ln in buf.getvalue().splitlines() if ln.strip()]
    return "\n".join(lines)


def make_gui_server(port=0):
    """Returns (server, url). Separate from cmd_gui so tests can drive it."""
    import http.server
    import socket

    token = secrets.token_urlsafe(24)
    port_holder = {}

    class Server(http.server.HTTPServer):
        # On Windows SO_REUSEADDR would let another local process bind the same port and
        # intercept the token URL; use SO_EXCLUSIVEADDRUSE there instead.
        allow_reuse_address = os.name != "nt"

        def server_bind(self):
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                with contextlib.suppress(OSError):
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    class H(http.server.BaseHTTPRequestHandler):
        server_version = "aiswitch"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(data)

        def _host_ok(self):
            # Blocks DNS-rebinding: only accept our own loopback host:port.
            return self.headers.get("Host", "") in (f"127.0.0.1:{port_holder['p']}", f"localhost:{port_holder['p']}")

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, json.dumps({"ok": False, "error": "bad host"}))
            path = self.path.split("?")[0]
            if path == "/":
                return self._send(200, GUI_HTML, "text/html")
            if path == "/api/state":
                if not secrets.compare_digest(self.headers.get("X-Token", ""), token):
                    return self._send(401, json.dumps({"ok": False, "error": "session expired - re-run `aiswitch gui`"}))
                try:
                    return self._send(200, json.dumps({"ok": True, "platforms": gui_state()}))
                except Exception as e:
                    return self._send(500, json.dumps({"ok": False, "error": str(e)}))
            self._send(404, json.dumps({"ok": False, "error": "not found"}))

        def do_POST(self):
            if not self._host_ok():
                return self._send(403, json.dumps({"ok": False, "error": "bad host"}))
            if self.path != "/api/action" or not secrets.compare_digest(self.headers.get("X-Token", ""), token):
                return self._send(401, json.dumps({"ok": False, "error": "unauthorized"}))
            if "application/json" not in self.headers.get("Content-Type", ""):
                return self._send(415, json.dumps({"ok": False, "error": "json only"}))
            try:
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
                if not isinstance(body, dict):
                    raise Fatal("bad request")
                msg = gui_action(body)
                self._send(200, json.dumps({"ok": True, "message": msg}))
            except Fatal as e:
                self._send(200, json.dumps({"ok": False, "error": str(e), "code": e.code}))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))

    srv = Server(("127.0.0.1", port), H)
    port_holder["p"] = srv.server_address[1]
    srv.aiswitch_token = token
    return srv, f"http://127.0.0.1:{port_holder['p']}/?t={token}"


def open_url(url):
    """Open the GUI in a graphical browser. Returns False when there is none to use (headless
    POSIX: Python would otherwise run a console browser like lynx in the foreground)."""
    if is_wsl():
        for cmd in (["wslview", url], ["explorer.exe", url]):
            if shutil.which(cmd[0]):
                with contextlib.suppress(OSError):
                    _spawn_detached(cmd)
                    return True
    if host_os() == "linux" and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
                                     or os.environ.get("BROWSER")):
        return False
    import webbrowser
    try:
        return bool(webbrowser.open(url))
    except Exception:
        return False


def cmd_gui(args):
    srv, url = make_gui_server(args.port)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()                                  # serve before any browser connects
    print(f"aiswitch GUI running at {url}\nPress Ctrl-C to stop.", flush=True)
    if not args.no_open and not open_url(url):
        print("(no graphical browser available - open the URL above yourself)", flush=True)
    try:
        while t.is_alive():
            t.join(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
        srv.server_close()


def build_parser():
    ap = argparse.ArgumentParser(prog="aiswitch", description="Switch accounts for AI tools "
                                 "(Claude Code, Codex, Gemini CLI, Claude Desktop, web).")
    ap.add_argument("--version", action="version", version=VERSION)
    ap.add_argument("--debug", action="store_true", help="show tracebacks for unexpected errors")
    sub = ap.add_subparsers(dest="cmd")

    def add(name, fn, help_, *aliases):
        p = sub.add_parser(name, help=help_, aliases=list(aliases))
        p.set_defaults(func=fn)
        return p

    add("platforms", cmd_platforms, "list supported platforms")
    p = add("init", cmd_init, "write an editable platforms.json (overrides) to ~/.aiswitch")
    p.add_argument("--force", action="store_true", help="overwrite (the old file is kept as .bak)")
    p.add_argument("--show-defaults", action="store_true", help="print the built-in definitions")
    p = add("ls", cmd_ls, "list saved accounts", "list")
    p.add_argument("platform", nargs="?")
    p = add("current", cmd_current, "show which account is active")
    p.add_argument("platform", nargs="?")
    p = add("profiles", cmd_profiles, "list browser profiles (for web platforms)")
    p.add_argument("platform", nargs="?")
    p = add("save", cmd_save, "save the login currently on this machine as <name>")
    p.add_argument("platform")
    p.add_argument("name")
    p.add_argument("--force", action="store_true", help="overwrite an existing saved account")
    p.add_argument("--profile", help="(web platforms) browser profile name or directory")
    p.add_argument("--quit", action="store_true", help="quit the desktop app first if it's running")
    p.add_argument("--allow-duplicate", action="store_true",
                   help="save even if this login is already saved under another name")
    p.add_argument("--allow-empty", action="store_true",
                   help="save even if no login is found (a logged-out state)")
    p = add("use", cmd_use, "switch to a saved account", "switch")
    p.add_argument("platform")
    p.add_argument("name")
    p.add_argument("--force", action="store_true", help="replace an unsaved current login")
    p.add_argument("--quit", action="store_true", help="quit the desktop app first if it's running")
    p.add_argument("--launch", action="store_true", help="relaunch the desktop app afterwards")
    p.add_argument("--writeback", action="store_true",
                   help="(apps without identity check) sync the live login back into the last-used account")
    p = add("new", cmd_new, "log out locally so you can sign in to a new account")
    p.add_argument("platform")
    p.add_argument("name")
    p.add_argument("--force", action="store_true")
    p.add_argument("--quit", action="store_true")
    p.add_argument("--writeback", action="store_true")
    p = add("rm", cmd_rm, "delete a saved account")
    p.add_argument("platform")
    p.add_argument("name")
    p.add_argument("-y", "--yes", action="store_true")
    p = add("purge", cmd_purge, "delete ALL saved accounts and backups (live logins untouched)")
    p.add_argument("-y", "--yes", action="store_true")
    add("doctor", cmd_doctor, "check paths, secret stores and running apps")
    p = add("gui", cmd_gui, "open the graphical switcher in your browser (local only)")
    p.add_argument("--port", type=int, default=0, help="port (default: random free port)")
    p.add_argument("--no-open", "--no-browser", dest="no_open", action="store_true",
                   help="don't open a browser automatically")
    return ap


def check_runtime():
    if sys.platform in ("cygwin", "msys") or sys.platform.startswith("msys"):
        die("Cygwin/MSYS Python can't manage the Windows tools' files and processes reliably. Use a "
            "native Windows Python (python.org, `winget install Python.Python.3.13`, or the `py` "
            "launcher), or run aiswitch inside WSL for WSL-side tools.")
    check_privileges()


def main(argv=None):
    global DEBUG, _PROC_CACHE
    setup_console()
    args = build_parser().parse_args(argv)
    DEBUG = args.debug or bool(os.environ.get("AISWITCH_DEBUG"))
    _PROC_CACHE = None
    if threading.current_thread() is threading.main_thread():
        install_signal_handlers()
    try:
        check_runtime()
        ensure_root()
        if not getattr(args, "func", None):
            args = build_parser().parse_args(["ls"])
        args.func(args)
    except Fatal as e:
        with contextlib.suppress(OSError):
            print(f"error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:
        with contextlib.suppress(OSError):
            sys.stdout = open(os.devnull, "w")
        return 0
    except Exception as e:
        if DEBUG:
            raise
        with contextlib.suppress(OSError):
            print(f"error: unexpected {type(e).__name__}: {e}\n(run with --debug for a traceback)",
                  file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
