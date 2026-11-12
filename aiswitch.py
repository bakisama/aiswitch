#!/usr/bin/env python3
"""aiswitch - a TcNo-Account-Switcher-style switcher for AI tool logins.

It freezes the login state of a tool (Claude Code, Codex CLI, Gemini CLI,
Claude Desktop, ...) per account, and swaps a saved copy back in on demand.
No passwords are ever asked for or stored by this tool: it only moves around
the credential files / Keychain items the tools already create themselves.

Platforms are defined by a small config (see DEFAULT_PLATFORMS, or run
`aiswitch init` and edit ~/.aiswitch/platforms.json).

Platform-specific modules (fcntl, msvcrt, ctypes.windll) are imported lazily so
this file imports on every OS.
"""
from __future__ import annotations

import argparse
import base64
import collections
import contextlib
import copy
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

VERSION = "0.2.0"
SNAPSHOT_SCHEMA = 2      # meta.json format (1 = legacy, path-derived keychain refs)
CONFIG_SCHEMA = 1        # platforms.json format (absent = legacy whole-entry replacement)
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
ARTIFACT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,59}$")
WIN_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
KEEP_BACKUPS = 5
OSES = ("darwin", "linux", "windows")
VAULT_PREFIX = "aiswitch:"
DEBUG = False

CHROME_DIR = {
    "darwin": "~/Library/Application Support/Google/Chrome",
    "linux": "{xdg_config}/google-chrome",
    "windows": "{localappdata}/Google/Chrome/User Data",
}
DESKTOP_DIR = "~/Library/Application Support/Claude"
CLAUDE_DIR = "{env:CLAUDE_CONFIG_DIR|~/.claude}"
CLAUDE_JSON = "{env:CLAUDE_CONFIG_DIR|~}/.claude.json"
CODEX_DIR = "{env:CODEX_HOME|~/.codex}"


def _desk(name, typ, rel, **kw):
    return {"name": name, "type": typ, "path": f"{DESKTOP_DIR}/{rel}", **kw}


def _web(label, url):
    return {"label": f"{label} (web, via Chrome profile)", "kind": "browser", "browser": "Google Chrome",
            "user_data": CHROME_DIR, "url": url}


# Artifact types:
#   file       copy one file
#   dir        copy a directory tree
#   json_keys  copy only some top-level keys of a JSON file (rest of the file is left alone)
#   keychain   a macOS Keychain generic-password item (by service name)
# "primary": true marks the artifacts that mean "a login exists".
# "identity" lets aiswitch tell which saved account is currently live (so refreshed
# tokens are written back to the right snapshot, never the wrong one).
# "path" is a template (see resolve_path) or a dict {"darwin": ..., "linux": ..., "windows": ...};
# an artifact whose path has no entry for this OS is skipped.
DEFAULT_PLATFORMS = {
    "claude-code": {
        "label": "Claude Code",
        "aliases": ["cc"],
        "kind": "login",
        "processes": ["claude"],
        "process_match": ["@anthropic-ai/claude-code"],
        "login_hint": "run `claude`, then /login",
        "artifacts": [
            {"name": "keychain", "type": "keychain", "service": "Claude Code-credentials",
             "primary": True, "os": ["darwin"]},
            {"name": "credentials", "type": "file", "path": f"{CLAUDE_DIR}/.credentials.json",
             "primary": True, "os": ["linux", "windows"]},
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
        "artifacts": [
            {"name": "auth", "type": "file", "path": f"{CODEX_DIR}/auth.json", "primary": True},
        ],
        "identity": [
            {"file": f"{CODEX_DIR}/auth.json", "path": "tokens.id_token", "jwt_claim": "email"},
            {"file": f"{CODEX_DIR}/auth.json", "path": "tokens.account_id"},
        ],
    },
    "gemini": {
        "label": "Gemini CLI",
        "aliases": ["gem"],
        "kind": "login",
        "processes": ["gemini"],
        "process_match": ["@google/gemini-cli"],
        "login_hint": "run `gemini` and choose 'Login with Google'",
        "artifacts": [
            {"name": "oauth", "type": "file", "path": "~/.gemini/oauth_creds.json", "primary": True},
            {"name": "accounts", "type": "file", "path": "~/.gemini/google_accounts.json"},
        ],
        "identity": [
            {"file": "~/.gemini/google_accounts.json", "path": "active"},
        ],
    },
    "claude-desktop": {
        "label": "Claude Desktop (experimental)",
        "aliases": ["cd"],
        "kind": "app",
        "app": "Claude",
        "os": ["darwin"],
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
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
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
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    return "linux"


def home():
    # On native Windows $HOME is often set by Git Bash/MSYS to something the tools don't use;
    # the tools themselves use %USERPROFILE%, which is what Path.home() returns there.
    if sys.platform == "win32":
        return Path.home()
    return Path(os.environ.get("HOME") or str(Path.home()))


_TOKEN_RE = re.compile(r"\{([a-z_]+)(?::([^{}]*))?\}")
_VAR_RE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")


def resolve_path(tpl, os_tag, env, home_dir):
    """Pure path-template resolver (testable for every OS on any runner).

    tpl: string, or dict keyed by OS tag (optionally "default"); returns None if this
    OS has no entry. Tokens: ~, {home}, {appdata}, {localappdata}, {xdg_config},
    {env:VAR|default}, $VAR / ${VAR}. Returns a string using '/' separators."""
    if isinstance(tpl, dict):
        tpl = tpl.get(os_tag, tpl.get("default"))
    if tpl is None:
        return None
    home_dir = str(home_dir).replace("\\", "/").rstrip("/") or "/"

    def tilde(s):
        if s == "~" or s.startswith("~/") or s.startswith("~\\"):
            return home_dir + s[1:]
        return s

    def env_or(var, fallback):
        v = env.get(var)
        return v.replace("\\", "/") if v else fallback

    def tok(m):
        name, arg = m.group(1), m.group(2)
        if name == "home":
            return home_dir
        if name == "appdata":
            return env_or("APPDATA", home_dir + "/AppData/Roaming")
        if name == "localappdata":
            return env_or("LOCALAPPDATA", home_dir + "/AppData/Local")
        if name == "xdg_config":
            return env_or("XDG_CONFIG_HOME", home_dir + "/.config")
        if name == "env" and arg:
            var, _, default = arg.partition("|")
            v = env.get(var.strip())
            return v.replace("\\", "/") if v else tilde(default)
        raise Fatal(f"unknown path token '{m.group(0)}' in '{tpl}'")

    s = tilde(str(tpl))
    s = _TOKEN_RE.sub(tok, s)
    s = _VAR_RE.sub(lambda m: env.get(m.group(1) or m.group(2), m.group(0)), s)
    return tilde(s)


def expand(tpl):
    p = resolve_path(tpl, host_os(), os.environ, home())
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


def replace_file(src, dst):
    _retry(os.replace, str(src), str(dst))


def real_target(p):
    """Dotfile managers symlink credential files; write/delete the file the link points at."""
    p = Path(p)
    return Path(os.path.realpath(p)) if p.is_symlink() else p


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
        os.chmod(tmp, mode)
        replace_file(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def remove_file(p):
    p = real_target(p)
    with contextlib.suppress(FileNotFoundError):
        _retry(os.unlink, str(p))


def rmtree_force(p):
    """rmtree that clears read-only flags (Windows) and tolerates vanished entries."""
    def fix(func, path, _exc):
        if not os.path.lexists(path):
            return
        with contextlib.suppress(OSError):
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD | (stat.S_IEXEC if os.path.isdir(path) else 0))
        func(path)
    if not os.path.lexists(p):
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(p, onexc=fix)
    else:
        shutil.rmtree(p, onerror=fix)


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
        os.chmod(r, 0o700)


def _try_lock(f):
    if os.name == "nt":
        import msvcrt
        try:
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


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


# --------------------------------------------------------------------------- processes
INTERPRETERS = {"node", "nodejs", "bun", "deno", "python", "python3", "pythonw"}
_PROC_CACHE = None
PROC_PROVIDER = None     # tests: a callable returning [(pid, exe, argv), ...] or None


def _base(path):
    return re.split(r"[\\/]", path.rstrip("\\/"))[-1] if path else ""


def _norm(name):
    name = name.lower() if host_os() in ("windows", "darwin") else name
    for ext in (".exe", ".cmd", ".js", ".mjs", ".cjs", ".py"):
        if name.lower().endswith(ext):
            return name[: -len(ext)]
    return name


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
                exe = _base(os.readlink(f"/proc/{pid}/exe"))
            except OSError:
                exe = _base(argv[0]) if argv else ""
        except OSError:
            continue
        out.append((int(pid), exe, argv))
    return out


def _run_quiet(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout if r.returncode == 0 else None


def _procs_ps():
    uid = str(os.getuid())
    comm = _run_quiet(["ps", "-A", "-o", "pid=", "-o", "uid=", "-o", "comm="])
    args = _run_quiet(["ps", "-A", "-o", "pid=", "-o", "args="])
    if comm is None:
        return None
    argmap = {}
    for line in (args or "").splitlines():
        parts = line.strip().split(None, 1)
        if parts and parts[0].isdigit():
            argmap[int(parts[0])] = parts[1].split() if len(parts) > 1 else []
    out = []
    for line in comm.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3 or not parts[0].isdigit() or parts[1] != uid:
            continue
        pid = int(parts[0])
        if pid != os.getpid():
            out.append((pid, _base(parts[2]), argmap.get(pid, [parts[2]])))
    return out


def _procs_windows():
    user = os.environ.get("USERNAME", "")
    tl = _run_quiet(["tasklist", "/FO", "CSV", "/NH", "/FI", f"USERNAME eq {user}"]) if user else None
    if tl is None:
        tl = _run_quiet(["tasklist", "/FO", "CSV", "/NH"])
    if tl is None:
        return None
    mine = {}
    for line in tl.splitlines():
        cols = re.findall(r'"([^"]*)"', line)
        if len(cols) >= 2 and cols[1].isdigit():
            mine[int(cols[1])] = cols[0]
    cmdlines = {}
    ps = _run_quiet(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     "Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | "
                     "ConvertTo-Json -Compress"], timeout=20)
    with contextlib.suppress(ValueError, TypeError):
        data = json.loads(ps) if ps else []
        for p in data if isinstance(data, list) else [data]:
            if p.get("CommandLine"):
                cmdlines[int(p["ProcessId"])] = [a.strip('"') for a in
                                                 re.findall(r'"[^"]*"|\S+', p["CommandLine"])]
    return [(pid, exe, cmdlines.get(pid, [exe])) for pid, exe in mine.items() if pid != os.getpid()]


class ProcTable:
    def __init__(self, procs):
        self.procs = procs          # None = detection unavailable

    def matches(self, name, patterns=()):
        if self.procs is None:
            return None
        n = _norm(name)
        hits = []
        for pid, exe, argv in self.procs:
            joined = " ".join(argv)
            hit = _norm(exe) == n or (argv and _norm(_base(argv[0])) == n)
            if not hit and argv and _norm(_base(argv[0])) in INTERPRETERS:
                script = next((a for a in argv[1:] if not a.startswith("-")), "")
                hit = _norm(_base(script)) == n
            if not hit and patterns:
                hit = any(p in joined for p in patterns)
            if hit:
                hits.append(pid)
        return hits

    def running(self, name, patterns=()):
        m = self.matches(name, patterns)
        return None if m is None else bool(m)


def proc_table(refresh=False):
    global _PROC_CACHE
    if _PROC_CACHE is None or refresh:
        if PROC_PROVIDER is not None:
            procs = PROC_PROVIDER()
        elif host_os() == "windows":
            procs = _procs_windows() if sys.platform == "win32" else None
        elif os.path.isdir("/proc/self") and sys.platform.startswith("linux"):
            procs = _procs_linux()
        elif hasattr(os, "getuid"):
            procs = _procs_ps()
        else:
            procs = None
        _PROC_CACHE = ProcTable(procs)
    return _PROC_CACHE


def app_procs(pcfg):
    return pcfg.get("processes") or ([pcfg["app"]] if pcfg.get("app") else [])


def running_state(pcfg, pt=None):
    """Return (list of running process names, unknown: bool)."""
    pt = pt or proc_table()
    names, unknown = [], False
    for name in app_procs(pcfg):
        r = pt.running(name, pcfg.get("process_match", ()))
        if r is None:
            unknown = True
        elif r:
            names.append(name)
    return names, unknown


def quit_app(pcfg):
    app = pcfg.get("app")
    if host_os() == "darwin" and app:
        subprocess.run(["osascript", "-e", f'tell application "{app}" to quit'], capture_output=True)
        return
    for name in app_procs(pcfg):
        for pid in proc_table().matches(name, pcfg.get("process_match", ())) or []:
            if host_os() == "windows":
                subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True)
            else:
                import signal
                with contextlib.suppress(OSError):
                    os.kill(pid, signal.SIGTERM)


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
        if host_os() == "windows" and isinstance(cmd, str):
            os.startfile(str(expand(cmd)))  # noqa
        else:
            _spawn_detached([str(expand(x)) for x in (cmd if isinstance(cmd, list) else [cmd])])
        return True
    except OSError as e:
        warn(f"could not launch {pcfg['label']}: {e}")
        return False


def _spawn_detached(cmd):
    kw = {"stdin": subprocess.DEVNULL, "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        kw["creationflags"] = 0x00000008 | 0x00000200   # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    subprocess.Popen(cmd, **kw)


# --------------------------------------------------------------------- secret stores
class SecretStore:
    """Generic-password store. Contract:
    account(service) -> account name, or None if the item is definitely absent.
    read(service)    -> {"account", "secret"}, or None if definitely absent.
    write(service, account, secret)   create or update in place.
    replace(service, account, secret) make (service, account, secret) the only item for service:
                                      write first, then remove items under other accounts.
    delete(service)  -> True if something was deleted, False if absent.
    Any other failure (locked keychain, denied prompt, no GUI session) raises Fatal - it must
    never be reported as "absent", or aiswitch would skip a backup and overwrite a live login."""

    name = "abstract"

    def delete_all(self, service):
        for _ in range(20):
            if not self.delete(service):
                return
        die(f"could not remove all keychain items for '{service}'", "keychain")

    def replace(self, service, account, secret):
        self.write(service, account, secret)


class MemoryStore(SecretStore):
    name = "memory"

    def __init__(self):
        self.items = {}
        self.fail = set()       # ops to fail, for tests: {"read", "write", "delete"}

    def _chk(self, op):
        if op in self.fail:
            die(f"simulated keychain failure on {op}", "keychain")

    def account(self, service):
        self._chk("read")
        it = self.items.get(service)
        return it["account"] if it else None

    def read(self, service):
        self._chk("read")
        it = self.items.get(service)
        return dict(it) if it else None

    def write(self, service, account, secret):
        self._chk("write")
        self.items[service] = {"account": account, "secret": secret}

    def delete(self, service):
        self._chk("delete")
        return self.items.pop(service, None) is not None


class FileStore(SecretStore):
    """A plain directory (AISWITCH_KEYCHAIN_DIR), for tests and experiments only."""
    name = "file"

    def __init__(self, d):
        self.d = Path(d)
        self.d.mkdir(parents=True, exist_ok=True)

    def _f(self, service):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", service)[:60]
        return self.d / f"{safe}-{hashlib.sha1(service.encode()).hexdigest()[:10]}.json"

    def read(self, service):
        f = self._f(service)
        if not f.exists():
            return None
        data = read_json(f)
        if not isinstance(data, dict):
            die(f"unreadable secret file {f}", "keychain")
        return data

    def account(self, service):
        it = self.read(service)
        return it["account"] if it else None

    def write(self, service, account, secret):
        atomic_write_bytes(self._f(service), dump_json({"account": account, "secret": secret}))

    def delete(self, service):
        f = self._f(service)
        if f.exists():
            remove_file(f)
            return True
        return False


class MacKeychain(SecretStore):
    """macOS Keychain via /usr/bin/security. Exit 44 (errSecItemNotFound) means absent;
    every other non-zero exit is a hard error. Secrets are written through `security -i`
    on stdin (hex encoded) so they never appear in a process argv visible to `ps`."""
    name = "macos-keychain"
    NOT_FOUND = 44

    def __init__(self):
        self.used_argv_fallback = False

    @staticmethod
    def _sec(args, stdin=None):
        try:
            return subprocess.run(["security", *args], input=stdin, capture_output=True, text=True,
                                  timeout=60)
        except FileNotFoundError:
            die("`security` not found - the keychain features need macOS", "keychain")
        except subprocess.TimeoutExpired:
            die("`security` timed out (is a keychain prompt waiting for an answer?)", "keychain")

    def _fail(self, what, service, r):
        die(f"keychain {what} for '{service}' failed (security exit {r.returncode}: "
            f"{(r.stderr or '').strip() or 'no message'}). The keychain may be locked, access was "
            "denied, or there is no GUI session (SSH). Nothing was changed.", "keychain")

    @staticmethod
    def _parse_acct(out):
        m = re.search(r'"acct"<blob>=(?:0x([0-9A-Fa-f]+)\s*)?(?:"((?:[^"\\]|\\.)*)"|<NULL>)', out)
        if not m:
            return getpass.getuser()
        if m.group(1):
            with contextlib.suppress(ValueError):
                return bytes.fromhex(m.group(1)).decode("utf-8")
        return m.group(2) if m.group(2) is not None else ""

    def account(self, service, account=None):
        args = ["find-generic-password", "-s", service] + (["-a", account] if account else [])
        r = self._sec(args)
        if r.returncode == self.NOT_FOUND:
            return None
        if r.returncode != 0:
            self._fail("lookup", service, r)
        return self._parse_acct(r.stdout + r.stderr)

    def read(self, service):
        acct = self.account(service)
        if acct is None:
            return None
        r = self._sec(["find-generic-password", "-s", service, "-w"])
        if r.returncode == self.NOT_FOUND:
            return None
        if r.returncode != 0:
            self._fail("read", service, r)
        secret = r.stdout[:-1] if r.stdout.endswith("\n") else r.stdout
        return {"account": acct, "secret": secret}

    @staticmethod
    def _q(s):
        if any(ch in s for ch in '"\\\n\r'):
            return None
        return f'"{s}"'

    def _secret_of(self, service, account):
        r = self._sec(["find-generic-password", "-s", service, "-a", account, "-w"])
        if r.returncode != 0:
            return None
        return r.stdout[:-1] if r.stdout.endswith("\n") else r.stdout

    def write(self, service, account, secret):
        qs, qa = self._q(service), self._q(account)
        if qs and qa:
            hexd = secret.encode("utf-8").hex()
            self._sec(["-i"], f"add-generic-password -U -s {qs} -a {qa} -X {hexd}\n")
            if self._secret_of(service, account) == secret:
                return
        # stdin route unavailable or did not verify: fall back to argv (briefly visible in `ps`).
        self.used_argv_fallback = True
        warn_once("kc-argv", "keychain write via stdin did not verify; falling back to passing the "
                             "secret on the `security` command line")
        r = self._sec(["add-generic-password", "-U", "-s", service, "-a", account, "-w", secret])
        if r.returncode != 0:
            self._fail("write", service, r)
        if self._secret_of(service, account) != secret:
            die(f"keychain write for '{service}' did not verify", "keychain")

    def delete(self, service, account=None):
        args = ["delete-generic-password", "-s", service] + (["-a", account] if account else [])
        r = self._sec(args)
        if r.returncode == self.NOT_FOUND:
            return False
        if r.returncode != 0:
            self._fail("delete", service, r)
        return True

    def replace(self, service, account, secret):
        prior = self.account(service)
        self.write(service, account, secret)      # -U: updates in place, keeps the item's ACL
        if prior is not None and prior != account:
            self.delete(service, prior)


class NoStore(SecretStore):
    name = "none"

    def _no(self, *a):
        die("keychain artifacts are only supported on macOS in this version "
            "(set AISWITCH_KEYCHAIN_DIR for testing)", "keychain")

    account = read = write = delete = _no


Stores = collections.namedtuple("Stores", "live vault")
STORE_FACTORY = None     # tests: a callable returning Stores


def stores():
    if STORE_FACTORY is not None:
        return STORE_FACTORY()
    d = os.environ.get("AISWITCH_KEYCHAIN_DIR")
    if d:
        s = FileStore(d)
    elif host_os() == "darwin":
        s = MacKeychain()
    else:
        s = NoStore()
    # The live store (where the tool keeps its secret) and the vault (where aiswitch keeps
    # copies) are the same keychain today; they are kept separate in the API so a future
    # backend (e.g. Windows, with its 2560-byte blob cap) can put the vault elsewhere.
    return Stores(s, s)


# ------------------------------------------------------------------------- config
def _validate_platform(k, v):
    if v.get("kind") not in ("login", "app", "browser"):
        die(f"platforms.json: '{k}' needs \"kind\": \"login\", \"app\" or \"browser\"")
    if not isinstance(v.get("label"), str):
        v["label"] = k
    seen = set()
    for a in v.get("artifacts", []):
        if not isinstance(a, dict) or not isinstance(a.get("name"), str) or \
                not ARTIFACT_NAME_RE.match(a["name"]) or a["name"] in ("meta", "pending-refs"):
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
        for k, v in entries.items():
            if not isinstance(v, dict) or k.startswith("_"):
                continue
            if v.get("disabled"):
                plats.pop(k, None)
                continue
            base_name = v.get("extends") or (k if merge else None)
            if v.get("extends") and v["extends"] not in plats:
                die(f"platforms.json: '{k}' extends unknown platform '{v['extends']}'")
            base = copy.deepcopy(plats.get(base_name, {})) if base_name else {}
            base.update({kk: vv for kk, vv in v.items() if kk != "extends"})
            plats[k] = base
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
    return p


def artifacts(pcfg):
    me = host_os()
    out = []
    for a in pcfg.get("artifacts", []):
        if me not in a.get("os", [me]):
            continue
        if a["type"] != "keychain" and expand(a["path"]) is None:
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


def cleanup_trash(plat, st):
    """Finish deletions/swaps interrupted earlier (hidden .tmp-/.old-/.del- dirs)."""
    for base in (root() / "snapshots" / plat, backup_root(plat)):
        if base.is_dir():
            for d in base.iterdir():
                if d.is_dir() and d.name.startswith(".") and re.search(r"\.(tmp|old|del)-[0-9a-f]+$", d.name):
                    purge_dir(d, st, quiet=True)


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
            shutil.copytree(p, dest / name, symlinks=True,
                            ignore=shutil.ignore_patterns("LOCK", "Singleton*"))
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
        item = st.live.read(spec["service"])          # raises on anything but "absent"
        if item:
            ref = uuid.uuid4().hex
            _record_refs(dest, [VAULT_PREFIX + ref])   # recorded first, so a crash can't orphan it
            st.vault.write(VAULT_PREFIX + ref, item["account"], item["secret"])
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
        old = hidden_sibling(p, "aiswitch-old")
        if present:
            new = hidden_sibling(p, "aiswitch-new")
            p.parent.mkdir(parents=True, exist_ok=True)
            try:
                shutil.copytree(src / name, new, symlinks=True)
                if p.exists():
                    replace_file(p, old)
                replace_file(new, p)
            except BaseException:
                if old.exists() and not p.exists():
                    replace_file(old, p)
                rmtree_force(new)
                raise
            rmtree_force(old)
        elif p.exists():
            replace_file(p, old)
            rmtree_force(old)
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
        if present:
            item = st.vault.read(vault_key(src, name, ent))
            if not item:
                die(f"saved keychain entry for '{name}' is missing")
            st.live.replace(spec["service"], item["account"], item["secret"])
        else:
            st.live.delete_all(spec["service"])


def probe(spec, st):
    t = spec["type"]
    if t == "keychain":
        return st.live.account(spec["service"]) is not None   # no -w: no keychain prompt
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


def live_identity(pcfg):
    parts = pcfg.get("identity")
    if not parts:
        return None
    vals = []
    for i, part in enumerate(parts):
        f = expand(part["file"])
        data = read_json(f) if f else None
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
        meta = {"schema": SNAPSHOT_SCHEMA, "saved_at": now(), "identity": live_identity(pcfg),
                "artifacts": info}
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


def restore_all(pcfg, src, st, meta):
    arts = (meta or {}).get("artifacts") or {}
    for spec in artifacts(pcfg):
        if spec["name"] in arts:
            restore(spec, Path(src), arts[spec["name"]], st)


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


def prune_backups(plat, st):
    for d in backup_dirs(plat)[:-KEEP_BACKUPS]:
        try:
            delete_snapshot(d, st)
        except Fatal as e:
            warn(f"could not prune backup {d.name}: {e}")


def new_backup_dir(plat):
    base = time.strftime("%Y%m%d-%H%M%S")
    b, n = backup_root(plat) / base, 1
    while b.exists():
        n += 1
        b = backup_root(plat) / f"{base}-{n}"
    return b


# ------------------------------------------------------------------ switching core
def check_processes(pcfg, do_quit):
    pt = proc_table(refresh=True)
    if pcfg["kind"] == "app":
        label = pcfg.get("app") or pcfg["label"]
        names, unknown = running_state(pcfg, pt)
        if unknown and not names:
            warn_once("proc-unknown", f"cannot tell whether {label} is running on this system; "
                      "make sure it is closed before switching")
            return
        if names:
            if not do_quit:
                die(f"{label} is running. Quit it first, or pass --quit to let aiswitch close it.",
                    "app_running")
            quit_app(pcfg)
            for _ in range(40):
                time.sleep(0.25)
                if not running_state(pcfg, proc_table(refresh=True))[0]:
                    break
            else:
                die(f"could not quit {label}; close it manually and retry")
    else:
        names, unknown = running_state(pcfg, pt)
        if names:
            warn(f"{', '.join(names)} appears to be running. Existing sessions keep the old login "
                 "in memory and may write it back - restart them after switching.")
        elif unknown:
            warn_once("proc-unknown", "cannot detect running processes here; restart any open "
                      f"{pcfg['label']} sessions after switching")


def leave_current(plat, pcfg, st, force, do_quit, writeback=False):
    """Prepare to replace the live login: stop-check, write refreshed tokens back to the
    matching saved account, and back the live state up.
    Returns (matched, synced, backup_dir)."""
    check_processes(pcfg, do_quit)
    state = load_state()
    has = live_has_login(pcfg, st)
    ident = live_identity(pcfg)
    matched, synced = None, False
    if ident:
        matched = find_by_identity(plat, ident)
        synced = bool(matched)
    elif has and not pcfg.get("identity"):
        # No way to verify which account is live: the user may have signed into a different
        # account inside the app. Only write back when explicitly asked to.
        n = state["active"].get(plat)
        if n and (snap_dir(plat, n) / "meta.json").exists():
            matched = n
            synced = writeback
            if not writeback:
                print(f"  not syncing the live login back into '{n}' (aiswitch can't verify which "
                      "account it is; pass --writeback if you're sure). It is kept in a backup.")
    if matched and synced:
        old = read_json(snap_dir(plat, matched) / "meta.json") or {}
        take_snapshot(pcfg, snap_dir(plat, matched), st,
                      {"created": old.get("created", old.get("saved_at")), "kind": pcfg["kind"]})
        print(f"  synced current login back into '{matched}'")
    elif not matched and has and not force:
        die("the login currently on this machine isn't saved under any account name.\n"
            f"  Save it first:  aiswitch save {plat} <name>\n"
            "  or pass --force to replace it (a backup is kept in ~/.aiswitch/backups).", "unsaved")
    backup = None
    if has:
        backup = new_backup_dir(plat)
        take_snapshot(pcfg, backup, st, {"backup": True})
        prune_backups(plat, st)
    return matched, synced, backup


def apply_or_rollback(pcfg, st, backup, action):
    """Run action(); on failure put back the backup (or an all-absent state if there was no
    login before). The original error is always reported."""
    try:
        action()
    except BaseException as e:
        err = f"{type(e).__name__}: {e}" if not isinstance(e, Fatal) else str(e)
        try:
            if backup:
                restore_all(pcfg, backup, st, read_json(backup / "meta.json"))
                outcome = "previous login restored"
            else:
                clear_all(pcfg, st)
                outcome = "left logged out (there was no login before)"
        except BaseException as e2:
            where = f" A copy of the previous login is in {backup}." if backup else ""
            die(f"switch failed ({err}); rolling back ALSO failed ({e2}).{where}")
        die(f"switch failed ({err}); {outcome}")


# ------------------------------------------------------------------------ browsers
def chrome_profiles(pcfg):
    ud = expand(pcfg.get("user_data", CHROME_DIR))
    ls = read_json(ud / "Local State") if ud else None
    cache = get_path(ls, "profile.info_cache") if isinstance(ls, dict) else None
    if not isinstance(cache, dict):
        return {}
    return {k: (v.get("name") or k) for k, v in cache.items() if isinstance(v, dict)}


def resolve_profile(pcfg, wanted):
    profiles = chrome_profiles(pcfg)
    if wanted in profiles:
        return wanted, profiles[wanted]
    for k, n in profiles.items():
        if n.lower() == wanted.lower():
            return k, n
    if not profiles:
        warn("could not read Chrome's profile list; using the value as a profile directory name")
        return wanted, wanted
    opts = ", ".join(f"{n} ({k})" for k, n in profiles.items())
    die(f"no Chrome profile '{wanted}'. Available: {opts}")


def _chrome_binary(pcfg):
    me = host_os()
    cands = pcfg.get("browser_bin")
    if isinstance(cands, dict):
        cands = cands.get(me)
    if not cands:
        cands = {
            "linux": ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"],
            "windows": ["{localappdata}/Google/Chrome/Application/chrome.exe",
                        "{env:ProgramFiles|C:/Program Files}/Google/Chrome/Application/chrome.exe",
                        "{env:ProgramFiles(x86)|C:/Program Files (x86)}/Google/Chrome/Application/chrome.exe"],
        }.get(me, [])
    for cand in ([cands] if isinstance(cands, str) else cands):
        if "/" in cand or "{" in cand:
            p = expand(cand)
            if p and p.is_file():
                return str(p)
        elif shutil.which(cand):
            return shutil.which(cand)
    return None


def open_browser_profile(pcfg, profile):
    """Returns None on success, or an error message."""
    flag = f"--profile-directory={profile}"
    try:
        if host_os() == "darwin":
            r = subprocess.run(["open", "-na", pcfg["browser"], "--args", flag, pcfg["url"]],
                               capture_output=True, text=True)
            return None if r.returncode == 0 else (r.stderr.strip() or f"open exited {r.returncode}")
        exe = _chrome_binary(pcfg)
        if not exe:
            return f"could not find {pcfg['browser']}; set \"browser_bin\" for this platform in platforms.json"
        args = [exe, flag]
        ud = pcfg.get("user_data")
        if ud and pcfg.get("pass_user_data"):
            args.append(f"--user-data-dir={expand(ud)}")
        _spawn_detached(args + [pcfg["url"]])
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
        "Path tokens: ~ {home} {appdata} {localappdata} {xdg_config} {env:VAR|default};",
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
        return n, False
    return None, False


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
            if meta.get("kind") == "browser":
                detail = f"Chrome profile: {meta.get('profile_name')}"
            else:
                detail = meta.get("identity") or ""
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
        profs = chrome_profiles(v)
        print(f"{v['browser']} profiles:")
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
        cleanup_trash(plat, st)
        check_case_collision(plat, args.name)
        dest = snap_dir(plat, args.name)
        if dest.exists() and not args.force:
            die(f"'{args.name}' already exists for {plat} (use --force to overwrite)")
        if pcfg["kind"] == "browser":
            if not args.profile:
                profs = ", ".join(f"{n}" for n in chrome_profiles(pcfg).values()) or "(none found)"
                die(f"pass --profile <Chrome profile name>. Profiles: {profs}")
            pdir, pname = resolve_profile(pcfg, args.profile)
            write_meta_dir(dest, {"schema": SNAPSHOT_SCHEMA, "kind": "browser", "profile": pdir,
                                  "profile_name": pname, "saved_at": now(), "artifacts": {}}, st)
            print(f"saved {plat}/{args.name} -> Chrome profile '{pname}'")
            return
        if pcfg["kind"] == "app":
            # SQLite / LevelDB files copied while the app runs can be inconsistent.
            check_processes(pcfg, args.quit)
        if not live_has_login(pcfg, st):
            warn(f"no {pcfg['label']} login found on this machine - saving an empty snapshot")
        ident = live_identity(pcfg)
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
    st = stores()
    with lock():
        cleanup_trash(plat, st)
        d = snap_dir(plat, args.name)
        meta = read_json(d / "meta.json")
        if not meta:
            names = ", ".join(n for n, _ in list_accounts(plat)) or "none saved"
            die(f"no account '{args.name}' for {plat} (saved: {names})")
        if pcfg["kind"] == "browser":
            err = open_browser_profile(pcfg, meta["profile"])
            if err:
                die(f"could not open {pcfg['browser']}: {err}")
            print(f"opened {pcfg['url']} in {pcfg['browser']} profile '{meta['profile_name']}'")
            return
        matched, synced, backup = leave_current(plat, pcfg, st, args.force, args.quit,
                                                getattr(args, "writeback", False))
        if matched == args.name and synced:
            print(f"'{args.name}' is already the active {pcfg['label']} account")
        else:
            apply_or_rollback(pcfg, st, backup, lambda: restore_all(pcfg, d, st, meta))
            print(f"switched {pcfg['label']} -> '{args.name}'")
        state = load_state()
        state["active"][plat] = args.name
        save_state(state)
    if args.launch and pcfg["kind"] == "app":
        if launch_app(pcfg):
            print(f"launched {pcfg.get('app') or pcfg['label']}")


def cmd_new(args):
    plat, pcfg = resolve(args.platform)
    if pcfg["kind"] == "browser":
        die("for web accounts, create a Chrome profile, sign in there, then: "
            f"aiswitch save {plat} <name> --profile <profile>")
    check_name(args.name)
    st = stores()
    with lock():
        cleanup_trash(plat, st)
        check_case_collision(plat, args.name)
        if snap_dir(plat, args.name).exists():
            die(f"'{args.name}' already exists; use `aiswitch use {plat} {args.name}`")
        _, _, backup = leave_current(plat, pcfg, st, args.force, args.quit,
                                     getattr(args, "writeback", False))
        apply_or_rollback(pcfg, st, backup, lambda: clear_all(pcfg, st))
        state = load_state()
        state["active"].pop(plat, None)
        save_state(state)
    print(f"{pcfg['label']} is now logged out locally (previous account saved/backed up).")
    print(f"Next: {pcfg['login_hint']}, then run:  aiswitch save {plat} {args.name}")


def cmd_rm(args):
    check_name(args.name)
    plat, pcfg = resolve(args.platform)
    d = snap_dir(plat, args.name)
    if not (d / "meta.json").exists():
        die(f"no account '{args.name}' for {plat}")
    if not args.yes:
        if input(f"Delete saved account {plat}/{args.name}? This cannot be undone. [y/N] ").lower() != "y":
            print("cancelled")
            return
    st = stores()
    with lock():
        delete_snapshot(d, st)
        state = load_state()
        if state["active"].get(plat) == args.name:
            state["active"].pop(plat)
            save_state(state)
    print(f"removed {plat}/{args.name}")


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
    for name in ("snapshots", "backups", "state.json", "platforms.json"):
        p = r / name
        if p.is_dir():
            rmtree_force(p)
        elif p.exists():
            remove_file(p)
    print(f"purged {r}. Remove the folder itself with your file manager if you like.")


def cmd_doctor(args):
    st = stores()
    print(f"aiswitch {VERSION}  os={host_os()}  python={sys.version.split()[0]}  store={root()}")
    print(f"secret store: {st.live.name}")
    if os.name == "posix":
        mode = oct(root().stat().st_mode & 0o777)
        print(f"store permissions: {mode} {'ok' if mode == '0o700' else '(expected 0o700)'}")
    else:
        print("store permissions: not checked on Windows (mode bits don't apply; files are "
              "protected only by your user profile's ACLs)")
    pt = proc_table(refresh=True)
    if pt.procs is None:
        print("process detection: unavailable (running-app checks are disabled)")
    for var in ("CLAUDE_CONFIG_DIR", "CODEX_HOME"):
        if os.environ.get(var):
            print(f"{var}={os.environ[var]} (honoured)")
    if os.environ.get("CLAUDE_CONFIG_DIR") and host_os() == "darwin":
        warn("with CLAUDE_CONFIG_DIR set, Claude Code may use a differently named Keychain item; "
             "this is not verified - check `aiswitch doctor` shows the keychain item as present")
    for k, v in load_platforms().items():
        print(c(f"\n{v['label']} [{k}]", "1"))
        if v["kind"] == "browser":
            print(f"  profiles found: {len(chrome_profiles(v))}")
            continue
        for spec in artifacts(v):
            where = str(expand(spec["path"])) if spec.get("path") else f"keychain:{spec.get('service')}"
            try:
                mark = glyph("ok") if probe(spec, st) else glyph("no")
            except Fatal as e:
                mark = "!"
                where += f"  ({e})"
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
    const sel=$("select",{},$("option",{value:""},"Chrome profile…"),p.profiles.map(x=>$("option",{value:x.dir},x.name)));
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
  return $("section",{class:"card"},$("div",{class:"ch"},$("h2",{},p.label),p.running?$("span",{class:"tag run"},"running"):null,$("div",{class:"sp"}),$("span",{class:"tag"},p.id)),list,hint,foot)}
async function load(){const r=await api("/api/state");const m=document.getElementById("main");m.textContent="";
  if(!r.ok){m.append($("div",{class:"empty"},r.error||"Cannot reach aiswitch. Re-open it with `aiswitch gui`."));return}
  r.platforms.forEach(p=>m.append(card(p)))}
document.getElementById("refresh").onclick=load;load();
document.addEventListener("visibilitychange",()=>{if(!document.hidden)load()});
</script></body></html>"""


def gui_state():
    state = load_state()
    pt = proc_table(refresh=True)      # one process scan per refresh (tasklist is slow)
    out = []
    for k, v in load_platforms().items():
        accounts = []
        for name, meta in list_accounts(k):
            detail = (f"Chrome profile: {meta.get('profile_name')}" if meta.get("kind") == "browser"
                      else meta.get("identity") or "")
            accounts.append({"name": name, "detail": detail.replace("|", " · "), "saved_at": meta.get("saved_at")})
        cur, _ = current_account(k, v, state)
        out.append({
            "id": k, "label": v["label"], "kind": v["kind"], "accounts": accounts, "current": cur,
            "login_hint": v.get("login_hint", ""),
            "running": bool(running_state(v, pt)[0]) if v["kind"] != "browser" else False,
            "profiles": ([{"dir": d, "name": n} for d, n in chrome_profiles(v).items()]
                         if v["kind"] == "browser" else []),
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
                            writeback=False, allow_duplicate=False)
    fn = {"use": cmd_use, "save": cmd_save, "new": cmd_new, "rm": cmd_rm}[op]
    buf = io.StringIO()
    # redirect_stdout is process-global: keep the HTTP server single-threaded.
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        fn(ns)
    lines = [re.sub(r"\x1b\[[0-9;]*m", "", ln).strip() for ln in buf.getvalue().splitlines() if ln.strip()]
    return "\n".join(lines)


def make_gui_server(port=0):
    """Returns (server, url). Separate from cmd_gui so tests can drive it."""
    import http.server

    token = secrets.token_urlsafe(24)
    port_holder = {}

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

    srv = http.server.HTTPServer(("127.0.0.1", port), H)
    port_holder["p"] = srv.server_address[1]
    srv.aiswitch_token = token
    return srv, f"http://127.0.0.1:{port_holder['p']}/?t={token}"


def cmd_gui(args):
    import webbrowser
    srv, url = make_gui_server(args.port)
    print(f"aiswitch GUI running at {url}\nPress Ctrl-C to stop.", flush=True)
    if not args.no_open:
        try:
            if not webbrowser.open(url):
                print("(no browser found - open the URL above yourself)")
        except Exception:
            print("(could not start a browser - open the URL above yourself)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
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
    p = add("profiles", cmd_profiles, "list Chrome profiles (for web platforms)")
    p.add_argument("platform", nargs="?")
    p = add("save", cmd_save, "save the login currently on this machine as <name>")
    p.add_argument("platform")
    p.add_argument("name")
    p.add_argument("--force", action="store_true", help="overwrite an existing saved account")
    p.add_argument("--profile", help="(web platforms) Chrome profile name or directory")
    p.add_argument("--quit", action="store_true", help="quit the desktop app first if it's running")
    p.add_argument("--allow-duplicate", action="store_true",
                   help="save even if this login is already saved under another name")
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
    add("doctor", cmd_doctor, "check paths, keychain access and running apps")
    p = add("gui", cmd_gui, "open the graphical switcher in your browser (local only)")
    p.add_argument("--port", type=int, default=0, help="port (default: random free port)")
    p.add_argument("--no-open", "--no-browser", dest="no_open", action="store_true",
                   help="don't open a browser automatically")
    return ap


def main(argv=None):
    global DEBUG, _PROC_CACHE
    setup_console()
    args = build_parser().parse_args(argv)
    DEBUG = args.debug or bool(os.environ.get("AISWITCH_DEBUG"))
    _PROC_CACHE = None
    try:
        ensure_root()
        if not getattr(args, "func", None):
            args = build_parser().parse_args(["ls"])
        args.func(args)
    except Fatal as e:
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
        print(f"error: unexpected {type(e).__name__}: {e}\n(run with --debug for a traceback)",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
