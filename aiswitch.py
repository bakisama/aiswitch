#!/usr/bin/env python3
"""aiswitch - a TcNo-Account-Switcher-style switcher for AI tool logins.

It freezes the login state of a tool (Claude Code, Codex CLI, Gemini CLI,
Claude Desktop, ...) per account, and swaps a saved copy back in on demand.
No passwords are ever asked for or stored by this tool: it only moves around
the credential files / Keychain items the tools already create themselves.

Platforms are defined by a small config (see DEFAULT_PLATFORMS, or run
`aiswitch init` and edit ~/.aiswitch/platforms.json).
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import fcntl
import getpass
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VERSION = "0.1.0"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
KEEP_BACKUPS = 5

CHROME_DIR = "~/Library/Application Support/Google/Chrome"
DESKTOP_DIR = "~/Library/Application Support/Claude"


def _desk(name, typ, rel, **kw):
    return {"name": name, "type": typ, "path": f"{DESKTOP_DIR}/{rel}", **kw}


# Artifact types:
#   file       copy one file
#   dir        copy a directory tree
#   json_keys  copy only some top-level keys of a JSON file (rest of the file is left alone)
#   keychain   a macOS Keychain generic-password item (by service name)
# "primary": true marks the artifacts that mean "a login exists".
# "identity" lets aiswitch tell which saved account is currently live (so refreshed
# tokens are written back to the right snapshot, never the wrong one).
DEFAULT_PLATFORMS = {
    "claude-code": {
        "label": "Claude Code",
        "aliases": ["cc"],
        "kind": "login",
        "processes": ["claude"],
        "login_hint": "run `claude`, then /login",
        "artifacts": [
            {"name": "keychain", "type": "keychain", "service": "Claude Code-credentials",
             "primary": True, "os": ["darwin"]},
            {"name": "credentials", "type": "file", "path": "~/.claude/.credentials.json",
             "primary": True, "os": ["linux"]},
            {"name": "account", "type": "json_keys", "path": "~/.claude.json", "keys": ["oauthAccount"]},
        ],
        "identity": [
            {"file": "~/.claude.json", "path": "oauthAccount.emailAddress"},
            {"file": "~/.claude.json", "path": "oauthAccount.organizationUuid"},
        ],
    },
    "codex": {
        "label": "Codex CLI",
        "aliases": ["cx"],
        "kind": "login",
        "processes": ["codex"],
        "login_hint": "run `codex login`",
        "artifacts": [
            {"name": "auth", "type": "file", "path": "~/.codex/auth.json", "primary": True},
        ],
        "identity": [
            {"file": "~/.codex/auth.json", "path": "tokens.id_token", "jwt_claim": "email"},
            {"file": "~/.codex/auth.json", "path": "tokens.account_id"},
        ],
    },
    "gemini": {
        "label": "Gemini CLI",
        "aliases": ["gem"],
        "kind": "login",
        "processes": ["gemini"],
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
    "claude-web": {
        "label": "Claude (web, via Chrome profile)", "kind": "browser", "os": ["darwin"],
        "browser": "Google Chrome", "user_data": CHROME_DIR, "url": "https://claude.ai",
    },
    "chatgpt-web": {
        "label": "ChatGPT (web, via Chrome profile)", "kind": "browser", "os": ["darwin"],
        "browser": "Google Chrome", "user_data": CHROME_DIR, "url": "https://chatgpt.com",
    },
    "gemini-web": {
        "label": "Gemini (web, via Chrome profile)", "kind": "browser", "os": ["darwin"],
        "browser": "Google Chrome", "user_data": CHROME_DIR, "url": "https://gemini.google.com",
    },
}


# --------------------------------------------------------------------------- utils
class Fatal(Exception):
    def __init__(self, msg, code="error"):
        super().__init__(msg)
        self.code = code


def die(msg, code="error"):
    raise Fatal(msg, code)


def c(txt, code):
    return f"\033[{code}m{txt}\033[0m" if sys.stdout.isatty() else str(txt)


def warn(msg):
    print(c("warning:", "33"), msg, file=sys.stderr)


def host_os():
    forced = os.environ.get("AISWITCH_FORCE_OS")
    if forced:
        return forced
    return "darwin" if sys.platform == "darwin" else "linux"


def home():
    return Path(os.environ.get("HOME") or str(Path.home()))


def expand(p):
    p = str(p)
    if p.startswith("~"):
        p = str(home()) + p[1:]
    return Path(os.path.expandvars(p))


def root():
    return Path(os.environ.get("AISWITCH_HOME") or (home() / ".aiswitch"))


def now():
    return dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S")


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


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


def atomic_write_bytes(dest, data, mode=0o600):
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".aiswitch-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, dest)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def is_running(name):
    try:
        return subprocess.run(["pgrep", "-x", name], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def ensure_root():
    r = root()
    r.mkdir(parents=True, exist_ok=True)
    os.chmod(r, 0o700)


@contextlib.contextmanager
def lock():
    f = open(root() / ".lock", "w")
    try:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            die("another aiswitch is running")
        yield
    finally:
        f.close()


# ------------------------------------------------------------------------ keychain
class Keychain:
    """macOS Keychain generic passwords via `security`. If AISWITCH_KEYCHAIN_DIR is
    set, a plain directory is used instead (for tests / non-macOS)."""

    def __init__(self):
        d = os.environ.get("AISWITCH_KEYCHAIN_DIR")
        self.emul = Path(d) if d else None
        if self.emul:
            self.emul.mkdir(parents=True, exist_ok=True)

    def _f(self, service):
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", service)[:60]
        return self.emul / f"{safe}-{hashlib.sha1(service.encode()).hexdigest()[:10]}.json"

    @staticmethod
    def _sec(*args):
        try:
            return subprocess.run(["security", *args], capture_output=True, text=True)
        except FileNotFoundError:
            die("`security` not found - the keychain features need macOS")

    def read(self, service):
        if self.emul:
            f = self._f(service)
            return json.loads(f.read_text()) if f.exists() else None
        r = self._sec("find-generic-password", "-s", service, "-w")
        if r.returncode != 0:
            return None
        secret = r.stdout[:-1] if r.stdout.endswith("\n") else r.stdout
        meta = self._sec("find-generic-password", "-s", service)
        m = re.search(r'"acct"<blob>="((?:[^"\\]|\\.)*)"', meta.stdout)
        return {"account": m.group(1) if m else getpass.getuser(), "secret": secret}

    def write(self, service, account, secret):
        if self.emul:
            atomic_write_bytes(self._f(service), json.dumps({"account": account, "secret": secret}).encode())
            return
        r = self._sec("add-generic-password", "-U", "-s", service, "-a", account, "-w", secret)
        if r.returncode != 0:
            die(f"keychain write failed for '{service}': {r.stderr.strip()}")

    def delete(self, service):
        if self.emul:
            f = self._f(service)
            if f.exists():
                f.unlink()
                return True
            return False
        return self._sec("delete-generic-password", "-s", service).returncode == 0


# ------------------------------------------------------------------------- config
def load_platforms():
    plats = {k: dict(v) for k, v in DEFAULT_PLATFORMS.items()}
    user = read_json(root() / "platforms.json")
    if isinstance(user, dict):
        for k, v in user.items():
            if isinstance(v, dict) and v.get("disabled"):
                plats.pop(k, None)
            elif isinstance(v, dict):
                plats[k] = v
    me = host_os()
    return {k: v for k, v in plats.items() if me in v.get("os", [me])}


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


def artifacts(pcfg):
    me = host_os()
    return [a for a in pcfg.get("artifacts", []) if me in a.get("os", [me])]


def check_name(name):
    if not NAME_RE.match(name):
        die("account names may use letters, digits, '.', '_' and '-' (max 40, must start with a letter/digit)")


# ------------------------------------------------------------- snapshot locations
def snap_dir(plat, name):
    return root() / "snapshots" / plat / name


def backup_root(plat):
    return root() / "backups" / plat


def kc_base(d):
    return "aiswitch:" + str(Path(d).relative_to(root()))


def load_state():
    st = read_json(root() / "state.json")
    if not isinstance(st, dict):
        st = {}
    st.setdefault("active", {})
    return st


def save_state(st):
    atomic_write_bytes(root() / "state.json", json.dumps(st, indent=2).encode())


def list_accounts(plat):
    base = root() / "snapshots" / plat
    out = []
    if base.is_dir():
        for d in sorted(base.iterdir()):
            meta = read_json(d / "meta.json") if d.is_dir() else None
            if meta:
                out.append((d.name, meta))
    return out


def find_by_identity(plat, ident):
    for name, meta in list_accounts(plat):
        if meta.get("identity") and meta["identity"] == ident:
            return name
    return None


# --------------------------------------------------------------- artifact handling
def capture(spec, dest, kc, base):
    t, name = spec["type"], spec["name"]
    if t == "file":
        p = expand(spec["path"])
        if p.is_file():
            atomic_write_bytes(dest / name, p.read_bytes())
            return {"type": t, "present": True}
        return {"type": t, "present": False}
    if t == "dir":
        p = expand(spec["path"])
        if p.is_dir():
            shutil.copytree(p, dest / name, symlinks=True,
                            ignore=shutil.ignore_patterns("LOCK", "Singleton*"))
            return {"type": t, "present": True}
        return {"type": t, "present": False}
    if t == "json_keys":
        data = read_json(expand(spec["path"]))
        data = data if isinstance(data, dict) else {}
        got = {k: data[k] for k in spec["keys"] if k in data}
        if got:
            atomic_write_bytes(dest / (name + ".json"), json.dumps(got).encode())
        return {"type": t, "present": bool(got)}
    if t == "keychain":
        item = kc.read(spec["service"])
        if item:
            kc.write(f"{base}:{name}", item["account"], item["secret"])
            return {"type": t, "present": True}
        return {"type": t, "present": False}
    die(f"unknown artifact type '{t}'")


def restore(spec, src, present, kc, base):
    t, name = spec["type"], spec["name"]
    if t == "file":
        p = expand(spec["path"])
        if present:
            atomic_write_bytes(p, (src / name).read_bytes())
        elif p.exists():
            p.unlink()
    elif t == "dir":
        p = expand(spec["path"])
        if present:
            tmp = p.with_name(p.name + ".aiswitch-new")
            if tmp.exists():
                shutil.rmtree(tmp)
            p.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(src / name, tmp, symlinks=True)
            if p.exists():
                shutil.rmtree(p)
            os.replace(tmp, p)
        elif p.exists():
            shutil.rmtree(p)
    elif t == "json_keys":
        p = expand(spec["path"])
        live = read_json(p)
        if live is None:
            if p.exists():
                die(f"cannot parse {p}; refusing to modify it")
            if not present:
                return
            live = {}
        for k in spec["keys"]:
            live.pop(k, None)
        if present:
            live.update(json.loads((src / (name + ".json")).read_text()))
        mode = (p.stat().st_mode & 0o777) if p.exists() else 0o600
        atomic_write_bytes(p, json.dumps(live, indent=2).encode(), mode)
    elif t == "keychain":
        item = None
        if present:
            item = kc.read(f"{base}:{name}")
            if not item:
                die(f"saved keychain entry for '{name}' is missing")
        for _ in range(5):
            if not kc.delete(spec["service"]):
                break
        if item:
            kc.write(spec["service"], item["account"], item["secret"])


def probe(spec, kc):
    t = spec["type"]
    if t == "file":
        return expand(spec["path"]).is_file()
    if t == "dir":
        return expand(spec["path"]).is_dir()
    if t == "json_keys":
        data = read_json(expand(spec["path"]))
        return isinstance(data, dict) and any(k in data for k in spec["keys"])
    if t == "keychain":
        return kc.read(spec["service"]) is not None
    return False


def live_has_login(pcfg, kc):
    specs = artifacts(pcfg)
    primary = [s for s in specs if s.get("primary")]
    return any(probe(s, kc) for s in (primary or specs))


def live_identity(pcfg):
    parts = pcfg.get("identity")
    if not parts:
        return None
    vals = []
    for i, part in enumerate(parts):
        data = read_json(expand(part["file"]))
        v = get_path(data, part["path"]) if isinstance(data, dict) else None
        if v is not None and part.get("jwt_claim"):
            v = jwt_claim(v, part["jwt_claim"])
        if v is None or v == "":
            if i == 0:
                return None
            v = ""
        vals.append(str(v))
    return "|".join(vals)


def take_snapshot(pcfg, final, kc, extra=None):
    final = Path(final)
    final.parent.mkdir(parents=True, exist_ok=True)
    tmp = final.with_name(final.name + ".tmp")
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(mode=0o700)
    info = {s["name"]: capture(s, tmp, kc, kc_base(final)) for s in artifacts(pcfg)}
    meta = {"saved_at": now(), "identity": live_identity(pcfg), "artifacts": info}
    meta.update(extra or {})
    atomic_write_bytes(tmp / "meta.json", json.dumps(meta, indent=2).encode())
    if final.exists():
        shutil.rmtree(final)
    os.replace(tmp, final)
    return meta


def restore_all(pcfg, src, kc, meta):
    for spec in artifacts(pcfg):
        ent = meta["artifacts"].get(spec["name"])
        if ent is not None:
            restore(spec, Path(src), ent["present"], kc, kc_base(src))


def delete_snapshot(d, kc):
    d = Path(d)
    meta = read_json(d / "meta.json") or {}
    for name, ent in meta.get("artifacts", {}).items():
        if ent.get("type") == "keychain" and ent.get("present"):
            kc.delete(f"{kc_base(d)}:{name}")
    shutil.rmtree(d, ignore_errors=True)


def prune_backups(plat, kc):
    br = backup_root(plat)
    if br.is_dir():
        for d in sorted(p for p in br.iterdir() if p.is_dir())[:-KEEP_BACKUPS]:
            delete_snapshot(d, kc)


# ------------------------------------------------------------------ switching core
def check_processes(pcfg, quit_app):
    if pcfg["kind"] == "app":
        app = pcfg["app"]
        if is_running(app):
            if not quit_app:
                die(f"{app} is running. Quit it first, or pass --quit to let aiswitch close it.", "app_running")
            subprocess.run(["osascript", "-e", f'tell application "{app}" to quit'],
                           capture_output=True)
            for _ in range(40):
                if not is_running(app):
                    break
                time.sleep(0.25)
            else:
                die(f"could not quit {app}; close it manually and retry")
    else:
        running = [p for p in pcfg.get("processes", []) if is_running(p)]
        if running:
            warn(f"{', '.join(running)} appears to be running. Existing sessions keep the old login "
                 "in memory and may write it back - restart them after switching.")


def leave_current(plat, pcfg, kc, force, quit_app):
    """Prepare to replace the live login: stop-check, write refreshed tokens back to
    the matching saved account, and back the live state up. Returns (matched, backup_dir)."""
    check_processes(pcfg, quit_app)
    st = load_state()
    has = live_has_login(pcfg, kc)
    ident = live_identity(pcfg)
    matched = None
    if ident:
        matched = find_by_identity(plat, ident)
    elif has and not pcfg.get("identity"):
        n = st["active"].get(plat)
        if n and (snap_dir(plat, n) / "meta.json").exists():
            matched = n
    if matched:
        old = read_json(snap_dir(plat, matched) / "meta.json") or {}
        take_snapshot(pcfg, snap_dir(plat, matched), kc,
                      {"created": old.get("created", old.get("saved_at")), "kind": pcfg["kind"]})
        print(f"  synced current login back into '{matched}'")
    elif has and not force:
        die("the login currently on this machine isn't saved under any account name.\n"
            f"  Save it first:  aiswitch save {plat} <name>\n"
            "  or pass --force to replace it (a backup is kept in ~/.aiswitch/backups).", "unsaved")
    backup = None
    if has:
        backup = backup_root(plat) / time.strftime("%Y%m%d-%H%M%S")
        n = 1
        while backup.exists():
            n += 1
            backup = backup_root(plat) / (time.strftime("%Y%m%d-%H%M%S") + f"-{n}")
        take_snapshot(pcfg, backup, kc, {"backup": True})
        prune_backups(plat, kc)
    return matched, backup


# ------------------------------------------------------------------------ browsers
def chrome_profiles(pcfg):
    ls = read_json(expand(pcfg.get("user_data", CHROME_DIR)) / "Local State")
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


# ---------------------------------------------------------------------- commands
def cmd_platforms(args):
    for k, v in load_platforms().items():
        al = f"  (alias: {', '.join(v['aliases'])})" if v.get("aliases") else ""
        print(f"{k:16} {v['label']}{al}")


def cmd_init(args):
    p = root() / "platforms.json"
    if p.exists() and not args.force:
        die(f"{p} already exists (use --force to overwrite)")
    atomic_write_bytes(p, json.dumps(DEFAULT_PLATFORMS, indent=2).encode(), 0o644)
    print(f"wrote {p}\nEdit it to add platforms, change paths, or set \"disabled\": true on an entry.")


def current_account(plat, pcfg, st):
    if pcfg["kind"] == "browser":
        return None, False
    ident = live_identity(pcfg)
    if ident:
        return find_by_identity(plat, ident), True
    if pcfg.get("identity"):
        return None, False
    n = st["active"].get(plat)
    if n and (snap_dir(plat, n) / "meta.json").exists():
        return n, False
    return None, False


def cmd_ls(args):
    st = load_state()
    plats = load_platforms()
    if args.platform:
        k, v = resolve(args.platform)
        plats = {k: v}
    for k, v in plats.items():
        accounts = list_accounts(k)
        if not args.platform and not accounts:
            continue
        print(c(f"{v['label']}", "1") + f"  [{k}]")
        cur, _ = current_account(k, v, st)
        if not accounts:
            print("  (no saved accounts)")
        for name, meta in accounts:
            dot = c("●", "32") if name == cur else "○"
            if meta.get("kind") == "browser":
                detail = f"Chrome profile: {meta.get('profile_name')}"
            else:
                detail = meta.get("identity") or ""
            print(f"  {dot} {name:16} {detail:34} saved {meta.get('saved_at', '?')}")
    if not any(list_accounts(k) for k in plats) and not args.platform:
        print("No saved accounts yet. Log in to a tool, then: aiswitch save <platform> <name>")
        print("Platforms: aiswitch platforms")


def cmd_current(args):
    st = load_state()
    plats = {resolve(args.platform)[0]: resolve(args.platform)[1]} if args.platform else load_platforms()
    for k, v in plats.items():
        if v["kind"] == "browser":
            continue
        name, verified = current_account(k, v, st)
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
    kc = Keychain()
    with lock():
        dest = snap_dir(plat, args.name)
        if dest.exists() and not args.force:
            die(f"'{args.name}' already exists for {plat} (use --force to overwrite)")
        if pcfg["kind"] == "browser":
            if not args.profile:
                profs = ", ".join(f"{n}" for n in chrome_profiles(pcfg).values()) or "(none found)"
                die(f"pass --profile <Chrome profile name>. Profiles: {profs}")
            pdir, pname = resolve_profile(pcfg, args.profile)
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name(dest.name + ".tmp")
            shutil.rmtree(tmp, ignore_errors=True)
            tmp.mkdir(mode=0o700)
            atomic_write_bytes(tmp / "meta.json", json.dumps(
                {"kind": "browser", "profile": pdir, "profile_name": pname, "saved_at": now(),
                 "artifacts": {}}, indent=2).encode())
            shutil.rmtree(dest, ignore_errors=True)
            os.replace(tmp, dest)
            print(f"saved {plat}/{args.name} -> Chrome profile '{pname}'")
            return
        if not live_has_login(pcfg, kc):
            warn(f"no {pcfg['label']} login found on this machine - saving an empty snapshot")
        meta = take_snapshot(pcfg, dest, kc, {"created": now(), "kind": pcfg["kind"]})
        st = load_state()
        st["active"][plat] = args.name
        save_state(st)
        who = f" ({meta['identity']})" if meta.get("identity") else ""
        print(f"saved current {pcfg['label']} login as '{args.name}'{who}")


def cmd_use(args):
    check_name(args.name)
    plat, pcfg = resolve(args.platform)
    kc = Keychain()
    with lock():
        d = snap_dir(plat, args.name)
        meta = read_json(d / "meta.json")
        if not meta:
            names = ", ".join(n for n, _ in list_accounts(plat)) or "none saved"
            die(f"no account '{args.name}' for {plat} (saved: {names})")
        if pcfg["kind"] == "browser":
            cmd = ["open", "-na", pcfg["browser"], "--args",
                   f"--profile-directory={meta['profile']}", pcfg["url"]]
            subprocess.run(cmd, check=False)
            print(f"opened {pcfg['url']} in {pcfg['browser']} profile '{meta['profile_name']}'")
            return
        matched, backup = leave_current(plat, pcfg, kc, args.force, args.quit)
        if matched == args.name:
            print(f"'{args.name}' is already the active {pcfg['label']} account")
        else:
            try:
                restore_all(pcfg, d, kc, meta)
            except BaseException as e:
                if backup:
                    restore_all(pcfg, backup, kc, read_json(backup / "meta.json"))
                    die(f"switch failed ({e}); previous login restored")
                raise
            print(f"switched {pcfg['label']} -> '{args.name}'")
        st = load_state()
        st["active"][plat] = args.name
        save_state(st)
        if args.launch and pcfg["kind"] == "app":
            subprocess.run(["open", "-a", pcfg["app"]], check=False)


def cmd_new(args):
    plat, pcfg = resolve(args.platform)
    if pcfg["kind"] == "browser":
        die("for web accounts, create a Chrome profile, sign in there, then: "
            f"aiswitch save {plat} <name> --profile <profile>")
    check_name(args.name)
    kc = Keychain()
    with lock():
        if snap_dir(plat, args.name).exists():
            die(f"'{args.name}' already exists; use `aiswitch use {plat} {args.name}`")
        leave_current(plat, pcfg, kc, args.force, args.quit)
        for spec in artifacts(pcfg):
            restore(spec, Path("/nonexistent"), False, kc, "")
        st = load_state()
        st["active"].pop(plat, None)
        save_state(st)
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
    kc = Keychain()
    with lock():
        delete_snapshot(d, kc)
        st = load_state()
        if st["active"].get(plat) == args.name:
            st["active"].pop(plat)
            save_state(st)
    print(f"removed {plat}/{args.name}")


def cmd_doctor(args):
    kc = Keychain()
    print(f"aiswitch {VERSION}  os={host_os()}  store={root()}")
    mode = oct(root().stat().st_mode & 0o777)
    print(f"store permissions: {mode} {'ok' if mode == '0o700' else '(expected 0o700)'}")
    for k, v in load_platforms().items():
        print(c(f"\n{v['label']} [{k}]", "1"))
        if v["kind"] == "browser":
            print(f"  profiles found: {len(chrome_profiles(v))}")
            continue
        for spec in artifacts(v):
            where = spec.get("path") or f"keychain:{spec.get('service')}"
            ok = probe(spec, kc)
            print(f"  {'✓' if ok else '·'} {spec['name']:22} {where}")
        ident = live_identity(v)
        if v.get("identity"):
            print(f"  identity: {ident or '(not logged in / unreadable)'}")
        procs = [v["app"]] if v["kind"] == "app" else v.get("processes", [])
        run = [p for p in procs if is_running(p)]
        if run:
            print(f"  running: {', '.join(run)}")


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
    kc = Keychain()
    st = load_state()
    out = []
    for k, v in load_platforms().items():
        accounts = []
        for name, meta in list_accounts(k):
            detail = (f"Chrome profile: {meta.get('profile_name')}" if meta.get("kind") == "browser"
                      else meta.get("identity") or "")
            accounts.append({"name": name, "detail": detail.replace("|", " · "), "saved_at": meta.get("saved_at")})
        cur, _ = current_account(k, v, st)
        procs = [v["app"]] if v["kind"] == "app" else v.get("processes", [])
        out.append({
            "id": k, "label": v["label"], "kind": v["kind"], "accounts": accounts, "current": cur,
            "login_hint": v.get("login_hint", ""),
            "running": any(is_running(p) for p in procs) if v["kind"] != "browser" else False,
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
                            launch=bool(body.get("launch")), profile=body.get("profile"), yes=True)
    fn = {"use": cmd_use, "save": cmd_save, "new": cmd_new, "rm": cmd_rm}[op]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        fn(ns)
    lines = [re.sub(r"\x1b\[[0-9;]*m", "", ln).strip() for ln in buf.getvalue().splitlines() if ln.strip()]
    return "\n".join(lines)


def cmd_gui(args):
    import http.server
    import secrets
    import webbrowser

    token = secrets.token_urlsafe(24)
    port_holder = {}

    class H(http.server.BaseHTTPRequestHandler):
        server_version = "aiswitch"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else body.encode()
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
                msg = gui_action(body)
                self._send(200, json.dumps({"ok": True, "message": msg}))
            except Fatal as e:
                self._send(200, json.dumps({"ok": False, "error": str(e), "code": e.code}))
            except Exception as e:
                self._send(200, json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"}))

    srv = http.server.HTTPServer(("127.0.0.1", args.port), H)
    port_holder["p"] = srv.server_address[1]
    url = f"http://127.0.0.1:{port_holder['p']}/?t={token}"
    print(f"aiswitch GUI running at {url}\nPress Ctrl-C to stop.", flush=True)
    if not args.no_open:
        webbrowser.open(url)
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
    sub = ap.add_subparsers(dest="cmd")

    def add(name, fn, help_, *aliases):
        p = sub.add_parser(name, help=help_, aliases=list(aliases))
        p.set_defaults(func=fn)
        return p

    add("platforms", cmd_platforms, "list supported platforms")
    p = add("init", cmd_init, "write an editable platforms.json to ~/.aiswitch")
    p.add_argument("--force", action="store_true")
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
    p = add("use", cmd_use, "switch to a saved account", "switch")
    p.add_argument("platform")
    p.add_argument("name")
    p.add_argument("--force", action="store_true", help="replace an unsaved current login")
    p.add_argument("--quit", action="store_true", help="quit the desktop app first if it's running")
    p.add_argument("--launch", action="store_true", help="relaunch the desktop app afterwards")
    p = add("new", cmd_new, "log out locally so you can sign in to a new account")
    p.add_argument("platform")
    p.add_argument("name")
    p.add_argument("--force", action="store_true")
    p.add_argument("--quit", action="store_true")
    p = add("rm", cmd_rm, "delete a saved account")
    p.add_argument("platform")
    p.add_argument("name")
    p.add_argument("-y", "--yes", action="store_true")
    add("doctor", cmd_doctor, "check paths, keychain access and running apps")
    p = add("gui", cmd_gui, "open the graphical switcher in your browser (local only)")
    p.add_argument("--port", type=int, default=0, help="port (default: random free port)")
    p.add_argument("--no-open", action="store_true", help="don't open a browser automatically")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
