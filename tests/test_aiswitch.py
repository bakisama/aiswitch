"""Hermetic tests for aiswitch. Stdlib only: `python -m unittest discover -s tests -v`.

Every test runs against throw-away HOME / USERPROFILE / APPDATA dirs, an in-memory secret
store and a fake process table. The macOS Keychain backend is exercised against a fake
`security` (tests/fake_security.py) on every OS. Real keystores are only touched when
AISWITCH_TEST_REAL_STORE=1 (throw-away service names; on Linux it needs an unlocked Secret
Service, e.g. `dbus-run-session -- sh -c 'echo pw | gnome-keyring-daemon --unlock; ...'`)."""
from __future__ import annotations

import contextlib
import errno
import hashlib
import http.client
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import aiswitch as A  # noqa: E402

REAL_STORE = os.environ.get("AISWITCH_TEST_REAL_STORE") == "1"
POSIX = os.name == "posix"


def jwt(claims):
    import base64
    b = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"h.{b}.s"


def P(pid, exe, argv):
    return A.Proc(pid, exe, argv, " ".join(argv))


class Env(unittest.TestCase):
    """Fresh fake machine per test."""
    os_tag = "linux"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="aiswitch-test-"))
        self.home = self.tmp / "home"
        self.home.mkdir()
        env = {
            "HOME": str(self.home), "USERPROFILE": str(self.home),
            "APPDATA": str(self.home / "AppData/Roaming"),
            "LOCALAPPDATA": str(self.home / "AppData/Local"),
            "XDG_CONFIG_HOME": str(self.home / ".config"),
            "AISWITCH_FORCE_OS": self.os_tag, "AISWITCH_LOCK_WAIT": "0.3", "NO_COLOR": "1",
            "PATH": str(self.tmp / "bin") + os.pathsep + os.environ.get("PATH", ""),
        }
        self._env = mock.patch.dict(os.environ, env)
        self._env.start()
        for v in ("AISWITCH_HOME", "AISWITCH_KEYCHAIN_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME",
                  "GEMINI_CLI_HOME", "CHROME_CONFIG_HOME", "GEMINI_FORCE_ENCRYPTED_FILE_STORAGE",
                  "GEMINI_FORCE_FILE_STORAGE", "WSL_DISTRO_NAME", "WSL_INTEROP", "SUDO_UID",
                  "AISWITCH_NO_ARGV_SECRETS", "DISPLAY", "WAYLAND_DISPLAY", "BROWSER"):
            os.environ.pop(v, None)
        self.kc = A.MemoryStore()
        self.procs = []
        A.STORE_FACTORY = lambda: A.Stores(self.kc, self.kc)
        A.PROC_PROVIDER = lambda: self.procs
        A._PROC_CACHE = None
        A._WARNED.clear()
        A._WSL_WIN = None
        self._patches = [mock.patch.object(A, "is_wsl", lambda: False),
                         mock.patch.object(A, "sandbox_kind", lambda: None)]
        if sys.platform == "win32":
            self._patches.append(mock.patch.object(A, "home", lambda: self.home))
        for p in self._patches:
            p.start()

    def tearDown(self):
        A.STORE_FACTORY = None
        A.PROC_PROVIDER = None
        A._PROC_CACHE = None
        for p in reversed(self._patches):
            p.stop()
        self._env.stop()
        A.rmtree_force(self.tmp)

    # helpers
    def run_cli(self, *argv, ok=True):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = A.main(list(argv))
        if ok is not None:
            self.assertEqual(rc == 0, ok, f"rc={rc}\nstdout:{out.getvalue()}\nstderr:{err.getvalue()}")
        return rc, out.getvalue(), err.getvalue()

    def write(self, rel, data):
        p = self.home / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return p

    def read(self, rel):
        return (self.home / rel).read_bytes()

    def store(self):
        return self.home / ".aiswitch"

    def codex_login(self, email, acct, extra=""):
        return self.write(".codex/auth.json", json.dumps(
            {"tokens": {"id_token": jwt({"email": email}), "account_id": acct}, "x": extra}))

    def vault_keys(self):
        return {k for k in self.kc.items if k.startswith(A.VAULT_PREFIX)}

    def all_refs(self):
        out = set()
        for d in list(A.root().glob("snapshots/*/*")) + list(A.root().glob("backups/*/*")):
            out |= A.snapshot_refs(d)
        return out

    def fake_bin(self, name, script="#!/bin/sh\nexit 0\n"):
        d = self.tmp / "bin"
        d.mkdir(exist_ok=True)
        p = d / name
        p.write_text(script)
        p.chmod(0o755)
        return p


# --------------------------------------------------------------------------- paths
class TestPathResolver(unittest.TestCase):
    def r(self, tpl, os_tag="linux", env=None, home="/h/u"):
        return A.resolve_path(tpl, os_tag, env or {}, home)

    def test_tilde_and_home(self):
        self.assertEqual(self.r("~/.codex/auth.json"), "/h/u/.codex/auth.json")
        self.assertEqual(self.r("{home}/x"), "/h/u/x")

    def test_root_home_has_no_double_slash(self):
        self.assertEqual(self.r("~/.claude", home="/"), "/.claude")
        self.assertEqual(self.r("~", home="/"), "/")
        self.assertEqual(self.r("{xdg_config}/x", home="/"), "/.config/x")

    def test_windows_tokens(self):
        env = {"APPDATA": r"C:\Users\u\AppData\Roaming", "LOCALAPPDATA": r"C:\Users\u\AppData\Local"}
        self.assertEqual(self.r("{appdata}/Claude", "windows", env, r"C:\Users\u"),
                         "C:/Users/u/AppData/Roaming/Claude")
        self.assertEqual(self.r("{localappdata}/G", "windows", env, r"C:\Users\u"),
                         "C:/Users/u/AppData/Local/G")
        self.assertEqual(self.r("{appdata}/C", "windows", {}, r"C:\Users\u"),
                         "C:/Users/u/AppData/Roaming/C")
        self.assertEqual(self.r("~/.claude/.credentials.json", "windows", {}, r"C:\Users\u"),
                         "C:/Users/u/.claude/.credentials.json")
        self.assertEqual(self.r("{env:ProgramW6432|C:/Program Files}/x", "windows", {}),
                         "C:/Program Files/x")
        self.assertEqual(self.r("{env:ProgramFiles(x86)|C:/PF86}/x", "windows",
                                {"ProgramFiles(x86)": r"D:\PF86"}), "D:/PF86/x")

    def test_xdg_and_chrome_config(self):
        self.assertEqual(self.r("{xdg_config}/google-chrome"), "/h/u/.config/google-chrome")
        self.assertEqual(self.r("{xdg_config}/c", env={"XDG_CONFIG_HOME": "/x"}), "/x/c")
        self.assertEqual(self.r("{chrome_config}/c", env={"XDG_CONFIG_HOME": "/x"}), "/x/c")
        self.assertEqual(self.r("{chrome_config}/c", env={"XDG_CONFIG_HOME": "/x", "CHROME_CONFIG_HOME": "/y"}), "/y/c")

    def test_env_override(self):
        tpl = "{env:CODEX_HOME|~/.codex}/auth.json"
        self.assertEqual(self.r(tpl), "/h/u/.codex/auth.json")
        self.assertEqual(self.r(tpl, env={"CODEX_HOME": "/srv/codex"}), "/srv/codex/auth.json")
        self.assertEqual(self.r(A.CLAUDE_JSON), "/h/u/.claude.json")
        self.assertEqual(self.r(A.CLAUDE_JSON, env={"CLAUDE_CONFIG_DIR": "/c"}), "/c/.claude.json")
        self.assertEqual(self.r(A.GEMINI_DIR + "/oauth_creds.json", env={"GEMINI_CLI_HOME": "/g"}),
                         "/g/.gemini/oauth_creds.json")

    def test_claude_keychain_suffix(self):
        svc = "Claude Code-credentials{claude_kc_suffix}"
        self.assertEqual(self.r(svc), "Claude Code-credentials")
        want = "-" + hashlib.sha256(b"/Users/u/.claude-work").hexdigest()[:8]
        self.assertEqual(self.r(svc, env={"CLAUDE_CONFIG_DIR": "/Users/u/.claude-work"}),
                         "Claude Code-credentials" + want)
        # hashed exactly as set: a trailing slash is a different config dir to Claude Code
        self.assertNotEqual(self.r(svc, env={"CLAUDE_CONFIG_DIR": "/Users/u/.claude-work/"}),
                            "Claude Code-credentials" + want)

    def test_codex_home_hash(self):
        d = tempfile.mkdtemp()
        try:
            want = hashlib.sha256(os.path.realpath(d).encode()).hexdigest()[:16]
            self.assertEqual(self.r("cli|{codex_home_hash}", env={"CODEX_HOME": d}), "cli|" + want)
        finally:
            os.rmdir(d)

    def test_claude_desktop_msix_probe(self):
        d = Path(tempfile.mkdtemp())
        try:
            env = {"LOCALAPPDATA": str(d / "Local"), "APPDATA": str(d / "Roaming")}
            self.assertEqual(self.r("{claude_desktop_win}", "windows", env), str(d / "Roaming").replace("\\", "/") + "/Claude")
            msix = d / "Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude"
            msix.mkdir(parents=True)
            self.assertTrue(self.r("{claude_desktop_win}", "windows", env).endswith("/Roaming/Claude"))
            self.assertNotIn("Packages", self.r("{claude_desktop_win}", "windows", env))  # no Local State yet
            (msix / "Local State").write_text("{}")
            self.assertIn("Packages/Claude_pzs8sxrjxfjjc", self.r("{claude_desktop_win}", "windows", env))
        finally:
            shutil.rmtree(d)

    def test_per_os_dict(self):
        tpl = {"darwin": "~/Library/X", "windows": "{appdata}/X"}
        self.assertEqual(self.r(tpl, "darwin"), "/h/u/Library/X")
        self.assertIsNone(self.r(tpl, "linux"))
        self.assertEqual(self.r({"default": "~/d"}, "linux"), "/h/u/d")

    def test_dollar_vars_and_unknown_token(self):
        self.assertEqual(self.r("$FOO/a", env={"FOO": "/f"}), "/f/a")
        with self.assertRaises(A.Fatal):
            self.r("{bogus}/a")

    def test_registry_resolves_on_every_os(self):
        for os_tag in A.OSES:
            for k, v in A.DEFAULT_PLATFORMS.items():
                for a in v.get("artifacts", []):
                    for key in ("path", "service", "account"):
                        if a.get(key):
                            self.r(a[key], os_tag)


# ----------------------------------------------------------------- secret stores
class StoreContract:
    big = '{"claudeAiOauth": {"accessToken": "a b\\"c", "ü": 1}}' + "x" * 1900

    def make(self):
        raise NotImplementedError

    def setUp(self):
        self.s = self.make()
        self.svc = f"aiswitch-test-{uuid.uuid4().hex[:10]}"

    def tearDown(self):
        with contextlib.suppress(Exception):
            self.s.delete_all(self.svc)
        with contextlib.suppress(Exception):
            for a in ("a1", "a2"):
                self.s.delete_all(self.svc, a)

    def test_absent(self):
        self.assertIsNone(self.s.read(self.svc))
        self.assertIsNone(self.s.account(self.svc))
        self.assertIsNone(self.s.read(self.svc, "nobody"))
        self.assertFalse(self.s.delete(self.svc))

    def strip(self, item):
        return {k: v for k, v in item.items() if k != "meta"}

    def test_roundtrip_and_update(self):
        for secret in (self.big, "line1\nline2\ttab", "ünïcødé ✓", "x"):
            self.s.write(self.svc, "acct1", secret)
            self.assertEqual(self.strip(self.s.read(self.svc)), {"account": "acct1", "secret": secret})
        self.assertTrue(self.s.delete(self.svc))
        self.assertIsNone(self.s.read(self.svc))

    def test_replace_other_account(self):
        self.s.write(self.svc, "old", "s1")
        self.s.replace(self.svc, "new", "s2")
        self.assertEqual(self.strip(self.s.read(self.svc)), {"account": "new", "secret": "s2"})
        self.assertIsNone(self.s.read(self.svc, "old"))
        self.s.delete_all(self.svc)
        self.assertIsNone(self.s.read(self.svc))

    def test_account_scoped_items_are_independent(self):
        self.s.write(self.svc, "a1", "one")
        self.s.write(self.svc, "a2", "two")
        self.assertEqual(self.s.read(self.svc, "a1")["secret"], "one")
        self.assertEqual(self.s.read(self.svc, "a2")["secret"], "two")
        self.s.replace(self.svc, "a1", "uno", exclusive=False)
        self.assertEqual(self.s.read(self.svc, "a2")["secret"], "two")
        self.s.delete_all(self.svc, "a1")
        self.assertIsNone(self.s.read(self.svc, "a1"))
        self.assertEqual(self.s.read(self.svc, "a2")["secret"], "two")

    def test_meta_roundtrip(self):
        meta = {"kind": "x", "attrs": {"k": "v"}}
        self.s.write(self.svc, "acct1", "s", meta)
        got = self.s.read(self.svc)
        if "meta" in got and got["meta"].get("kind") == "x":
            self.assertEqual(got["meta"], meta)


class TestMemoryStore(StoreContract, unittest.TestCase):
    def make(self):
        return A.MemoryStore()

    def test_failure_is_not_absence(self):
        self.s.fail.add("read")
        with self.assertRaises(A.Fatal):
            self.s.read(self.svc)


class TestFileStore(StoreContract, unittest.TestCase):
    def make(self):
        self.d = tempfile.mkdtemp()
        return A.FileStore(Path(self.d) / "kc")

    def test_reads_02_format_and_is_lazy(self):
        self.assertFalse((Path(self.d) / "kc").exists())
        f = self.s._f(self.svc)
        f.parent.mkdir(parents=True)
        f.write_text(json.dumps({"account": "me", "secret": "old"}))
        self.assertEqual(self.s.read(self.svc), {"account": "me", "secret": "old"})


class FakeSecurity:
    def setUp(self):
        self.fdir = Path(tempfile.mkdtemp())
        exe = self.fdir / "security"
        exe.write_text(f"#!{sys.executable}\n" + (ROOT / "tests/fake_security.py").read_text())
        exe.chmod(0o755)
        self._p = [mock.patch.object(A.MacKeychain, "SECURITY", str(exe)),
                   mock.patch.dict(os.environ, {"FAKE_SEC_DB": str(self.fdir / "db.json"),
                                                "FAKE_SEC_LOG": str(self.fdir / "log")})]
        for p in self._p:
            p.start()
        super().setUp()

    def tearDown(self):
        super().tearDown()
        for p in reversed(self._p):
            p.stop()
        shutil.rmtree(self.fdir)

    def argv_log(self):
        try:
            return [json.loads(x) for x in (self.fdir / "log").read_text().splitlines()]
        except FileNotFoundError:
            return []


@unittest.skipUnless(POSIX, "fake security is a posix script")
class TestMacKeychainFake(FakeSecurity, StoreContract, unittest.TestCase):
    def make(self):
        return A.MacKeychain()

    def test_secrets_never_on_argv_when_they_fit(self):
        for secret in ("short", "ü\nnewline", self.big):
            self.s.write(self.svc, "acct1", secret)
        self.assertFalse(self.s.used_argv_fallback)
        for argv in self.argv_log():
            self.assertNotIn("-w", argv[:-1] if argv and argv[0] != "find-generic-password" else [])
            self.assertFalse(any("x" * 100 in a for a in argv))

    def test_long_secret_never_goes_through_truncating_stdin(self):
        long = "y" * 5000
        self.s.write(self.svc, "acct1", "previous")
        with mock.patch.dict(os.environ, {"AISWITCH_NO_ARGV_SECRETS": "1"}):
            with self.assertRaises(A.Fatal):
                self.s.write(self.svc, "acct1", long)
        self.assertEqual(self.s.read(self.svc)["secret"], "previous")      # untouched, not truncated
        self.assertFalse([a for a in self.argv_log() if a[:1] == ["-i"]][1:])
        self.s.write(self.svc, "acct1", long)                               # default: argv fallback
        self.assertTrue(self.s.used_argv_fallback)
        self.assertEqual(self.s.read(self.svc)["secret"], long)

    def test_locked_keychain_is_an_error(self):
        self.s.write(self.svc, "acct1", "s")
        with mock.patch.dict(os.environ, {"FAKE_SEC_FAIL": "locked"}):
            for fn in (lambda: self.s.read(self.svc), lambda: self.s.account(self.svc),
                       lambda: self.s.delete(self.svc)):
                with self.assertRaises(A.Fatal):
                    fn()

    def test_hex_password_output_is_decoded(self):
        self.s.write(self.svc, "acct1", "naïve\x01ctl")
        self.assertEqual(self.s.read(self.svc)["secret"], "naïve\x01ctl")

    def test_parsers(self):
        pa = A.MacKeychain._parse_acct
        self.assertEqual(pa('    "acct"<blob>="alice"\n'), "alice")
        self.assertEqual(pa('    "acct"<blob>=<NULL>\n'), "")
        self.assertEqual(pa('    "acct"<blob>=0x C3A9  "\\303\\251"\n'.replace("0x C3", "0xC3")), "é")
        self.assertIsNone(pa("nothing here"))
        pp = A.MacKeychain._parse_pw
        self.assertEqual(pp('password: "abc"\n'), "abc")
        self.assertEqual(pp("password: \n"), "")
        self.assertEqual(pp('password: 0x610A62  "a\\012b"\n'), "a\nb")
        self.assertIsNone(pp("nope"))


@unittest.skipUnless(REAL_STORE and sys.platform == "darwin", "set AISWITCH_TEST_REAL_STORE=1 on macOS")
class TestMacKeychainReal(StoreContract, unittest.TestCase):
    def make(self):
        return A.MacKeychain()

    def test_secret_not_on_argv(self):
        self.s.write(self.svc, "acct1", "topsecret")
        self.s.write(self.svc, "acct1", "ü\nnewline")
        self.s.write(self.svc, "acct1", self.big)
        self.assertFalse(self.s.used_argv_fallback, "security -i stdin route did not verify")


@unittest.skipUnless(REAL_STORE and POSIX and sys.platform != "darwin" and shutil.which("secret-tool"),
                     "set AISWITCH_TEST_REAL_STORE=1 with an unlocked Secret Service")
class TestSecretServiceReal(StoreContract, unittest.TestCase):
    def make(self):
        return A.SecretServiceStore()

    def test_keytar_and_keyring_rs_style_items_keep_their_attributes(self):
        def st(attrs, secret):
            subprocess.run(["secret-tool", "store", "--label=t", *sum(([k, v] for k, v in attrs.items()), [])],
                           input=secret.encode(), check=True)
        st({"service": self.svc, "account": "a1"}, "keytar-secret")
        item = self.s.read(self.svc, "a1")
        self.assertEqual(item["secret"], "keytar-secret")
        self.s.replace(self.svc, "a1", "new", item["meta"], exclusive=False)
        r = subprocess.run(["secret-tool", "lookup", "service", self.svc, "account", "a1"], capture_output=True)
        self.assertEqual(r.stdout, b"new")
        self.s.delete_all(self.svc, "a1")
        st({"service": self.svc, "username": "a2", "application": "rust-keyring"}, "rs")
        self.assertEqual(self.s.account(self.svc), "a2")
        self.assertEqual(self.s.read(self.svc)["meta"]["attrs"]["application"], "rust-keyring")

    def test_item_without_account_keeps_its_attributes(self):
        subprocess.run(["secret-tool", "store", "--label=t", "service", self.svc], input=b"s1", check=True)
        item = self.s.read(self.svc)
        self.s.replace(self.svc, item["account"], "s2", item["meta"])
        r = subprocess.run(["secret-tool", "search", "--all", "service", self.svc], capture_output=True)
        self.assertNotIn(b"username", r.stderr)
        self.assertEqual(self.s.read(self.svc)["secret"], "s2")

    def test_vault_keeps_meta(self):
        v = A.SecretServiceStore(vault=True)
        meta = {"kind": "secret-service", "attrs": {"service": "x", "account": "y"}, "label": "L"}
        v.write(self.svc, "acct", "s", meta)
        self.assertEqual(v.read(self.svc)["meta"], meta)
        v.delete(self.svc)

    def test_no_bus_is_an_error(self):
        with mock.patch.dict(os.environ, {"DBUS_SESSION_BUS_ADDRESS": "", "XDG_RUNTIME_DIR": "/nonexistent",
                                          "DISPLAY": ""}):
            with self.assertRaises(A.Fatal):
                A.SecretServiceStore().read(self.svc)


@unittest.skipUnless(REAL_STORE and POSIX and sys.platform != "darwin" and shutil.which("secret-tool"),
                     "set AISWITCH_TEST_REAL_STORE=1 with an unlocked Secret Service")
class TestSecretServiceEndToEnd(Env):
    """save / new / use through the real Linux backends (live + vault), keytar-style item."""

    def setUp(self):
        super().setUp()
        A.STORE_FACTORY = None
        self.svc = f"aiswitch-e2e-{uuid.uuid4().hex[:8]}"
        self.store().mkdir()
        (self.store() / "platforms.json").write_text(json.dumps({"schema": 1, "platforms": {"tool": {
            "kind": "login", "label": "Tool", "artifacts": [
                {"name": "kc", "type": "keychain", "service": self.svc, "account": "main-account", "primary": True}],
        }}}))

    def tearDown(self):
        subprocess.run(["secret-tool", "clear", "service", self.svc])
        with contextlib.suppress(A.Fatal):
            self.run_cli("purge", "-y", ok=None)
        super().tearDown()

    def put(self, secret):
        subprocess.run(["secret-tool", "store", "--label=Tool", "service", self.svc, "account", "main-account"],
                       input=secret.encode(), check=True)

    def get(self):
        r = subprocess.run(["secret-tool", "lookup", "service", self.svc, "account", "main-account"],
                           capture_output=True)
        return r.stdout.decode() if r.returncode == 0 else None

    def vault_services(self):
        r = subprocess.run(["secret-tool", "search", "--all", "application", "aiswitch"], capture_output=True)
        return {ln.split(" = ", 1)[1] for ln in r.stderr.decode().splitlines() if ln.startswith("attribute.service = ")}

    def test_switch(self):
        before = self.vault_services()
        self.put("alice-token\nline2")
        self.run_cli("save", "tool", "alice")
        self.run_cli("new", "tool", "bob")
        self.assertIsNone(self.get())
        self.put("bob-token")
        self.run_cli("save", "tool", "bob")
        self.run_cli("use", "tool", "alice")
        self.assertEqual(self.get(), "alice-token\nline2")     # same attributes: the tool finds it
        self.run_cli("rm", "tool", "bob", "-y")
        self.assertEqual(self.vault_services() - before, self.all_refs())   # no orphaned saved copies
        self.run_cli("purge", "-y")
        self.assertEqual(self.vault_services() - before, set())


@unittest.skipUnless(REAL_STORE and sys.platform == "win32", "set AISWITCH_TEST_REAL_STORE=1 on Windows")
class TestWinCredReal(StoreContract, unittest.TestCase):
    big = "z" * 1200                     # UTF-16LE blob cap is 2560 bytes

    def make(self):
        return A.WinCredStore()

    def test_account_scoped_items_are_independent(self):
        self.skipTest("Credential Manager targets are unique per service")

    def test_replace_other_account(self):
        self.s.write(self.svc, "old", "s1")
        self.s.replace(self.svc, "new", "s2")
        self.assertEqual(self.strip(self.s.read(self.svc)), {"account": "new", "secret": "s2"})

    def test_cap_and_utf8_blob_preserved(self):
        with self.assertRaises(A.Fatal):
            self.s.write(self.svc, "a", "q" * 2000)
        self.s.write(self.svc, "a", "x", {"kind": A.WinCredStore.name, "enc": "utf-8"})
        item = self.s.read(self.svc)
        self.assertEqual((item["secret"], item["meta"]["enc"]), ("x", "utf-8"))

    def test_dpapi_vault(self):
        d = Path(tempfile.mkdtemp())
        v = A.DpapiFileStore(d / "vault")
        v.write("aiswitch:x", "acct", "s" * 10000, {"kind": "k"})
        self.assertEqual(v.read("aiswitch:x")["secret"], "s" * 10000)
        self.assertNotIn(b"sss", next((d / "vault").iterdir()).read_bytes())


# ----------------------------------------------------------------- end-to-end flows
class TestCodexFlow(Env):
    def test_save_use_save_byte_equal(self):
        a = self.codex_login("a@x.com", "A1", "ü-alice").read_bytes()
        self.run_cli("save", "codex", "alice")
        self.run_cli("new", "codex", "bob")
        self.assertFalse((self.home / ".codex/auth.json").exists())
        b = self.codex_login("b@x.com", "B1").read_bytes()
        self.run_cli("save", "codex", "bob")
        self.run_cli("use", "cx", "alice")
        self.assertEqual(self.read(".codex/auth.json"), a)
        self.run_cli("use", "cx", "bob")
        self.assertEqual(self.read(".codex/auth.json"), b)
        _, out, _ = self.run_cli("current", "codex")
        self.assertIn("bob", out)

    def test_writeback_of_refreshed_tokens(self):
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "alice")
        self.run_cli("new", "codex", "bob")
        self.codex_login("b@x.com", "B1")
        self.run_cli("save", "codex", "bob")
        self.run_cli("use", "codex", "alice")
        refreshed = self.codex_login("a@x.com", "A1", "refreshed").read_bytes()
        self.run_cli("use", "codex", "bob")
        self.assertEqual((A.snap_dir("codex", "alice") / "auth").read_bytes(), refreshed)

    def test_unsaved_guard_force_and_backup(self):
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "alice")
        self.run_cli("new", "codex", "bob")
        live = self.codex_login("z@x.com", "Z9").read_bytes()
        rc, _, err = self.run_cli("use", "codex", "alice", ok=False)
        self.assertIn("isn't saved", err)
        self.assertEqual(self.read(".codex/auth.json"), live)
        self.run_cli("use", "codex", "alice", "--force")
        backups = A.backup_dirs("codex")
        self.assertTrue(backups)
        self.assertEqual((backups[-1] / "auth").read_bytes(), live)

    def test_empty_save_refused(self):
        _, _, err = self.run_cli("save", "codex", "nobody", ok=False)
        self.assertIn("no Codex CLI login found", err)
        self.run_cli("save", "codex", "nobody", "--allow-empty")

    def test_duplicate_identity_rejected(self):
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "alice")
        self.run_cli("save", "codex", "alice", "--force")
        _, _, err = self.run_cli("save", "codex", "alice2", ok=False)
        self.assertIn("already saved as 'alice'", err)
        self.run_cli("save", "codex", "alice2", "--allow-duplicate")

    def test_rm_and_backup_pruning_numeric(self):
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "alice")
        br = A.backup_root("codex")
        for n in ["20260101-000000", "20260101-000000-2", "20260101-000000-10",
                  "20260101-000000-9", "20250101-000000", "20260102-000000"]:
            (br / n).mkdir(parents=True)
            (br / n / "meta.json").write_text("{}")
        names = [p.name for p in A.backup_dirs("codex")]
        self.assertEqual(names, ["20250101-000000", "20260101-000000", "20260101-000000-2",
                                 "20260101-000000-9", "20260101-000000-10", "20260102-000000"])
        A.prune_backups("codex", A.stores())
        self.assertEqual([p.name for p in A.backup_dirs("codex")], names[-5:])
        self.run_cli("rm", "codex", "alice", "-y")
        self.assertFalse(A.snap_dir("codex", "alice").exists())

    def test_codex_home_override(self):
        os.environ["CODEX_HOME"] = str(self.tmp / "ch")
        p = self.tmp / "ch/auth.json"
        p.parent.mkdir()
        p.write_text(json.dumps({"tokens": {"id_token": jwt({"email": "c@x"}), "account_id": "C"}}))
        _, out, _ = self.run_cli("save", "codex", "c")
        self.assertIn("c@x|C", out)

    def test_keyring_mode_refused_off_macos(self):
        self.codex_login("a@x.com", "A1")
        for mode in ("keyring", "auto"):
            self.write(".codex/config.toml", f'model = "x"\n[profiles.w]\ncli_auth_credentials_store = "{mode}"\n')
            _, _, err = self.run_cli("save", "codex", "alice", ok=False)
            self.assertIn(mode, err)
        self.write(".codex/config.toml", 'cli_auth_credentials_store = "ephemeral"\n')
        _, _, err = self.run_cli("save", "codex", "alice", ok=False)
        self.assertIn("ephemeral", err)
        self.write(".codex/config.toml", "cli_auth_credentials_store = 'file'\n")
        self.run_cli("save", "codex", "alice")

    def test_names(self):
        self.codex_login("a@x.com", "A1")
        for bad in ("con", "NUL.txt", "com1", "a.", "-x", "a/b", "x" * 41, "conin$"):
            with self.assertRaises(A.Fatal):
                A.check_name(bad)
        self.run_cli("save", "codex", "con", ok=False)
        self.run_cli("save", "codex", "Alice")
        _, _, err = self.run_cli("save", "codex", "alice", "--allow-duplicate", ok=False)
        self.assertIn("only by case", err)


class TestCodexKeyringMac(Env):
    os_tag = "darwin"

    def test_keyring_item_switched_without_touching_other_codex_homes(self):
        self.write(".codex/config.toml", 'cli_auth_credentials_store = "keyring"\n')
        acct = A.expand_str("cli|{codex_home_hash}")
        self.kc.put("Codex Auth", "cli|otherhome0000000", "OTHER")

        def tok(e, a):
            return json.dumps({"tokens": {"id_token": jwt({"email": e}), "account_id": a}})
        self.kc.put("Codex Auth", acct, tok("a@x", "A1"))
        _, out, _ = self.run_cli("save", "codex", "alice")
        self.assertIn("a@x|A1", out)
        self.run_cli("new", "codex", "bob")
        self.assertIsNone(self.kc.get("Codex Auth", acct))
        self.assertEqual(self.kc.get("Codex Auth", "cli|otherhome0000000"), "OTHER")
        self.kc.put("Codex Auth", acct, tok("b@x", "B1"))
        self.run_cli("save", "codex", "bob")
        self.kc.put("Codex Auth", acct, tok("b@x", "B1") + " ")        # refreshed by Codex
        _, out, _ = self.run_cli("use", "codex", "alice")             # identity known: no --force
        self.assertIn("synced current login back into 'bob'", out)
        self.assertIn("A1", self.kc.get("Codex Auth", acct))
        self.kc.fail.add("read")                                        # ls/current never read secrets
        self.run_cli("ls", "codex")
        self.run_cli("current", "codex")
        self.kc.fail.clear()
        self.assertEqual(self.kc.get("Codex Auth", "cli|otherhome0000000"), "OTHER")


class TestGemini(Env):
    def test_gemini_cli_home_and_encrypted_mode(self):
        os.environ["GEMINI_CLI_HOME"] = str(self.tmp / "gh")
        g = self.tmp / "gh/.gemini"
        g.mkdir(parents=True)
        (g / "oauth_creds.json").write_text('{"t": "alice"}')
        (g / "google_accounts.json").write_text('{"active": "alice@g"}')
        _, out, _ = self.run_cli("save", "gemini", "alice")
        self.assertIn("alice@g", out)
        os.environ["GEMINI_FORCE_ENCRYPTED_FILE_STORAGE"] = "true"
        os.environ["GEMINI_FORCE_FILE_STORAGE"] = "true"
        arts = {a["name"] for a in A.artifacts(A.load_platforms()["gemini"])}
        self.assertEqual(arts, {"oauth", "accounts", "encrypted"})
        os.environ.pop("GEMINI_FORCE_FILE_STORAGE")
        arts = {a["name"] for a in A.artifacts(A.load_platforms()["gemini"])}
        self.assertEqual(arts, {"oauth", "accounts", "encrypted", "keychain"})
        with mock.patch.object(A, "is_wsl", lambda: True):
            self.assertNotIn("keychain", {a["name"] for a in A.artifacts(A.load_platforms()["gemini"])})
        self.kc.put("gemini-cli-oauth", "main-account", "kc-alice")
        (g / "oauth_creds.json").unlink()
        (g / "google_accounts.json").write_text('{"active": "alice@g"}')
        self.run_cli("save", "gemini", "alice", "--force")
        self.kc.put("gemini-cli-oauth", "main-account", "kc-bob")
        self.kc.put("gemini-cli-oauth", "mcp-server-x", "MCP")
        (g / "google_accounts.json").write_text('{"active": "bob@g"}')
        self.run_cli("save", "gemini", "bob")
        self.run_cli("use", "gemini", "alice")
        self.assertEqual(self.kc.get("gemini-cli-oauth", "main-account"), "kc-alice")
        self.assertEqual(self.kc.get("gemini-cli-oauth", "mcp-server-x"), "MCP")


class TestRollback(Env):
    def setUp(self):
        super().setUp()
        self.write(".gemini/oauth_creds.json", '{"t": "alice"}')
        self.write(".gemini/google_accounts.json", '{"active": "alice@g"}')
        self.run_cli("save", "gemini", "alice")
        self.run_cli("new", "gemini", "bob")
        self.write(".gemini/oauth_creds.json", '{"t": "bob"}')
        self.write(".gemini/google_accounts.json", '{"active": "bob@g"}')
        self.run_cli("save", "gemini", "bob")

    def _failing_restore(self, fail_on, exc=OSError("disk full (injected)")):
        real = A.restore

        def restore(spec, src, ent, st):
            if spec["name"] == fail_on and "snapshots" in str(src):
                raise exc
            return real(spec, src, ent, st)
        return mock.patch.object(A, "restore", restore)

    def test_failed_switch_restores_previous(self):
        with self._failing_restore("accounts"):
            _, _, err = self.run_cli("use", "gemini", "alice", ok=False)
        self.assertIn("injected", err)
        self.assertIn("previous login restored", err)
        self.assertEqual(self.read(".gemini/oauth_creds.json"), b'{"t": "bob"}')

    def test_interrupt_rolls_back(self):
        with self._failing_restore("accounts", KeyboardInterrupt()):
            _, _, err = self.run_cli("use", "gemini", "alice", ok=False)
        self.assertIn("KeyboardInterrupt", err)
        self.assertEqual(self.read(".gemini/oauth_creds.json"), b'{"t": "bob"}')

    def test_failed_switch_without_backup_goes_all_absent(self):
        self.run_cli("new", "gemini", "carol")
        with self._failing_restore("accounts"):
            _, _, err = self.run_cli("use", "gemini", "alice", ok=False)
        self.assertIn("left logged out", err)
        self.assertFalse((self.home / ".gemini/oauth_creds.json").exists())
        self.assertFalse((self.home / ".gemini/google_accounts.json").exists())

    def test_rollback_failure_still_reports_original_error(self):
        real = A.restore

        def restore(spec, src, ent, st):
            if spec["name"] == "accounts":
                raise OSError("boom-" + ("snap" if "snapshots" in str(src) else "backup"))
            return real(spec, src, ent, st)
        with mock.patch.object(A, "restore", restore):
            _, _, err = self.run_cli("use", "gemini", "alice", ok=False)
        self.assertIn("boom-snap", err)
        self.assertIn("ALSO failed", err)
        self.assertIn("boom-backup", err)


class TestClaudeCodeMac(Env):
    """Keychain-backed flow with the in-memory store standing in for the macOS Keychain."""
    os_tag = "darwin"
    SVC = "Claude Code-credentials"

    def login(self, who):
        self.kc.items.pop(self.SVC, None)
        self.kc.put(self.SVC, "me", json.dumps({"tok": who}))
        cfg = {"theme": "dark", "名前": "ü"}
        cfg["oauthAccount"] = {"emailAddress": f"{who}@x", "organizationUuid": "org-" + who}
        self.write(".claude.json", json.dumps(cfg, ensure_ascii=False))

    def setUp(self):
        super().setUp()
        self.login("alice")
        self.run_cli("save", "claude-code", "alice")
        self.run_cli("new", "cc", "bob")
        self.assertNotIn(self.SVC, self.kc.items)
        self.login("bob")
        self.run_cli("save", "claude-code", "bob")

    def test_switch_and_other_settings_kept(self):
        cfg = json.loads(self.read(".claude.json"))
        cfg["theme"] = "light"
        self.write(".claude.json", json.dumps(cfg))
        self.run_cli("use", "cc", "alice")
        self.assertEqual(json.loads(self.kc.get(self.SVC)), {"tok": "alice"})
        cfg = json.loads(self.read(".claude.json"))
        self.assertEqual(cfg["theme"], "light")
        self.assertEqual(cfg["oauthAccount"]["emailAddress"], "alice@x")
        self.assertEqual(cfg["名前"], "ü")
        self.assertIn("名前", self.read(".claude.json").decode("utf-8"))

    def test_file_fallback_is_switched_too(self):
        self.write(".claude/.credentials.json", '{"tok": "bob-file"}')
        self.run_cli("save", "cc", "bob", "--force")
        self.run_cli("use", "cc", "alice")
        self.assertFalse((self.home / ".claude/.credentials.json").exists())   # alice had none
        self.run_cli("use", "cc", "bob")
        self.assertEqual(self.read(".claude/.credentials.json"), b'{"tok": "bob-file"}')

    def test_config_dir_uses_suffixed_keychain_item(self):
        cdir = self.tmp / "work"
        cdir.mkdir()
        os.environ["CLAUDE_CONFIG_DIR"] = str(cdir)
        svc = A.expand_str("Claude Code-credentials{claude_kc_suffix}")
        self.assertNotEqual(svc, self.SVC)
        self.kc.put(svc, "me", "work-token")
        (cdir / ".claude.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "w@x"}}))
        self.run_cli("save", "cc", "work")
        meta = json.loads((A.snap_dir("claude-code", "work") / "meta.json").read_text())
        ref = A.VAULT_PREFIX + meta["artifacts"]["keychain"]["ref"]
        self.assertEqual(self.kc.get(ref), "work-token")
        self.assertEqual(json.loads(self.kc.get(self.SVC)), {"tok": "bob"})   # default profile untouched

    def test_locked_keychain_is_a_hard_error_not_absence(self):
        backups = A.backup_dirs("claude-code")
        self.kc.fail.add("read")
        _, _, err = self.run_cli("use", "cc", "alice", ok=False)
        self.assertIn("simulated keychain failure", err)
        self.kc.fail.clear()
        self.assertEqual(json.loads(self.kc.get(self.SVC)), {"tok": "bob"})
        self.assertEqual(A.backup_dirs("claude-code"), backups)

    def test_keychain_failure_on_save_leaves_no_partial_snapshot(self):
        before = {k: dict(v) for k, v in self.kc.items.items()}
        self.kc.fail.add("write")
        self.run_cli("save", "cc", "bob", "--force", ok=False)
        self.kc.fail.clear()
        self.assertEqual(self.kc.items, before)
        meta = json.loads((A.snap_dir("claude-code", "bob") / "meta.json").read_text())
        self.assertIn(A.VAULT_PREFIX + meta["artifacts"]["keychain"]["ref"], self.kc.items)
        self.assertFalse([p for p in A.snap_dir("claude-code", "x").parent.iterdir()
                          if p.name.startswith(".")])

    def test_resave_rotates_refs_without_orphans(self):
        self.run_cli("save", "cc", "bob", "--force")
        self.run_cli("use", "cc", "alice")
        self.run_cli("rm", "cc", "bob", "-y")
        self.assertEqual(self.all_refs(), self.vault_keys())

    def test_interrupted_tmp_dir_is_cleaned(self):
        tmp = A.hidden_sibling(A.snap_dir("claude-code", "zed"), "tmp")
        tmp.mkdir()
        self.kc.put(A.VAULT_PREFIX + "deadbeef", "a", "s")
        (tmp / "pending-refs.json").write_text(json.dumps([A.VAULT_PREFIX + "deadbeef"]))
        self.run_cli("save", "cc", "zed", "--allow-duplicate")
        self.assertFalse(tmp.exists())
        self.assertNotIn(A.VAULT_PREFIX + "deadbeef", self.kc.items)

    def test_legacy_schema1_snapshot_restores_and_deletes(self):
        d = A.snap_dir("claude-code", "old")
        d.mkdir(parents=True)
        legacy_key = A.VAULT_PREFIX + str(Path("snapshots/claude-code/old")) + ":keychain"
        self.kc.put(legacy_key, "me", '{"tok": "old"}')
        (d / "account.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "old@x",
                                                                       "organizationUuid": "o"}}))
        (d / "meta.json").write_text(json.dumps({"saved_at": "x", "identity": "old@x|o", "artifacts": {
            "keychain": {"type": "keychain", "present": True},
            "account": {"type": "json_keys", "present": True}}}))
        self.run_cli("use", "cc", "old")
        self.assertEqual(self.kc.get(self.SVC), '{"tok": "old"}')
        self.run_cli("use", "cc", "alice")
        self.assertNotIn(legacy_key, self.kc.items)
        self.run_cli("rm", "cc", "old", "-y")
        self.assertEqual(self.all_refs(), self.vault_keys())


class TestDesktopApp(Env):
    os_tag = "darwin"
    base = "Library/Application Support/Claude/"
    exe = "/Applications/Claude.app/Contents/MacOS/Claude"

    def setUp(self):
        super().setUp()
        self.write(self.base + "Cookies", "alice-cookie")
        self.write(self.base + "Local Storage/leveldb/1.ldb", "alice-ls")
        self.write(self.base + "config.json", '{"oauth:tokenCache": "alice", "keep": 1}')
        self.run_cli("save", "cd", "alice")

    def test_refuses_while_running_and_on_save(self):
        self.procs = [P(4242, self.exe, [self.exe])]
        _, _, err = self.run_cli("save", "cd", "alice2", ok=False)
        self.assertIn("is running", err)
        _, _, err = self.run_cli("new", "cd", "bob", ok=False)
        self.assertIn("is running", err)

    def test_cli_and_app_are_told_apart(self):
        self.procs = [P(1, "/usr/local/bin/claude", ["claude"])]          # Claude Code CLI only
        self.assertEqual(A.running_state(A.load_platforms()["claude-desktop"], A.proc_table(True)), ([], False))
        helper = "/Applications/Claude.app/Contents/Frameworks/Claude Helper (Renderer).app/Contents/MacOS/Claude Helper (Renderer)"
        self.procs = [P(2, self.exe, [self.exe]), P(3, helper, [helper, "--type=renderer"])]
        pt = A.proc_table(True)
        self.assertEqual(A.running_state(A.load_platforms()["claude-code"], pt), ([], False))
        self.assertTrue(A.running_state(A.load_platforms()["claude-desktop"], pt)[0])
        with mock.patch.object(A.os, "getpgid", lambda pid: -1, create=True):
            self.assertEqual(A._quit_targets(A.load_platforms()["claude-desktop"]), [2])

    def test_no_writeback_without_flag(self):
        self.run_cli("new", "cd", "bob")
        self.assertFalse((self.home / self.base / "Cookies").exists())
        self.assertEqual(json.loads(self.read(self.base + "config.json")), {"keep": 1})
        self.write(self.base + "Cookies", "bob-cookie")
        self.run_cli("save", "cd", "bob")
        self.write(self.base + "Cookies", "mallory-cookie")
        _, out, _ = self.run_cli("use", "cd", "alice")
        self.assertIn("not syncing", out)
        self.assertEqual((A.snap_dir("claude-desktop", "bob") / "cookies").read_bytes(), b"bob-cookie")
        self.assertEqual(self.read(self.base + "Cookies"), b"alice-cookie")
        self.assertEqual(self.read(self.base + "Local Storage/leveldb/1.ldb"), b"alice-ls")
        self.write(self.base + "Cookies", "alice-refreshed")
        self.run_cli("use", "cd", "bob", "--writeback")
        self.assertEqual((A.snap_dir("claude-desktop", "alice") / "cookies").read_bytes(), b"alice-refreshed")

    def test_interrupted_dir_swap_is_repaired(self):
        live = self.home / self.base / "Local Storage"
        old = live.parent / ".Local Storage.aiswitch-old-0123abcd"
        live.rename(old)                                    # crash after "rename away"
        (live.parent / ".Local Storage.aiswitch-new-89abcdef").mkdir()
        (live.parent / ".aiswitch-tmp_1234").write_text("secret temp")
        _, _, err = self.run_cli("save", "cd", "alice", "--force")
        self.assertIn("interrupted switch", err)
        self.assertEqual(self.read(self.base + "Local Storage/leveldb/1.ldb"), b"alice-ls")
        self.assertEqual(sorted(p.name for p in live.parent.iterdir() if p.name.startswith(".")), [])


class TestDesktopOtherOS(Env):
    def test_linux_and_windows_paths(self):
        plat = A.load_platforms()["claude-desktop"]
        p = A.spec_path(A.artifacts(plat)[0])
        self.assertEqual(p, self.home / ".config/Claude/Cookies")
        self.procs = [P(5, "/usr/lib/claude-desktop/claude-desktop", ["/usr/lib/claude-desktop/claude-desktop"]),
                      P(6, "/home/u/.local/bin/claude", ["claude"])]
        pt = A.proc_table(True)
        self.assertTrue(A.running_state(plat, pt)[0])
        self.assertEqual(A.running_state(A.load_platforms()["claude-code"], pt)[0], ["claude"])
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        A._PROC_CACHE = None
        plat = A.load_platforms()["claude-desktop"]
        self.procs = [P(7, r"C:\Program Files\WindowsApps\Claude_1.0_x64__pzs8sxrjxfjjc\app\Claude.exe",
                        [r"C:\Program Files\WindowsApps\Claude_1.0_x64__pzs8sxrjxfjjc\app\Claude.exe"]),
                      P(8, r"C:\Users\u\.local\bin\claude.exe", [r"C:\Users\u\.local\bin\claude.exe"])]
        pt = A.proc_table(True)
        self.assertTrue(A.running_state(plat, pt)[0])
        self.assertEqual(A.find_pids if hasattr(A, "find_pids") else None, None)
        hits = pt.find(**A.proc_spec(A.load_platforms()["claude-code"]))
        self.assertEqual([h[0] for h in hits], [8])


# -------------------------------------------------------------------- processes
class TestProcesses(Env):
    def test_matching(self):
        pt = A.ProcTable([
            P(1, "/usr/bin/node", ["node", "--no-warnings", "/usr/local/bin/gemini"]),
            P(2, "/x/codex-x86_64-unknown-linux-musl", ["/x/node_modules/@openai/codex/bin/codex-x86_64-unknown-linux-musl"]),
            P(3, "/usr/bin/python3", ["python3", "/x/aiswitch.py", "use", "codex", "a"]),
            P(4, "/usr/bin/claude", ["claude"]),
            P(5, "/usr/bin/less", ["less", "/x/@anthropic-ai/claude-code/README.md"]),
        ])
        self.assertTrue(pt.running("gemini"))
        self.assertTrue(pt.running("codex"))             # arch-suffixed native binary
        self.assertTrue(pt.running("claude"))
        self.assertFalse(pt.running("aider"))
        self.assertIsNone(A.ProcTable(None).running("claude"))
        hits = pt.find(["claude"], (), ["@anthropic-ai/claude-code"])
        self.assertEqual({(h[0], h[1]) for h in hits}, {(4, "strong"), (5, "weak")})

    def test_windows_command_lines(self):
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        node = r"C:\Program Files\nodejs\node.exe"
        script = r"C:\Users\u\AppData\Roaming\npm\node_modules\@anthropic-ai\claude-code\cli.js"
        pt = A.ProcTable([P(1, node, [node, script]), P(2, r"C:\x\Codex.EXE", [r"C:\x\Codex.EXE"])])
        self.assertTrue(pt.find(["claude"], (), ["@anthropic-ai/claude-code"]))
        self.assertTrue(pt.running("codex"))

    def test_partial_table_reports_unknown(self):
        pt = A.ProcTable([P(1, "/bin/sh", ["sh"])], partial=True)
        self.assertIsNone(pt.running("claude"))
        self.assertEqual(A.running_state(A.load_platforms()["claude-code"], pt), ([], True))

    def test_unknown_warns(self):
        A.PROC_PROVIDER = lambda: None
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "alice")
        _, _, err = self.run_cli("new", "codex", "bob")
        self.assertIn("cannot detect", err)

    def test_launch_argv_keeps_urls_and_flags(self):
        argv = A._launch_argv(["~/bin/app", "https://claude.ai/x", "--a=b//c", "{home}/f"])
        self.assertEqual([Path(argv[0]), argv[1], argv[2], Path(argv[3])],
                         [self.home / "bin/app", "https://claude.ai/x", "--a=b//c", self.home / "f"])
        self.assertEqual(A._launch_argv("flatpak run com.anthropic.Claude"),
                         ["flatpak", "run", "com.anthropic.Claude"])

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin", "posix")
    def test_real_table_sees_a_child(self):
        A.PROC_PROVIDER = None
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "aiswitch-probe-xyz"])
        try:
            time.sleep(0.3)
            pt = A.proc_table(refresh=True)
            self.assertIsNotNone(pt.procs)
            self.assertTrue(pt.find((), (), ["aiswitch-probe-xyz"]))
        finally:
            p.kill()
            p.wait()

    @unittest.skipUnless(POSIX and shutil.which("ps") and
                         "busybox" not in os.path.realpath(shutil.which("ps") or ""),
                         "needs a procps/BSD ps (busybox ps has no uid column; Linux reads /proc)")
    def test_ps_backend_ignores_columns(self):
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "x" * 300 + "-tail-marker"])
        try:
            time.sleep(0.3)
            with mock.patch.dict(os.environ, {"COLUMNS": "40"}):
                procs = A._procs_ps()
            self.assertTrue(any("-tail-marker" in q.cmdline for q in procs))
        finally:
            p.kill()
            p.wait()


# ------------------------------------------------------------------------ browsers
class TestBrowsers(Env):
    def setUp(self):
        super().setUp()
        (self.tmp / "bin").mkdir(exist_ok=True)
        os.environ["PATH"] = str(self.tmp / "bin")      # hermetic: no real browsers / flatpak

    def local_state(self, rel, profiles):
        self.write(rel + "/Local State", json.dumps(
            {"profile": {"info_cache": {d: {"name": n} for d, n in profiles.items()}}}))

    @unittest.skipUnless(POSIX, "uses sh scripts as fake browsers")
    def test_chromium_only_machine_uses_chromium_dir(self):
        log = self.tmp / "launch.log"
        self.fake_bin("chromium", f"#!/bin/sh\necho \"$@\" > {log}\n")
        self.local_state(".config/chromium", {"Profile 1": "Work"})
        self.local_state(".config/google-chrome", {"Default": "Chrome Person"})   # Chrome data, no binary
        os.environ["DISPLAY"] = ":0"
        self.run_cli("save", "claude-web", "work", "--profile", "Work")
        meta = json.loads((A.snap_dir("claude-web", "work") / "meta.json").read_text())
        self.assertEqual((meta["browser"], meta["profile"]), ("chromium", "Profile 1"))
        self.run_cli("use", "claude-web", "work")
        time.sleep(0.3)
        self.assertIn("--profile-directory=Profile 1 https://claude.ai", log.read_text())

    @unittest.skipUnless(POSIX, "uses a sh script as a fake browser")
    def test_headless_launch_is_an_error(self):
        self.fake_bin("google-chrome")
        self.local_state(".config/google-chrome", {"Default": "Me"})
        self.run_cli("save", "claude-web", "me", "--profile", "Me")
        _, _, err = self.run_cli("use", "claude-web", "me", ok=False)
        self.assertIn("no graphical session", err)

    def test_missing_browser_and_profiles(self):
        _, _, err = self.run_cli("save", "claude-web", "me", "--profile", "Me", ok=False)
        self.assertIn("profiles found", err)

    def test_explicit_edge_on_windows(self):
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        self.local_state("AppData/Local/Microsoft/Edge/User Data", {"Default": "Me"})
        self.store().mkdir()
        (self.store() / "platforms.json").write_text(json.dumps(
            {"schema": 1, "platforms": {"claude-web": {"browser": "edge"}}}))
        b = A.select_browser(A.load_platforms()["claude-web"])
        self.assertEqual(b.label, "Microsoft Edge")
        self.assertEqual(A.chrome_profiles(b), {"Default": "Me"})

    def test_legacy_custom_browser_config(self):
        self.local_state("custom-ud", {"P": "Pers"})
        self.store().mkdir()
        (self.store() / "platforms.json").write_text(json.dumps(
            {"schema": 1, "platforms": {"claude-web": {"browser": "Vivaldi", "user_data": "~/custom-ud",
                                                       "browser_bin": "/nonexistent/vivaldi"}}}))
        b = A.select_browser(A.load_platforms()["claude-web"])
        self.assertEqual((b.preset, b.pass_user_data, b.launcher), ("custom", True, None))
        self.assertEqual(A.chrome_profiles(b), {"P": "Pers"})


# ------------------------------------------------------------------------ config
class TestConfig(Env):
    def cfg(self, data):
        self.store().mkdir(exist_ok=True)
        (self.store() / "platforms.json").write_text(json.dumps(data))

    def test_init_writes_skeleton_and_merges(self):
        self.run_cli("init")
        data = json.loads((self.store() / "platforms.json").read_text())
        self.assertEqual(data["schema"], A.CONFIG_SCHEMA)
        data["platforms"] = {"codex": {"processes": ["codex", "codex-dev"]},
                             "codex-work": {"extends": "codex", "label": "Codex (work)", "aliases": []},
                             "gemini": {"disabled": True}}
        self.cfg(data)
        plats = A.load_platforms()
        self.assertEqual(plats["codex"]["processes"], ["codex", "codex-dev"])
        self.assertEqual(plats["codex"]["artifacts"], A.DEFAULT_PLATFORMS["codex"]["artifacts"])
        self.assertEqual(plats["codex-work"]["label"], "Codex (work)")
        self.assertNotIn("gemini", plats)
        self.run_cli("init", ok=False)
        self.run_cli("init", "--force")
        self.assertTrue(list(self.store().glob("platforms.json.bak-*")))

    def test_legacy_config_warns(self):
        self.cfg({"codex": dict(A.DEFAULT_PLATFORMS["codex"])})
        _, _, err = self.run_cli("platforms")
        self.assertIn("old format", err)

    def test_dangerous_paths_refused(self):
        for path in ["~", "/", "~/.aiswitch/x", "~/.aiswitch"]:
            A._WARNED.clear()
            self.cfg({"schema": 1, "platforms": {"evil": {"kind": "login", "label": "e", "artifacts": [
                {"name": "d", "type": "dir", "path": path, "primary": True}]}}})
            _, _, err = self.run_cli("save", "evil", "x", ok=False)
            self.assertTrue("refusing to manage" in err or (os.name == "nt" and "must be absolute" in err),
                            f"{path}: {err}")

    def test_bad_names(self):
        for plats in ({"evil": {"kind": "login", "artifacts": [{"name": "../x", "type": "file", "path": "~/a"}]}},
                      {"evil": {"kind": "login", "artifacts": [{"name": "nul", "type": "file", "path": "~/a"}]}},
                      {"../x": {"kind": "login"}}, {"con": {"kind": "login"}},
                      {"Codex": {"kind": "login"}},
                      {"evil": {"kind": "login", "artifacts": [{"name": "a", "type": "file", "path": "~/a",
                                                                "enabled_if": "nope"}]}}):
            self.cfg({"schema": 1, "platforms": plats})
            self.run_cli("platforms", ok=False)

    def test_store_guard(self):
        other = self.tmp / "docs"
        other.mkdir()
        (other / "thesis.tex").write_text("x")
        os.environ["AISWITCH_HOME"] = str(other)
        _, _, err = self.run_cli("ls", ok=False)
        self.assertIn("does not look like an aiswitch store", err)
        os.environ["AISWITCH_HOME"] = str(self.home)
        self.run_cli("ls", ok=False)


# ------------------------------------------------------------------ fs / runtime
class TestRuntime(Env):
    def test_bom_json_is_read(self):
        self.write(".codex/auth.json", b"\xef\xbb\xbf" + json.dumps(
            {"tokens": {"id_token": jwt({"email": "a@x"}), "account_id": "A"}}).encode())
        _, out, _ = self.run_cli("save", "codex", "a")
        self.assertIn("a@x|A", out)

    @unittest.skipIf(sys.platform == "win32", "symlinks need privileges on Windows")
    def test_write_through_symlink(self):
        real = self.write("dotfiles/codex-auth.json", "x")
        (self.home / ".codex").mkdir()
        (self.home / ".codex/auth.json").symlink_to(real)
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "a")
        self.run_cli("new", "codex", "b")
        self.assertTrue((self.home / ".codex/auth.json").is_symlink())
        self.run_cli("use", "codex", "a")
        self.assertTrue((self.home / ".codex/auth.json").is_symlink())
        self.assertIn(b"A1", real.read_bytes())

    def test_readonly_json_file_is_updated(self):
        self.write(".claude/.credentials.json", '{"t": 1}')
        p = self.write(".claude.json", json.dumps({"oauthAccount": {"emailAddress": "a@x"}, "k": 1}))
        self.run_cli("save", "cc", "a")
        self.run_cli("new", "cc", "b")
        p.chmod(stat.S_IREAD)
        self.run_cli("use", "cc", "a")
        self.assertEqual(json.loads(p.read_text())["oauthAccount"]["emailAddress"], "a@x")
        self.assertFalse([x for x in self.home.iterdir() if x.name.startswith(".aiswitch-")])

    def test_glyph_fallback(self):
        class Cp1252(io.StringIO):
            encoding = "cp1252"
        with contextlib.redirect_stdout(Cp1252()):
            self.assertEqual(A.glyph("on"), "*")
        with contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
            self.assertEqual(A.glyph("on"), "●")

    def test_host_os(self):
        os.environ.pop("AISWITCH_FORCE_OS")
        for plat, want in (("win32", "windows"), ("cygwin", "windows"), ("linux", "linux"),
                           ("android", "linux"), ("freebsd14", "linux"), ("openbsd7", "linux"),
                           ("darwin", "darwin")):
            with mock.patch.object(sys, "platform", plat):
                self.assertEqual(A.host_os(), want, plat)

    def test_cygwin_is_refused(self):
        with mock.patch.object(sys, "platform", "cygwin"):
            _, _, err = self.run_cli("ls", ok=False)
        self.assertIn("native Windows Python", err)

    @unittest.skipUnless(POSIX and hasattr(os, "geteuid"), "posix")
    def test_sudo_is_refused(self):
        with mock.patch.object(A.os, "geteuid", lambda: 0), mock.patch.dict(os.environ, {"SUDO_UID": "1000"}):
            _, _, err = self.run_cli("ls", ok=False)
        self.assertIn("sudo", err)

    @unittest.skipUnless(POSIX, "posix")
    def test_chmod_unsupported_fs_warns(self):
        real = os.chmod

        def chmod(p, m, *a, **k):
            raise OSError(errno.EPERM, "Operation not permitted")
        with mock.patch.object(A.os, "chmod", chmod):
            self.codex_login("a@x.com", "A1")
            _, _, err = self.run_cli("save", "codex", "a")
        self.assertIn("no Unix permissions", err)
        self.assertIs(os.chmod, real)

    @unittest.skipUnless(POSIX, "posix")
    def test_lock_unsupported_fs_is_explained(self):
        import fcntl
        self.run_cli("ls")
        with mock.patch.object(fcntl, "flock", side_effect=OSError(errno.ENOLCK, "No locks available")):
            with self.assertRaises(A.Fatal) as cm:
                with A.lock():
                    pass
        self.assertIn("may not support locks", str(cm.exception))

    @unittest.skipUnless(POSIX, "posix signals")
    def test_sigterm_unwinds_like_ctrl_c(self):
        old = signal.getsignal(signal.SIGTERM)
        try:
            A.install_signal_handlers()
            with self.assertRaises(KeyboardInterrupt):
                os.kill(os.getpid(), signal.SIGTERM)
                time.sleep(1)
        finally:
            signal.signal(signal.SIGTERM, old)

    def test_windows_registry(self):
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        plats = A.load_platforms()
        arts = {a["name"]: a for a in A.artifacts(plats["claude-code"])}
        self.assertEqual(set(arts), {"credentials", "account"})
        self.assertEqual(A.expand(arts["credentials"]["path"]),
                         Path(str(self.home).replace("\\", "/") + "/.claude/.credentials.json"))
        self.assertIn("claude-desktop", plats)

    def test_store_python_appdata_refused(self):
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        with mock.patch.object(A, "is_store_python", lambda: True):
            spec = A.artifacts(A.load_platforms()["claude-desktop"])[0]
            with self.assertRaises(A.Fatal) as cm:
                A.spec_path(spec)
        self.assertIn("Microsoft Store", str(cm.exception))

    def test_unexpected_error_is_reported(self):
        with mock.patch.object(A, "cmd_ls", side_effect=ZeroDivisionError("x")):
            rc, _, err = self.run_cli("ls", ok=None)
        self.assertEqual(rc, 2)
        self.assertIn("--debug", err)

    def test_doctor_runs_everywhere(self):
        for os_tag in A.OSES:
            os.environ["AISWITCH_FORCE_OS"] = os_tag
            _, out, _ = self.run_cli("doctor")
            self.assertIn("bit", out)

    def test_headless_gui_does_not_open_console_browser(self):
        with mock.patch("webbrowser.open", side_effect=AssertionError("must not be called")):
            self.assertFalse(A.open_url("http://127.0.0.1:1/"))


class TestLock(Env):
    def test_second_process_is_refused_with_pid(self):
        self.run_cli("ls")
        script = textwrap.dedent(f"""
            import sys, time; sys.path.insert(0, {str(ROOT)!r})
            import aiswitch
            with aiswitch.lock():
                print("locked", flush=True); time.sleep(5)
        """)
        p = subprocess.Popen([sys.executable, "-c", script], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(p.stdout.readline().strip(), "locked")
            with self.assertRaises(A.Fatal) as cm:
                with A.lock():
                    pass
            self.assertIn(f"pid {p.pid}", str(cm.exception))
        finally:
            p.kill()
            p.wait()
        with A.lock():
            pass


# --------------------------------------------------------------------------- GUI
class TestGui(Env):
    def setUp(self):
        super().setUp()
        A.ensure_root()
        self.srv, url = A.make_gui_server(0)
        self.port = self.srv.server_address[1]
        self.token = self.srv.aiswitch_token
        self.t = threading.Thread(target=self.srv.serve_forever, daemon=True)
        self.t.start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        super().tearDown()

    def req(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = {"Host": f"127.0.0.1:{self.port}", "X-Token": self.token, "Content-Type": "application/json"}
        h.update(headers or {})
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        data = r.read()
        conn.close()
        return r.status, data

    def test_security_checks(self):
        self.assertEqual(self.req("GET", "/", headers={"Host": "evil.example:80"})[0], 403)
        self.assertEqual(self.req("GET", "/api/state", headers={"X-Token": "nope"})[0], 401)
        self.assertEqual(self.req("POST", "/api/action", b"{}", headers={"X-Token": "nope"})[0], 401)
        self.assertEqual(self.req("POST", "/api/action", b"op=use",
                                  headers={"Content-Type": "text/plain"})[0], 415)

    def test_state_and_action(self):
        status, page = self.req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"aiswitch", page)
        self.codex_login("a@x.com", "A1")
        status, data = self.req("POST", "/api/action",
                                json.dumps({"op": "save", "platform": "codex", "name": "alice"}).encode())
        self.assertTrue(json.loads(data)["ok"], data)
        status, data = self.req("GET", "/api/state")
        plats = {p["id"]: p for p in json.loads(data)["platforms"]}
        self.assertEqual(plats["codex"]["current"], "alice")
        status, data = self.req("POST", "/api/action",
                                json.dumps({"op": "use", "platform": "codex", "name": "nobody"}).encode())
        self.assertFalse(json.loads(data)["ok"])


if __name__ == "__main__":
    unittest.main()


# ------------------------------------------------- regressions from the adversarial review
class TestReviewRegressions(Env):
    def save_two_codex(self):
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "alice")
        self.run_cli("new", "codex", "bob")
        self.codex_login("b@x.com", "B1")
        self.run_cli("save", "codex", "bob")

    def test_R1_new_backup_survives_clock_going_back(self):
        self.save_two_codex()
        for i in range(5):
            d = A.backup_root("codex") / f"2999010{i}-000000"     # "future" names (clock moved back)
            d.mkdir(parents=True)
            (d / "meta.json").write_text("{}")
        live = self.codex_login("z@x.com", "Z9").read_bytes()
        self.run_cli("use", "codex", "alice", "--force")
        kept = [d for d in A.backup_dirs("codex") if (d / "auth").exists() and (d / "auth").read_bytes() == live]
        self.assertTrue(kept, "the backup of the unsaved login was pruned")

    def test_R1_missing_backup_is_a_rollback_failure(self):
        with self.assertRaises(A.Fatal) as cm:
            A.apply_or_rollback(A.load_platforms()["codex"], A.stores(), self.tmp / "gone",
                                lambda: (_ for _ in ()).throw(OSError("boom")))
        self.assertIn("ALSO failed", str(cm.exception))

    def test_R2_mode_mismatch_is_refused(self):
        os.environ["GEMINI_FORCE_ENCRYPTED_FILE_STORAGE"] = "true"
        self.write(".gemini/google_accounts.json", '{"active": "alice@g"}')
        self.kc.put("gemini-cli-oauth", "main-account", "kc-alice")
        self.run_cli("save", "gemini", "alice")
        self.kc.put("gemini-cli-oauth", "main-account", "kc-bob")
        self.write(".gemini/google_accounts.json", '{"active": "bob@g"}')
        self.run_cli("save", "gemini", "bob")
        os.environ.pop("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE")
        _, _, err = self.run_cli("use", "gemini", "alice", ok=False)
        self.assertIn("GEMINI_FORCE_ENCRYPTED_FILE_STORAGE", err)
        self.assertEqual(self.kc.get("gemini-cli-oauth", "main-account"), "kc-bob")
        meta = json.loads((A.snap_dir("gemini", "bob") / "meta.json").read_text())
        self.assertTrue(meta["artifacts"]["keychain"]["present"])         # bob's snapshot intact

    def test_R3_no_writeback_when_credentials_are_gone(self):
        self.write(".claude/.credentials.json", "CRED-alice")
        self.write(".claude.json", json.dumps({"oauthAccount": {"emailAddress": "a@x", "organizationUuid": "o"}}))
        self.run_cli("save", "cc", "alice")
        self.run_cli("new", "cc", "bob")
        self.write(".claude/.credentials.json", "CRED-bob")
        self.write(".claude.json", json.dumps({"oauthAccount": {"emailAddress": "b@x", "organizationUuid": "o"}}))
        self.run_cli("save", "cc", "bob")
        self.run_cli("use", "cc", "alice")
        (self.home / ".claude/.credentials.json").unlink()                # creds gone, identity stays
        _, out, _ = self.run_cli("use", "cc", "bob")
        self.assertIn("not syncing back into 'alice'", out)
        self.assertEqual((A.snap_dir("claude-code", "alice") / "credentials").read_bytes(), b"CRED-alice")

    def test_R5_duplicate_identity_prefers_target(self):
        self.codex_login("a@x.com", "A1", "v1-work")
        self.run_cli("save", "codex", "work")
        self.codex_login("a@x.com", "A1", "v1-work2")
        self.run_cli("save", "codex", "work2", "--allow-duplicate")
        refreshed = self.codex_login("a@x.com", "A1", "v2-work2").read_bytes()
        _, out, _ = self.run_cli("use", "codex", "work2")          # work2 is active and live
        self.assertIn("already the active", out)
        self.assertEqual(self.read(".codex/auth.json"), refreshed)
        self.assertIn(b"v1-work", (A.snap_dir("codex", "work") / "auth").read_bytes())
        self.assertNotIn(b"v2", (A.snap_dir("codex", "work") / "auth").read_bytes())
        _, out, _ = self.run_cli("use", "codex", "work")           # live is work2: sync there, then switch
        self.assertIn("synced current login back into 'work2'", out)
        self.assertIn(b"v1-work\"", self.read(".codex/auth.json") + b'"')
        self.assertIn(b"v2-work2", (A.snap_dir("codex", "work2") / "auth").read_bytes())
        st = A.load_state()
        st["active"].pop("codex")                                  # unknown which duplicate is live
        A.save_state(st)
        _, out, _ = self.run_cli("use", "codex", "work2")
        self.assertIn("matches several saved accounts", out)
        self.assertIn(b"v1-work", (A.snap_dir("codex", "work") / "auth").read_bytes())

    def test_PROC2_unknown_during_quit_wait_is_not_quit(self):
        os.environ["AISWITCH_FORCE_OS"] = "linux"
        plat = {"kind": "app", "label": "X", "processes": ["xapp"]}
        seq = iter([[P(500, "/usr/bin/xapp", ["xapp"])]] + [None] * 100)
        A.PROC_PROVIDER = lambda: next(seq)
        A.proc_table(refresh=True)
        self.assertFalse(A.wait_until_quit(plat, timeout=1.2))

    def test_PROC3_bare_image_name_is_ambiguous(self):
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        pt = A.ProcTable([P(4242, "claude.exe", ["claude.exe"])], partial=True, pathless=True)
        self.assertEqual(A.running_state(A.load_platforms()["claude-code"], pt), ([], True))

    def test_PROC4_unquittable_match_names_the_pids(self):
        plat = {"kind": "app", "label": "X", "processes": ["xapp"], "process_match": ["--xapp-helper"]}
        self.procs = [P(77, "/usr/bin/python3", ["python3", "-m", "x", "--xapp-helper"])]
        with self.assertRaises(A.Fatal) as cm:
            A.check_processes(plat, True)
        self.assertIn("77", str(cm.exception))

    def test_PROC1_ps_keeps_real_argv0(self):
        outs = {"comm": " 10   %d sleep\n" % os.getuid() if POSIX else "", "args": " 10 claude 30\n"}
        with mock.patch.object(A, "_run_quiet", lambda cmd, **k: outs["comm" if "comm=" in cmd else "args"]):
            if POSIX:
                procs = A._procs_ps()
                self.assertEqual(procs[0].argv, ["claude", "30"])
                self.assertTrue(A.ProcTable(procs).running("claude"))

    def test_PROC6_windows_quoted_launch_and_bad_quotes(self):
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        argv = A._launch_argv('"C:/Program Files/X/x.exe" --flag')
        os.environ["AISWITCH_FORCE_OS"] = "linux"
        self.assertEqual(argv[1:], ["--flag"])
        self.assertTrue(argv[0].endswith("x.exe") and '"' not in argv[0])
        self.assertFalse(A.launch_app({"label": "X", "launch": {A.host_os(): '"/opt/x y/app'}}))

    def test_PROC8_gui_reports_unknown(self):
        A.PROC_PROVIDER = lambda: None
        A.ensure_root()
        plats = {p["id"]: p for p in A.gui_state()}
        self.assertIsNone(plats["claude-code"]["running"])


@unittest.skipUnless(POSIX, "fake security is a posix script")
class TestMacKeychainReviewFake(FakeSecurity, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.s = A.MacKeychain()

    def db(self, items=None):
        p = Path(os.environ["FAKE_SEC_DB"])
        if items is not None:
            p.write_text(json.dumps([{"svc": s, "acct": a, "pw": v.encode().hex()} for s, a, v in items]))
        return [(i["svc"], i["acct"], bytes.fromhex(i["pw"]).decode()) for i in json.loads(p.read_text())]

    def test_MK1_empty_account_is_not_any_account(self):
        self.db([("S", "alice", "a")])
        self.assertIsNone(self.s.read("S", ""))
        self.assertFalse(self.s.delete("S", ""))
        self.assertEqual(self.db(), [("S", "alice", "a")])
        self.db([])
        self.s.replace("S", "", "new")
        self.assertEqual(self.db(), [("S", "", "new")])

    def test_MK2_exclusive_replace_removes_every_other_account(self):
        self.db([("S", "alice", "old"), ("S", "bob", "b"), ("T", "bob", "keep")])
        self.s.replace("S", "alice", "new")
        self.assertEqual(sorted(self.db()), [("S", "alice", "new"), ("T", "bob", "keep")])


class TestBrowserReview(Env):
    def setUp(self):
        super().setUp()
        (self.tmp / "bin").mkdir(exist_ok=True)
        os.environ["PATH"] = str(self.tmp / "bin")

    def cfg(self, plat):
        self.store().mkdir(exist_ok=True)
        (self.store() / "platforms.json").write_text(json.dumps({"schema": 1, "platforms": {"claude-web": plat}}))

    def local_state(self, rel, profiles):
        self.write(rel + "/Local State", json.dumps(
            {"profile": {"info_cache": {d: {"name": n} for d, n in profiles.items()}}}))

    @unittest.skipUnless(POSIX, "sh scripts")
    def test_BR1_legacy_app_name_maps_to_preset(self):
        self.fake_bin("google-chrome")
        self.cfg({"browser": "Google Chrome", "user_data": "{xdg_config}/google-chrome"})
        b = A.select_browser(A.load_platforms()["claude-web"])
        self.assertEqual((b.preset, bool(b.launcher)), ("chrome", True))

    @unittest.skipUnless(POSIX, "sh scripts")
    def test_BR2_preset_with_user_data(self):
        self.fake_bin("microsoft-edge")
        self.cfg({"browser": "edge", "user_data": "~/edge-data"})
        b = A.select_browser(A.load_platforms()["claude-web"])
        self.assertEqual((b.label, b.data, b.pass_user_data), ("Microsoft Edge", self.home / "edge-data", True))
        self.assertTrue(b.launcher)

    def test_BR3_saved_browser_must_still_match(self):
        self.local_state(".config/google-chrome", {"Profile 1": "Work"})
        self.run_cli("save", "claude-web", "work", "--profile", "Work")
        self.cfg({"browser": "edge"})
        _, _, err = self.run_cli("use", "claude-web", "work", ok=False)
        self.assertIn("saved with Google Chrome", err)

    @unittest.skipUnless(POSIX, "sh scripts")
    def test_BR4_browser_bin_only_keeps_preset_data(self):
        exe = self.fake_bin("my-chrome")
        self.cfg({"browser": "chrome", "browser_bin": str(exe)})
        b = A.select_browser(A.load_platforms()["claude-web"])
        self.assertEqual((b.launcher, b.data), ([str(exe)], self.home / ".config/google-chrome"))
        self.assertTrue(b.pass_user_data)                       # the custom binary gets the listed dir
        self.cfg({"browser_bin": str(exe)})                      # auto + browser_bin: ambiguous data dir
        with self.assertRaises(A.Fatal):
            A.select_browser(A.load_platforms()["claude-web"])

    @unittest.skipUnless(POSIX, "sh scripts")
    def test_BR5_wsl_windows_browser_gets_windows_path(self):
        log = self.tmp / "args"
        exe = self.fake_bin("vivaldi.exe", f'#!/bin/sh\necho "$@" > {log}\n')
        self.fake_bin("wslpath", '#!/bin/sh\necho "C:\\\\Users\\\\me\\\\Vivaldi"\n')
        self.local_state("viv", {"Default": "Me"})
        self.cfg({"browser": "Vivaldi", "user_data": "~/viv", "browser_bin": str(exe)})
        with mock.patch.object(A, "is_wsl", lambda: True):
            b = A.select_browser(A.load_platforms()["claude-web"])
            self.assertIsNone(A.open_browser_profile(b, "Default", "https://x"))
        time.sleep(0.3)
        self.assertIn("--user-data-dir=C:\\Users\\me\\Vivaldi", log.read_text())

    @unittest.skipUnless(POSIX, "sh scripts")
    def test_WSL_cmd_output_in_oem_codepage_does_not_crash(self):
        self.fake_bin("cmd.exe", "#!/bin/sh\nprintf 'C:\\\\Users\\\\Jos\\202\\\\AppData\\\\Local\\r\\n'\n")
        A._WSL_WIN = None
        self.assertEqual(A._wsl_windows_dirs(), {})


class TestVerifyRegressions(Env):
    def test_bsd_bare_names_still_detected(self):
        pt = A.ProcTable([P(9, "claude", ["claude"])])            # BSD ps: short comm, argv0 via PATH
        self.assertEqual(A.running_state(A.load_platforms()["claude-code"], pt), (["claude"], False))

    def test_quit_wait_finishes_in_partial_table(self):
        plat = {"kind": "app", "label": "X", "processes": ["xapp"]}
        seq = iter([[P(5, "/usr/bin/xapp", ["xapp"])]] + [[]] * 100)
        A.PROC_PROVIDER = lambda: next(seq)
        with mock.patch.object(A, "sandbox_kind", lambda: "flatpak"):
            A.proc_table(refresh=True)
            self.assertTrue(A.wait_until_quit(plat, timeout=2))

    def test_browser_bin_with_auto_is_refused(self):
        self.store().mkdir()
        (self.store() / "platforms.json").write_text(json.dumps({"schema": 1, "platforms": {
            "claude-web": {"browser_bin": "/opt/x/chrome"}}}))
        _, _, err = self.run_cli("profiles", "claude-web", ok=False)
        self.assertIn("browser_bin", err)

    def test_legacy_custom_meta_still_opens(self):
        self.write(".config/google-chrome/Local State", json.dumps({"profile": {"info_cache": {"P": {"name": "P"}}}}))
        b = A.select_browser(A.load_platforms()["claude-web"],
                             prefer={"browser": "custom", "user_data": str(self.home / ".config/google-chrome")})
        self.assertEqual(b.preset, "chrome")


@unittest.skipUnless(POSIX, "fake security is a posix script")
class TestMacKeychainNoDump(FakeSecurity, unittest.TestCase):
    def test_stale_items_without_dump_are_warned(self):
        p = Path(os.environ["FAKE_SEC_DB"])
        p.write_text(json.dumps([{"svc": "S", "acct": "alice", "pw": "6f"}, {"svc": "S", "acct": "bob", "pw": "62"}]))
        s = A.MacKeychain()
        A._WARNED.clear()
        err = io.StringIO()
        with mock.patch.object(A.MacKeychain, "accounts", lambda self, svc: None), contextlib.redirect_stderr(err):
            s.replace("S", "alice", "new")
        self.assertIn("may remain", err.getvalue())
