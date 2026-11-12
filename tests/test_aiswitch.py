"""Hermetic tests for aiswitch. Stdlib only: `python -m unittest discover -s tests -v`.

Every test runs against throw-away HOME / USERPROFILE / APPDATA dirs, an in-memory secret
store and a fake process table. Real keystores are only touched when
AISWITCH_TEST_REAL_STORE=1 (with a throw-away service prefix)."""
from __future__ import annotations

import contextlib
import http.client
import io
import json
import os
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


def jwt(claims):
    import base64
    b = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"h.{b}.s"


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
        }
        self._env = mock.patch.dict(os.environ, env)
        self._env.start()
        for v in ("AISWITCH_HOME", "AISWITCH_KEYCHAIN_DIR", "CLAUDE_CONFIG_DIR", "CODEX_HOME"):
            os.environ.pop(v, None)
        self.kc = A.MemoryStore()
        self.procs = []
        A.STORE_FACTORY = lambda: A.Stores(self.kc, self.kc)
        A.PROC_PROVIDER = lambda: self.procs
        A._PROC_CACHE = None
        A._WARNED.clear()
        if sys.platform == "win32":
            self._home = mock.patch.object(A, "home", lambda: self.home)
            self._home.start()

    def tearDown(self):
        A.STORE_FACTORY = None
        A.PROC_PROVIDER = None
        A._PROC_CACHE = None
        if sys.platform == "win32":
            self._home.stop()
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


# --------------------------------------------------------------------------- paths
class TestPathResolver(unittest.TestCase):
    def r(self, tpl, os_tag="linux", env=None, home="/h/u"):
        return A.resolve_path(tpl, os_tag, env or {}, home)

    def test_tilde_and_home(self):
        self.assertEqual(self.r("~/.codex/auth.json"), "/h/u/.codex/auth.json")
        self.assertEqual(self.r("{home}/x"), "/h/u/x")

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

    def test_xdg(self):
        self.assertEqual(self.r("{xdg_config}/google-chrome"), "/h/u/.config/google-chrome")
        self.assertEqual(self.r("{xdg_config}/c", env={"XDG_CONFIG_HOME": "/x"}), "/x/c")

    def test_env_override(self):
        tpl = "{env:CODEX_HOME|~/.codex}/auth.json"
        self.assertEqual(self.r(tpl), "/h/u/.codex/auth.json")
        self.assertEqual(self.r(tpl, env={"CODEX_HOME": "/srv/codex"}), "/srv/codex/auth.json")
        self.assertEqual(self.r(A.CLAUDE_JSON), "/h/u/.claude.json")
        self.assertEqual(self.r(A.CLAUDE_JSON, env={"CLAUDE_CONFIG_DIR": "/c"}), "/c/.claude.json")

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
                    if a.get("path"):
                        self.r(a["path"], os_tag)


# ----------------------------------------------------------------- secret stores
class StoreContract:
    def make(self):
        raise NotImplementedError

    def setUp(self):
        self.s = self.make()
        self.svc = f"aiswitch-test-{uuid.uuid4().hex[:10]}"

    def tearDown(self):
        with contextlib.suppress(Exception):
            self.s.delete_all(self.svc)

    def test_absent(self):
        self.assertIsNone(self.s.read(self.svc))
        self.assertIsNone(self.s.account(self.svc))
        self.assertFalse(self.s.delete(self.svc))

    def test_roundtrip_and_update(self):
        secret = '{"claudeAiOauth": {"accessToken": "a b\\"c", "ü": 1}}' + "x" * 3000
        self.s.write(self.svc, "acct1", secret)
        self.assertEqual(self.s.read(self.svc), {"account": "acct1", "secret": secret})
        self.s.write(self.svc, "acct1", "v2")
        self.assertEqual(self.s.read(self.svc)["secret"], "v2")
        self.assertTrue(self.s.delete(self.svc))
        self.assertIsNone(self.s.read(self.svc))

    def test_replace_other_account(self):
        self.s.write(self.svc, "old", "s1")
        self.s.replace(self.svc, "new", "s2")
        self.assertEqual(self.s.read(self.svc), {"account": "new", "secret": "s2"})
        self.s.delete_all(self.svc)
        self.assertIsNone(self.s.read(self.svc))


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
        return A.FileStore(self.d)


@unittest.skipUnless(REAL_STORE and sys.platform == "darwin", "set AISWITCH_TEST_REAL_STORE=1 on macOS")
class TestMacKeychain(StoreContract, unittest.TestCase):
    def make(self):
        return A.MacKeychain()

    def test_secret_not_on_argv(self):
        self.s.write(self.svc, "acct1", "topsecret")
        self.assertFalse(self.s.used_argv_fallback, "security -i stdin route did not verify")

    def test_credential_sized_secret_not_on_argv(self):
        self.s.write(self.svc, "acct1", json.dumps({"claudeAiOauth": {"accessToken": "x" * 1500}}))
        self.assertFalse(self.s.used_argv_fallback, "security -i stdin route failed for ~1.5KB secret")


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

    def test_duplicate_identity_rejected(self):
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "alice")
        self.run_cli("save", "codex", "alice", "--force")      # refreshing itself is fine
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

    def test_names(self):
        self.codex_login("a@x.com", "A1")
        for bad in ("con", "NUL.txt", "com1", "a.", "-x", "a/b", "x" * 41):
            with self.assertRaises(A.Fatal):
                A.check_name(bad)
        self.run_cli("save", "codex", "con", ok=False)
        self.run_cli("save", "codex", "Alice")
        _, _, err = self.run_cli("save", "codex", "alice", "--allow-duplicate", ok=False)
        self.assertIn("only by case", err)


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

    def _failing_restore(self, fail_on):
        real = A.restore

        def restore(spec, src, ent, st):
            if spec["name"] == fail_on and "snapshots" in str(src):
                raise OSError("disk full (injected)")
            return real(spec, src, ent, st)
        return mock.patch.object(A, "restore", restore)

    def test_failed_switch_restores_previous(self):
        with self._failing_restore("accounts"):
            _, _, err = self.run_cli("use", "gemini", "alice", ok=False)
        self.assertIn("injected", err)
        self.assertIn("previous login restored", err)
        self.assertEqual(self.read(".gemini/oauth_creds.json"), b'{"t": "bob"}')

    def test_failed_switch_without_backup_goes_all_absent(self):
        self.run_cli("new", "gemini", "carol")       # live is now logged out, nothing to back up
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
        self.kc.items[self.SVC] = {"account": "me", "secret": json.dumps({"tok": who})}
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
        self.assertEqual(json.loads(self.kc.items[self.SVC]["secret"]), {"tok": "alice"})
        cfg = json.loads(self.read(".claude.json"))
        self.assertEqual(cfg["theme"], "light")
        self.assertEqual(cfg["oauthAccount"]["emailAddress"], "alice@x")
        self.assertEqual(cfg["名前"], "ü")
        self.assertIn("名前", self.read(".claude.json").decode("utf-8"))

    def test_locked_keychain_is_a_hard_error_not_absence(self):
        self.kc.fail.add("read")
        _, _, err = self.run_cli("use", "cc", "alice", ok=False)
        self.assertIn("simulated keychain failure", err)
        self.kc.fail.clear()
        self.assertEqual(json.loads(self.kc.items[self.SVC]["secret"]), {"tok": "bob"})
        self.assertEqual(A.backup_dirs("claude-code"), A.backup_dirs("claude-code"))

    def test_keychain_failure_on_save_leaves_no_partial_snapshot(self):
        before = set(self.kc.items)
        self.kc.fail.add("write")
        self.run_cli("save", "cc", "bob", "--force", ok=False)
        self.kc.fail.clear()
        self.assertEqual(set(self.kc.items), before)
        meta = json.loads((A.snap_dir("claude-code", "bob") / "meta.json").read_text())
        self.assertIn(A.VAULT_PREFIX + meta["artifacts"]["keychain"]["ref"], self.kc.items)
        self.assertFalse([p for p in A.snap_dir("claude-code", "x").parent.iterdir()
                          if p.name.startswith(".")])

    def test_resave_rotates_refs_without_orphans(self):
        def refs():
            out = set()
            for d in list(A.root().glob("snapshots/*/*")) + list(A.root().glob("backups/*/*")):
                out |= A.snapshot_refs(d)
            return out
        self.run_cli("save", "cc", "bob", "--force")
        self.run_cli("use", "cc", "alice")
        self.run_cli("rm", "cc", "bob", "-y")
        self.assertEqual(refs(), self.vault_keys())

    def test_interrupted_tmp_dir_is_cleaned(self):
        tmp = A.hidden_sibling(A.snap_dir("claude-code", "zed"), "tmp")
        tmp.mkdir()
        self.kc.items[A.VAULT_PREFIX + "deadbeef"] = {"account": "a", "secret": "s"}
        (tmp / "pending-refs.json").write_text(json.dumps([A.VAULT_PREFIX + "deadbeef"]))
        self.run_cli("save", "cc", "zed", "--allow-duplicate")
        self.assertFalse(tmp.exists())
        self.assertNotIn(A.VAULT_PREFIX + "deadbeef", self.kc.items)

    def test_legacy_schema1_snapshot_restores_and_deletes(self):
        d = A.snap_dir("claude-code", "old")
        d.mkdir(parents=True)
        legacy_key = A.VAULT_PREFIX + str(Path("snapshots/claude-code/old")) + ":keychain"
        self.kc.items[legacy_key] = {"account": "me", "secret": '{"tok": "old"}'}
        (d / "account.json").write_text(json.dumps({"oauthAccount": {"emailAddress": "old@x",
                                                                       "organizationUuid": "o"}}))
        (d / "meta.json").write_text(json.dumps({"saved_at": "x", "identity": "old@x|o", "artifacts": {
            "keychain": {"type": "keychain", "present": True},
            "account": {"type": "json_keys", "present": True}}}))
        self.run_cli("use", "cc", "old")
        self.assertEqual(self.kc.items[self.SVC]["secret"], '{"tok": "old"}')
        self.run_cli("use", "cc", "alice")       # write-back re-saves "old" with a schema-2 ref
        self.assertNotIn(legacy_key, self.kc.items)
        self.run_cli("rm", "cc", "old", "-y")
        self.assertEqual(len([k for k in self.vault_keys()]),
                         sum(len(A.snapshot_refs(p)) for p in
                             list(A.root().glob("snapshots/*/*")) + list(A.root().glob("backups/*/*"))))


class TestDesktopApp(Env):
    os_tag = "darwin"

    def setUp(self):
        super().setUp()
        self.base = "Library/Application Support/Claude/"
        self.write(self.base + "Cookies", "alice-cookie")
        self.write(self.base + "Local Storage/leveldb/1.ldb", "alice-ls")
        self.write(self.base + "config.json", '{"oauth:tokenCache": "alice", "keep": 1}')
        self.run_cli("save", "cd", "alice")

    def test_refuses_while_running_and_on_save(self):
        self.procs = [(4242, "Claude", ["/Applications/Claude.app/Contents/MacOS/Claude"])]
        _, _, err = self.run_cli("save", "cd", "alice2", ok=False)
        self.assertIn("is running", err)
        _, _, err = self.run_cli("new", "cd", "bob", ok=False)
        self.assertIn("is running", err)

    def test_no_writeback_without_flag(self):
        self.run_cli("new", "cd", "bob")
        self.assertFalse((self.home / self.base / "Cookies").exists())
        self.assertEqual(json.loads(self.read(self.base + "config.json")), {"keep": 1})
        self.write(self.base + "Cookies", "bob-cookie")
        self.run_cli("save", "cd", "bob")
        # user signs into a *different* account inside the app; aiswitch can't tell
        self.write(self.base + "Cookies", "mallory-cookie")
        _, out, _ = self.run_cli("use", "cd", "alice")
        self.assertIn("not syncing", out)
        self.assertEqual((A.snap_dir("claude-desktop", "bob") / "cookies").read_bytes(), b"bob-cookie")
        self.assertEqual(self.read(self.base + "Cookies"), b"alice-cookie")
        self.assertEqual(self.read(self.base + "Local Storage/leveldb/1.ldb"), b"alice-ls")
        self.write(self.base + "Cookies", "alice-refreshed")
        self.run_cli("use", "cd", "bob", "--writeback")
        self.assertEqual((A.snap_dir("claude-desktop", "alice") / "cookies").read_bytes(), b"alice-refreshed")


# -------------------------------------------------------------------- processes
class TestProcesses(Env):
    def test_matching(self):
        pt = A.ProcTable([
            (1, "node", ["node", "--no-warnings", "/usr/local/bin/gemini"]),
            (2, "codex-x86_64-unknown-linux-musl", ["/x/node_modules/@openai/codex/bin/codex-x86_64"]),
            (3, "python3", ["python3", "/x/aiswitch.py", "use", "codex", "a"]),
            (4, "claude", ["claude"]),
        ])
        self.assertTrue(pt.running("gemini"))
        self.assertTrue(pt.running("codex", ["@openai/codex"]))
        self.assertFalse(pt.running("codex"))
        self.assertTrue(pt.running("claude"))
        self.assertFalse(pt.running("aider"))
        self.assertIsNone(A.ProcTable(None).running("claude"))

    def test_windows_names_case_insensitive(self):
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        pt = A.ProcTable([(1, "Claude.exe", ["C:\\Program Files\\Claude\\Claude.exe"])])
        self.assertTrue(pt.running("claude"))

    def test_unknown_warns(self):
        A.PROC_PROVIDER = lambda: None
        self.codex_login("a@x.com", "A1")
        self.run_cli("save", "codex", "alice")
        self.run_cli("new", "codex", "bob")
        _, _, err = self.run_cli("save", "codex", "bob")
        self.assertNotIn("Traceback", err)

    @unittest.skipUnless(sys.platform.startswith("linux") or sys.platform == "darwin", "posix")
    def test_real_table_sees_a_child(self):
        A.PROC_PROVIDER = None
        p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)", "aiswitch-probe-xyz"])
        try:
            time.sleep(0.3)
            pt = A.proc_table(refresh=True)
            self.assertIsNotNone(pt.procs)
            self.assertTrue(pt.running("nope", ["aiswitch-probe-xyz"]))
        finally:
            p.kill()
            p.wait()


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
            self.assertIn("refusing to manage", err, path)

    def test_bad_artifact_names(self):
        self.cfg({"schema": 1, "platforms": {"evil": {"kind": "login", "artifacts": [
            {"name": "../x", "type": "file", "path": "~/a"}]}}})
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


# ------------------------------------------------------------------ fs / encoding
class TestFiles(Env):
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
        self.codex_login("a@x.com", "A1")      # writes through the link
        self.run_cli("save", "codex", "a")
        self.run_cli("new", "codex", "b")
        self.assertTrue((self.home / ".codex/auth.json").is_symlink())
        self.run_cli("use", "codex", "a")
        self.assertTrue((self.home / ".codex/auth.json").is_symlink())
        self.assertIn(b"A1", real.read_bytes())

    def test_glyph_fallback(self):
        class Cp1252(io.StringIO):
            encoding = "cp1252"
        with contextlib.redirect_stdout(Cp1252()):
            self.assertEqual(A.glyph("on"), "*")
        with contextlib.redirect_stdout(io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
            self.assertEqual(A.glyph("on"), "●")

    def test_host_os(self):
        os.environ.pop("AISWITCH_FORCE_OS")
        with mock.patch.object(sys, "platform", "win32"):
            self.assertEqual(A.host_os(), "windows")
        with mock.patch.object(sys, "platform", "cygwin"):
            self.assertEqual(A.host_os(), "windows")
        with mock.patch.object(sys, "platform", "linux"):
            self.assertEqual(A.host_os(), "linux")

    def test_windows_registry(self):
        os.environ["AISWITCH_FORCE_OS"] = "windows"
        plats = A.load_platforms()
        self.assertNotIn("claude-desktop", plats)
        arts = {a["name"]: a for a in A.artifacts(plats["claude-code"])}
        self.assertEqual(set(arts), {"credentials", "account"})
        self.assertEqual(A.expand(arts["credentials"]["path"]),
                         Path(str(self.home).replace("\\", "/") + "/.claude/.credentials.json"))
        self.assertTrue(str(A.expand(plats["claude-web"]["user_data"])).endswith("Google/Chrome/User Data"))

    def test_unexpected_error_is_reported(self):
        with mock.patch.object(A, "cmd_ls", side_effect=ZeroDivisionError("x")):
            rc, _, err = self.run_cli("ls", ok=None)
        self.assertEqual(rc, 2)
        self.assertIn("--debug", err)


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
