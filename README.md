# aiswitch

Account switcher for AI coding tools, in the spirit of TcNo Account Switcher. It saves each
account's login state and swaps a saved copy back in, so you can move between your own
accounts without logging in again. It never asks for or stores your password. It only copies
the credential files and Keychain items the tools already create themselves.

Single file, Python 3.9+, no dependencies.

> **Never try aiswitch on an account you couldn't log back into.** It manipulates live
> credentials. Test it with an account where `/login` again would be a minor inconvenience.

## Support matrix

| Tool | macOS | Linux | Windows |
|---|---|---|---|
| Claude Code | supported | supported | **beta** |
| Codex CLI (file credential store) | supported | supported | **beta** |
| Gemini CLI | beta | beta | beta |
| Claude Desktop | experimental | - | - |
| Web logins (Chrome profile launcher) | supported | beta | beta |
| ChatGPT desktop app | - | - | - |

"Beta" means the storage location is documented or strongly suggested but has not been
verified on real machines for this release. Please report what you see (`aiswitch doctor`).

## Install

    pipx install aiswitch            # or: uv tool install aiswitch
    aiswitch doctor

Without pipx/uv: download `aiswitch.pyz` from the
[latest release](https://github.com/bakisama/aiswitch/releases) (check it against
`SHA256SUMS`) and run `python3 aiswitch.pyz doctor`. On Windows, use `py aiswitch.pyz doctor`.

From a checkout: `python3 aiswitch.py doctor`.

## Use

    # 1. log in to account A the normal way (e.g. `claude` -> /login), then:
    aiswitch save claude-code personal
    # 2. add a second account
    aiswitch new claude-code work       # logs out locally (personal stays saved)
    claude                              # /login as account B
    aiswitch save claude-code work
    # 3. flip any time
    aiswitch use claude-code personal
    aiswitch ls ; aiswitch current ; aiswitch doctor

Platforms: `claude-code` (cc), `codex` (cx), `gemini` (gem), `claude-desktop` (cd, macOS,
experimental), and web logins `claude-web`, `chatgpt-web`, `gemini-web`.

Restart running CLI sessions after switching. They keep the old token in memory and may
write it back.

## GUI

    aiswitch gui             # opens a local page in your browser; Ctrl-C to stop
    aiswitch gui --no-browser  # headless Linux / WSL: just print the URL

The GUI shows account cards per tool with Switch, Save current login, Add new account and
Delete. It asks before replacing an unsaved login or quitting a running app. It listens on
127.0.0.1 only, on a random port with a one-time token in the URL, and rejects foreign Host
headers (DNS rebinding) and non-JSON requests.

## Where the data is

What gets swapped (paths shown for the default config):

| Tool | macOS | Linux | Windows |
|---|---|---|---|
| Claude Code | Keychain item `Claude Code-credentials` + `oauthAccount` key of `~/.claude.json` | `~/.claude/.credentials.json` + `oauthAccount` of `~/.claude.json` | `%USERPROFILE%\.claude\.credentials.json` + `oauthAccount` of `%USERPROFILE%\.claude.json` |
| Codex CLI | `~/.codex/auth.json` | same | `%USERPROFILE%\.codex\auth.json` |
| Gemini CLI | `~/.gemini/oauth_creds.json`, `google_accounts.json` | same | `%USERPROFILE%\.gemini\...` |
| Claude Desktop | cookies / Local Storage / IndexedDB / `oauth:tokenCache` in `~/Library/Application Support/Claude` | - | - |
| Web | nothing is swapped: each account is a Chrome profile, `use` opens the site in it | | |

Only the listed keys of `~/.claude.json` are touched. Your other settings stay as they are.

Environment overrides are honoured: `CLAUDE_CONFIG_DIR` (Claude Code's files then live there)
and `CODEX_HOME`. On macOS with `CLAUDE_CONFIG_DIR` set, Claude Code may use a differently
named Keychain item. That case is **not verified**, and `aiswitch doctor` warns about it.

aiswitch's own store is `~/.aiswitch` (override with `AISWITCH_HOME`):

- `snapshots/<platform>/<name>/` holds the saved accounts. Keychain-backed secrets are kept as
  separate Keychain items named `aiswitch:<uuid>`. Everything else is a plain copy of the
  original file.
- `backups/<platform>/` holds the last 5 live states that were replaced.
- `state.json` records the last-used account per platform. `platforms.json` is your optional
  config overrides.

To delete everything aiswitch saved (snapshots, backups and their Keychain items), run
`aiswitch purge`. Your current live logins are not touched.

## Safety model

- **Keychain errors are errors.** A locked keychain, a denied prompt or an SSH session without
  keychain access stops the command. aiswitch never reads that as "not logged in", so it
  cannot skip a backup and overwrite your only copy.
- **Refreshed tokens are written back** into the matching saved account before switching away.
  The match is by email/org id, so the wrong account is never overwritten. Tools without an
  identity check (Claude Desktop) are not written back unless you pass `--writeback`, because
  you may have signed into a different account inside the app.
- **Unsaved logins are protected.** aiswitch refuses to replace a login that isn't saved under
  any name (override with `--force`). The replaced state always goes to `backups/`.
- **A failed switch rolls back** to the previous login, or to a clean logged-out state if
  there was none. Snapshot writes are staged and swapped in by rename, so an interrupted save
  never leaves a half-written account.
- **Running apps:** aiswitch refuses to save or switch Claude Desktop while it runs (`--quit`
  closes it). For CLIs it warns. If process detection isn't available, it says so instead of
  assuming nothing runs.
- **Secrets stay off the command line:** Keychain writes go to `security` over stdin, not
  argv. If that path can't be verified on your macOS version, aiswitch warns and falls back
  to argv, where the secret is briefly visible to `ps`.
- **No network.** aiswitch makes no outbound network requests and has no telemetry. The GUI
  is a local server on 127.0.0.1.

### Threat model

aiswitch protects against casual disclosure, and against losing a login through its own
mistakes. It does **not** protect against malware running as your user, which can read the
same files and Keychain items the tools themselves use.

**Plaintext at rest:** Codex, Gemini, Claude Code on Linux/Windows, and Claude Desktop
snapshots are plain copies of credential files, the same as the originals. On macOS/Linux the
store is mode 0700. On Windows, mode bits don't apply: the files are protected only by your
user profile's ACLs. Treat `~/.aiswitch` like a password file, and don't sync or back it up
to shared places.

## Terms of service

This is not legal advice. Re-read each provider's current terms yourself:
[Anthropic](https://www.anthropic.com/legal/consumer-terms) ·
[OpenAI](https://openai.com/policies/terms-of-use) ·
[Google Gemini CLI](https://github.com/google-gemini/gemini-cli/blob/main/docs/tos-privacy.md).

- **Use only your own accounts.** Never share, upload or give a snapshot to anyone. A snapshot
  is a logged-in session, so treat it like a password.
- **Don't use switching to evade rate limits, usage limits or plan caps.** All three providers
  prohibit circumventing their limits.
- aiswitch only swaps files and Keychain items. The official clients make every request, and
  aiswitch never calls any provider API or refreshes tokens itself.
- Anthropic's consumer terms forbid sharing login information. Google's Gemini CLI terms object
  to third-party software using the CLI's OAuth login, and there are unofficial reports of
  suspensions. Providers can change their terms and suspend accounts at any time. You use
  aiswitch at your own risk, and the author takes no responsibility.

## Config

`aiswitch init` writes `~/.aiswitch/platforms.json`. Entries under `"platforms"` are merged
field by field over the built-in definitions, so path fixes in newer aiswitch versions still
reach you:

    {
      "schema": 1,
      "platforms": {
        "gemini":     { "disabled": true },
        "codex":      { "processes": ["codex", "codex-dev"] },
        "codex-work": { "extends": "codex", "label": "Codex (work)", "aliases": [] }
      }
    }

Path tokens are `~`, `{home}`, `{appdata}`, `{localappdata}`, `{xdg_config}` and
`{env:VAR|default}`. A path can also be per-OS: `{"darwin": "...", "linux": "...",
"windows": "..."}`. To see the built-ins, run `aiswitch init --show-defaults`. Paths that
point at your home directory, a drive root or the aiswitch store are refused.

Older `platforms.json` files without `"schema"` still work, but they replace built-in entries
wholesale. aiswitch warns about this. Re-run `aiswitch init --force` to migrate (the old file
is kept as a `.bak`).

## Known limitations

- Windows: Claude Code and Codex support is beta. Claude Desktop isn't supported yet, because
  Store/MSIX installs redirect its data folder. Windows Credential Manager / Linux Secret
  Service backends are not implemented yet, so tools configured to keep credentials in those
  (for example Codex `cli_auth_credentials_store = "keyring"`) aren't switched correctly.
- Gemini CLI versions that keep credentials in the system keychain or an encrypted file are not
  handled yet.
- Claude Desktop snapshots contain data encrypted with a machine-bound key. They restore on the
  same machine, but not on another machine or after reinstalling the OS.
- Environment variables such as `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` override any
  stored login. If one is set, switching has no visible effect.

## Development

    python -m unittest discover -s tests -v      # hermetic; no real credentials touched
    AISWITCH_TEST_REAL_STORE=1 python -m unittest tests.test_aiswitch.TestMacKeychain   # macOS only

The tests use temporary HOME dirs, an in-memory secret store and a fake process table. CI
runs them on Linux, macOS (arm64 and Intel) and Windows with Python 3.9, 3.11 and 3.13.
