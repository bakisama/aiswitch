# aiswitch

**Website:** [bakisama.github.io/aiswitch](https://bakisama.github.io/aiswitch/)

Account switcher for AI coding tools, in the spirit of TcNo Account Switcher. It saves each
account's login state and swaps a saved copy back in, so you can move between your own
accounts without logging in again. It never asks for or stores your password. It only copies
the credential files and OS keychain items the tools already create themselves.

One file of pure Python 3.9+ using only the standard library: no compiled code and no
dependencies, so it runs on any CPU (x86-64, ARM64, 32-bit and others). It supports
**macOS, Linux, the BSDs, WSL and Windows**.

> **Never try aiswitch on an account you couldn't log back into.** It manipulates live
> credentials. Test it with an account where `/login` again would be a minor inconvenience.

## Support matrix

| Tool | macOS | Linux / BSD | Windows |
|---|---|---|---|
| Claude Code | supported | supported | **beta** |
| Codex CLI | supported (file and keyring mode) | supported (file mode) | **beta** (file mode) |
| Gemini CLI | beta | beta | beta |
| Claude Desktop | experimental | experimental | experimental |
| Web logins (browser-profile launcher: Chrome, Edge, Chromium, Brave) | supported | beta | beta |
| ChatGPT desktop app | - | - | - |

"Beta" and "experimental" mean the storage location comes from the tools' docs or source
code, but this release hasn't been verified on real machines for that combination. Please
report what you see (`aiswitch doctor`).

CI runs the full test suite on Linux x86-64 and ARM64, macOS ARM64 and Intel, Windows x64
and ARM64, 32-bit Windows Python, Alpine (musl) and FreeBSD, with Python 3.9, 3.11 and 3.13.
It also runs contract tests against the real macOS Keychain, Windows Credential Manager and
the Linux Secret Service.

## Install

    pipx install aiswitch            # or: uv tool install aiswitch
    aiswitch doctor

Without pipx/uv: download `aiswitch.pyz` from the
[latest release](https://github.com/bakisama/aiswitch/releases) (check it against
`SHA256SUMS`) and run `python3 aiswitch.pyz doctor`. On Windows, use `py aiswitch.pyz doctor`.

From a checkout: `python3 aiswitch.py doctor`.

On Windows, use Python from python.org or `winget install Python.Python.3.13`. Some notes
on other Pythons and setups:

- **Microsoft Store Python** redirects writes under `%APPDATA%`, so aiswitch refuses to
  manage files there with it.
- **Cygwin/MSYS Python** is not supported.
- **WSL:** run aiswitch inside WSL for the tools you use inside WSL.

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

Platforms: `claude-code` (cc), `codex` (cx), `gemini` (gem), `claude-desktop` (cd,
experimental), and web logins `claude-web`, `chatgpt-web`, `gemini-web`.

Restart running CLI sessions after switching. They keep the old token in memory and may
write it back.

## GUI

    aiswitch gui               # opens a local page in your browser; Ctrl-C to stop
    aiswitch gui --no-browser  # just print the URL

The GUI shows account cards per tool with Switch, Save current login, Add new account and
Delete. It asks before replacing an unsaved login or quitting a running app.

It listens on 127.0.0.1 only, on a random port with a one-time token in the URL. It binds
the port exclusively on Windows, and rejects foreign Host headers (DNS rebinding) and
non-JSON requests. On a machine without a graphical session it prints the URL instead of
starting a text browser. Under WSL it opens the Windows browser.

## Where the data is

What gets swapped (default config):

| Tool | macOS | Linux / BSD | Windows |
|---|---|---|---|
| Claude Code | Keychain item `Claude Code-credentials`, plus `~/.claude/.credentials.json` if Claude Code fell back to it | `~/.claude/.credentials.json` | `%USERPROFILE%\.claude\.credentials.json` |
| ...and on every OS | the `oauthAccount` key of `~/.claude.json` (your other settings are left alone) | | |
| Codex CLI | `~/.codex/auth.json`, or Keychain item `Codex Auth` (account `cli\|<hash of CODEX_HOME>`) in keyring/auto mode | `~/.codex/auth.json` | `%USERPROFILE%\.codex\auth.json` |
| Gemini CLI | `~/.gemini/oauth_creds.json` + `google_accounts.json` | same | `%USERPROFILE%\.gemini\...` |
| Gemini CLI with `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true` | adds the keychain item `gemini-cli-oauth` / `main-account` and `~/.gemini/gemini-credentials.json` | adds the Secret Service item and the encrypted file | adds the Credential Manager item and the encrypted file |
| Claude Desktop | cookies / Local Storage / IndexedDB / `oauth:tokenCache` in `~/Library/Application Support/Claude` | same, in `~/.config/Claude` | same, in `%APPDATA%\Claude` or the Store (MSIX) app's `...\Packages\Claude_*\LocalCache\Roaming\Claude` |
| Web | nothing is swapped: each account is a browser profile, and `use` opens the site in it | | |

### Overrides

Environment overrides are honoured:

- `CLAUDE_CONFIG_DIR`: Claude Code's files then live there. On macOS the Keychain item gets
  the matching `-<hash>` suffix.
- `CODEX_HOME`
- `GEMINI_CLI_HOME`
- `CHROME_CONFIG_HOME` and `XDG_CONFIG_HOME`

### Codex keyring mode

aiswitch reads `cli_auth_credentials_store` from Codex's `config.toml`:

- **`file`** (the default) works everywhere.
- **`keyring` and `auto`** work on macOS. On Linux and Windows aiswitch refuses them with an
  explanation: Codex caches the login in the kernel keyring on Linux, and on Windows it uses
  an encrypted store. Neither can be swapped safely.
- **`ephemeral`** keeps nothing on disk, so there is nothing to switch.

### Browsers

Web platforms use the first installed Chromium-family browser that has profiles: Chrome,
then Edge, Chromium, then Brave. This includes snap and flatpak installs, the FreeBSD/OpenBSD
Chromium port, and the Windows browser under WSL. Profiles are always listed from, and opened
in, the same browser. Pick one explicitly with `"browser": "edge"` (see Config).

### aiswitch's own store

The store is `~/.aiswitch` (override with `AISWITCH_HOME`):

- **`snapshots/<platform>/<name>/`** holds the saved accounts. aiswitch's copies of keychain
  items are kept per OS:
  - macOS: Keychain items named `aiswitch:<uuid>`.
  - Linux/BSD: Secret Service items with `application=aiswitch`.
  - Windows: DPAPI-encrypted files in `vault/`. These only decrypt for your Windows user on
    this machine.

  Everything else is a plain copy of the original file.
- **`backups/<platform>/`** holds the last 5 live states that were replaced.
- **`state.json`** records the last-used account per platform. `platforms.json` holds your
  optional config overrides.

To delete everything aiswitch saved (snapshots, backups and their keychain copies), run
`aiswitch purge`. Your current live logins are not touched.

## Safety model

- **Keychain errors are errors.** A locked keychain, a denied prompt, an SSH session without
  keychain access or a missing D-Bus session stops the command. aiswitch never reads that
  as "not logged in", so it cannot skip a backup and overwrite your only copy.
- **Refreshed tokens are written back** into the matching saved account before switching away.
  The match is by email/org id, so the wrong account is never overwritten. Tools without an
  identity check (Claude Desktop) are not written back unless you pass `--writeback`, because
  you may have signed into a different account inside the app.
- **Unsaved logins are protected.** aiswitch refuses to replace a login that isn't saved under
  any name (override with `--force`). The replaced state always goes to `backups/`.
- **A failed or interrupted switch rolls back.** This covers Ctrl-C, SIGTERM and a closed
  terminal (SIGHUP). aiswitch restores the previous login, or a clean logged-out state if
  there was none.
- **Crashes are repaired on the next run.** Snapshot writes are staged and swapped in by
  rename. Work left half-done by a crash or power loss is finished or undone the next time
  aiswitch runs.
- **Running apps:** aiswitch refuses to save or switch Claude Desktop while it runs (`--quit`
  closes it). For CLIs it warns. Detection is scoped to your user and matches the executable
  (also npm/node-hosted CLIs and native binaries named after their CPU, like
  `codex-aarch64-…`). If it can't see every process, for example inside a flatpak or
  container sandbox, it says "unknown" instead of assuming nothing runs.
- **Secrets stay off the command line:**
  - macOS: Keychain writes go to `/usr/bin/security` over stdin. A secret too long for that
    channel (over about 2 KB) falls back to argv with a warning. Set
    `AISWITCH_NO_ARGV_SECRETS=1` to refuse instead.
  - Linux: secrets go to `secret-tool` over stdin.
  - Windows: secrets go through the Credential Manager API, never another process.
- **No sudo.** aiswitch refuses to run as root against a user's home, because that would
  make the credential files root-owned.
- **No network.** aiswitch makes no outbound network requests and has no telemetry. The GUI
  is a local server on 127.0.0.1.

### Threat model

aiswitch protects against casual disclosure, and against losing a login through its own
mistakes. It does **not** protect against malware running as your user, which can read the
same files and keychain items the tools themselves use.

**Plaintext at rest:** file-based logins are plain copies of credential files, the same as
the originals. This covers Codex, Gemini, Claude Code on Linux/Windows and Claude Desktop.

- On macOS/Linux the store is mode 0700. aiswitch warns if the store is on a filesystem
  without Unix permissions, such as `/mnt/c` under WSL, FAT or SMB.
- On Windows, mode bits don't apply: the files are protected only by your user profile's
  ACLs.

Treat `~/.aiswitch` like a password file, and don't sync or back it up to shared places.

## Terms of service

This is not legal advice. Re-read each provider's current terms yourself:
[Anthropic](https://www.anthropic.com/legal/consumer-terms) ·
[OpenAI](https://openai.com/policies/terms-of-use) ·
[Google Gemini CLI](https://github.com/google-gemini/gemini-cli/blob/main/docs/tos-privacy.md).

- **Use only your own accounts.** Never share, upload or give a snapshot to anyone. A snapshot
  is a logged-in session, so treat it like a password.
- **Don't use switching to evade rate limits, usage limits or plan caps.** All three providers
  prohibit circumventing their limits.
- aiswitch only swaps files and keychain items. The official clients make every request, and
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
        "codex-work": { "extends": "codex", "label": "Codex (work)", "aliases": [] },
        "claude-web": { "browser": "edge" },
        "my-tool":    { "kind": "login", "label": "My tool", "artifacts": [
                          { "name": "token", "type": "keychain", "service": "my-tool", "account": "default", "primary": true },
                          { "name": "config", "type": "file", "path": "{xdg_config}/my-tool/auth.json" } ] }
      }
    }

Path tokens are `~`, `{home}`, `{appdata}`, `{localappdata}`, `{xdg_config}`,
`{chrome_config}` and `{env:VAR|default}`. A path or keychain service can also be per-OS:
`{"darwin": "...", "linux": "...", "windows": "..."}`.

A `keychain` artifact maps to each OS's store:

- **macOS:** a Keychain generic password, where `service` is the item's service.
- **Windows:** a Credential Manager generic credential, where `service` is the exact target
  name shown by `cmdkey /list`.
- **Linux/BSD:** a Secret Service item, where `service` is its `service` attribute and
  `account` its `username`/`account` attribute.

To see the built-ins, run `aiswitch init --show-defaults`. Paths that point at your home
directory, a drive root or the aiswitch store are refused.

Older `platforms.json` files without `"schema"` still work, but they replace built-in entries
wholesale. aiswitch warns about this. Re-run `aiswitch init --force` to migrate (the old file
is kept as a `.bak`).

## Known limitations

- **Not verified on real machines:** Windows and Linux support for Claude Desktop and Gemini's
  encrypted mode. Restoring Claude Desktop on Windows/Linux assumes its keyring holds only the
  machine's cookie key, not the login itself.
- **Claude Desktop snapshots are machine-bound.** They contain data encrypted with a key tied
  to this machine. They restore here, but not on another machine or after reinstalling the
  OS. The same goes for Gemini's `gemini-credentials.json` and for the Windows DPAPI vault.
- **Gemini's encrypted mode also switches its MCP tokens**, because Gemini keeps them in the
  same keychain service and file.
- **Environment variables override stored logins.** If `ANTHROPIC_API_KEY`,
  `CLAUDE_CODE_OAUTH_TOKEN`, `OPENAI_API_KEY` or similar is set, switching has no visible
  effect. `aiswitch doctor` warns about these.
- **Codex `-c cli_auth_credentials_store=...` overrides on the command line** can't be seen.
  Only `config.toml` is read.

## Development

    python -m unittest discover -s tests -v      # hermetic; no real credentials touched
    AISWITCH_TEST_REAL_STORE=1 python -m unittest tests.test_aiswitch.TestMacKeychainReal   # macOS
    AISWITCH_TEST_REAL_STORE=1 python -m unittest tests.test_aiswitch.TestWinCredReal       # Windows
    # Linux, in a throw-away keyring:
    dbus-run-session -- sh -c 'echo -n pw | gnome-keyring-daemon --unlock --components=secrets > /tmp/kr.env;
      export $(cat /tmp/kr.env); AISWITCH_TEST_REAL_STORE=1 python -m unittest tests.test_aiswitch.TestSecretServiceReal'

The tests use temporary HOME dirs, an in-memory secret store, a fake process table, and a fake
macOS `security` tool (`tests/fake_security.py`) that reproduces the real tool's output formats
and its 4096-byte `-i` line limit, so the macOS Keychain code is exercised on every OS.
