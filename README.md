# aiswitch

Account switcher for AI tools, in the spirit of TcNo Account Switcher. It freezes each
account's login state and swaps a saved copy back in. It never asks for, or stores, your
password. It only copies the credential files and Keychain items the tools already create.

Single file, Python 3.9+, no dependencies. macOS first (Linux works for the CLI tools).

## Install
No sudo needed: link the script into `~/.local/bin` and put that on your PATH.

    git clone https://github.com/bakisama/aiswitch.git ~/tools/aiswitch
    chmod +x ~/tools/aiswitch/aiswitch.py
    mkdir -p ~/.local/bin && ln -sf ~/tools/aiswitch/aiswitch.py ~/.local/bin/aiswitch
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
    aiswitch doctor

## Use
    # 1. log in to account A the normal way (e.g. `claude` -> /login), then:
    aiswitch save claude-code personal
    # 2. add a second account
    aiswitch new claude-code            # logs out locally (A stays saved)
    claude   # /login as account B
    aiswitch save claude-code work
    # 3. flip any time
    aiswitch use claude-code personal
    aiswitch ls ; aiswitch current ; aiswitch doctor

## GUI
    aiswitch gui            # opens a local page in your browser; Ctrl-C to stop
Account cards per tool with Switch / Save current login / Add new account / Delete. It asks
before replacing an unsaved login or quitting a running app. It listens on 127.0.0.1 only, on a
random port with a one-time token in the URL, and rejects foreign Host headers (DNS-rebinding).
Use `--port N` for a fixed port, `--no-open` to skip launching the browser.

Platforms: `claude-code` (cc), `codex` (cx), `gemini` (gem), `claude-desktop` (cd, experimental),
and web logins `claude-web`, `chatgpt-web`, `gemini-web`.

## How each one works
| Platform | What is swapped |
|---|---|
| Claude Code | Keychain item `Claude Code-credentials` (macOS) or `~/.claude/.credentials.json`, plus the `oauthAccount` key of `~/.claude.json` (other settings untouched) |
| Codex CLI | `~/.codex/auth.json` |
| Gemini CLI | `~/.gemini/oauth_creds.json`, `google_accounts.json` |
| Claude Desktop | cookies / local storage / IndexedDB in `~/Library/Application Support/Claude`; app must be quit (`--quit`). Experimental: tokens may be bound to the machine keychain |
| Web | Not swapped. Each account is a separate Chrome profile; `use` opens the site in that profile (`aiswitch save chatgpt-web work --profile "Work"`) |

## Safety
- Before replacing a login, aiswitch writes any refreshed tokens back to the matching saved account
  (identified by email/org id, so it can't overwrite the wrong one), and keeps the last 5 backups.
- It refuses to replace a login that isn't saved under any name (override with `--force`).
- A failed switch rolls back to the previous login.
- Snapshots live in `~/.aiswitch` (mode 700). Claude Code's are in Keychain items, not plain files.
  **Codex/Gemini snapshots are plaintext token files, same as the originals**, so treat that folder as secret.
- Restart running CLI sessions after switching; they hold the old token in memory.
- `aiswitch init` writes `~/.aiswitch/platforms.json` so you can add other tools or fix paths if a tool changes its layout.

Check each provider's terms before sharing or pooling subscriptions. This only moves *your* logins between *your* accounts.

## Known limitations
- Keychain writes pass the credential to `security add-generic-password -w`, so it is briefly visible to other local processes in `ps`.
- Codex, Gemini and Claude Desktop snapshots are plain files under `~/.aiswitch` (folder mode 0700). Keep that folder private.
- Claude Desktop and the browser profiles have had less testing than the CLI tools.
