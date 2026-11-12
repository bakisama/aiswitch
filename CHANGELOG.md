# Changelog

## 0.3.0 (unreleased)

OS- and CPU-architecture-agnostic release, based on a 71-finding audit (Windows, Linux/BSD/WSL,
macOS and arch, per-tool storage research, secret-store design), with each finding
independently verified.

### Secret stores on every OS
- New backends: Windows Credential Manager (ctypes, pointer-correct on x86/x64/ARM64) with a
  DPAPI-encrypted vault for aiswitch's copies, and the freedesktop Secret Service via
  `secret-tool` (stdin only; a dismissed unlock prompt or a missing D-Bus session is an error,
  never "absent"). Keychain artifacts can be scoped to one account. Backend metadata (attributes,
  blob encoding) is preserved, so restored items stay findable by the tool.
- macOS Keychain:
  - Passwords are read with `-g` instead of `-w`. With `-w`, any secret with non-printable or
    non-ASCII bytes was returned as hex and would have been restored corrupted.
  - `security -i` is never used for lines over its 4096-byte buffer. Previously a long secret
    could be truncated into the live item.
  - `security` always runs as the absolute `/usr/bin/security`.
  - Stale items under other accounts are removed in a loop.
  - An unparseable item is an error.

### Tools
- Claude Code: the macOS `.credentials.json` fallback is switched too. With
  `CLAUDE_CONFIG_DIR` set, the per-config-dir Keychain item (`-<sha256[:8]>` suffix) is used.
- Codex: keyring/auto mode is supported on macOS (`Codex Auth`, account per CODEX_HOME,
  identity read from the keyring JSON). On other OSes it is refused with an explanation.
  `ephemeral` is refused.
- Gemini: `GEMINI_CLI_HOME` is honoured. Encrypted-storage mode (keychain item and encrypted
  file) is supported.
- Claude Desktop: Windows (including the MSIX/Store data dir) and Linux are supported, and the
  desktop app is no longer confused with the Claude Code CLI.
- Browsers: Chrome, Edge, Chromium and Brave, including snap, flatpak, the BSD port,
  the Windows browser from WSL, and 32-bit Python on 64-bit Windows. Profiles are listed from
  and launched in the same browser. A launch with no display is now an error.

### Processes
- Matches executables and command lines, case-sensitive except on Windows, and handles
  Windows backslash paths, arch-suffixed binaries and node-hosted CLIs.
- `ps -ww` without COLUMNS. tasklist and PowerShell run from absolute System32 paths, with no
  console flash, and their results are sanity-checked.
- Sandboxes, and missing command lines, report "unknown".
- Quitting targets only main executables: never helpers, the parent or the process group. It
  waits by wall-clock time and checks the macOS Automation permission.

### Robustness
- SIGTERM and SIGHUP roll back like Ctrl-C, and a rollback can't be interrupted.
- Live-side leftovers of a crash (a dir renamed away, temp files) are repaired on the next run.
- Running as root via sudo is refused.
- Filesystems without locks or without Unix permissions get a clear error or warning.
- NTFS junctions and read-only files are handled.
- Platform ids and artifact names are validated, including Windows reserved names and
  case-only clashes.
- Account names are matched case-insensitively where the filesystem is.
- `save` refuses an empty snapshot unless `--allow-empty` is given.
- Cygwin/MSYS Python is refused with guidance. Microsoft Store Python is refused for
  `%APPDATA%` paths.
- GUI: the server starts before the browser opens, no console browser is started on headless
  machines, it opens the Windows browser from WSL, and the port is bound exclusively on
  Windows.
- `doctor` shows the CPU, Python bitness, WSL, sandbox, secret stores, tool storage modes and
  overriding env vars.

### CI
- Linux and Windows ARM64, macOS Intel and ARM64, 32-bit Windows Python, Alpine/musl, FreeBSD,
  real keystore jobs on all three OSes, and wheel/`.pyz` smoke tests on all three OSes.

## 0.2.0 (unreleased)

Hardening release before public distribution.

### Data safety
- macOS Keychain: only `security` exit 44 means "no item". A locked keychain, a denied prompt
  or a missing GUI session is now a hard error, instead of reading as "not logged in" (which
  could skip the backup and the unsaved-login guard).
- Keychain restore writes first (`add-generic-password -U`) and removes stale items afterwards,
  instead of delete-then-write.
- Keychain secrets are passed to `security` over stdin (hex encoded), not argv. If that can't
  be verified, aiswitch falls back to argv with a warning.
- Snapshots (schema 2) store vault secrets under random `aiswitch:<uuid>` refs recorded in
  `meta.json`. Snapshot dirs are swapped by rename, and deletes rename the dir away before
  removing secrets. Interrupted operations are cleaned up on the next run. Schema-1
  snapshots are still read.
- A failed switch with no prior login now returns to a clean logged-out state, and a failing
  rollback no longer hides the original error.
- Claude Desktop: no automatic write-back (there is no identity check). Use `--writeback` to opt in.
  `save` refuses while the app is running.
- `save` refuses to store the same identity under a second name (`--allow-duplicate` overrides).

### Cross-platform
- Imports and runs on Windows: lazy `fcntl`, a `msvcrt` lock, `host_os()` returns `windows`,
  and `%USERPROFILE%` is used.
- Per-OS path templates and env overrides (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`). Claude Code and
  Codex are enabled on Windows (beta), and the Chrome-profile launcher on Linux/Windows (beta).
- UTF-8 file I/O (BOM tolerated), ASCII fallback glyphs on legacy consoles, `NO_COLOR`,
  Windows VT colours, and a top-level error handler with `--debug`.
- Process guard: executable/argv matching (node-hosted CLIs), scoped to the current user, and
  "unknown" instead of a silent "not running".
- Writes go through symlinks (dotfile managers), with retry on Windows sharing violations,
  read-only-safe deletes, a lock that waits briefly and names the holding pid, rejection of
  Windows reserved and case-colliding names, refusal of dangerous configured paths, and a
  guard against `AISWITCH_HOME` pointing at a non-store folder.
- `platforms.json` schema 1: field-wise merge over built-ins, `extends`, `disabled`.

### New
- `aiswitch purge`, `aiswitch init --show-defaults`, `aiswitch gui --no-browser`.
- `pyproject.toml` (console script `aiswitch`), a `.pyz` build, and CI on Linux/macOS/Windows.

## 0.1.0
- First version (macOS-first).
