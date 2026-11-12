# Changelog

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
