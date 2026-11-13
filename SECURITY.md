# Security policy

aiswitch handles live login credentials, so security bugs matter more here than in most CLIs.

## Reporting a vulnerability

Please **do not open a public issue**. Report it privately through GitHub's
"Report a vulnerability" button (Security tab of this repository). Include the aiswitch
version (`aiswitch --version`), your OS, and steps to reproduce.

You should get a reply within a week. Fixes are released as a new version on PyPI and
GitHub Releases, and the advisory is published once a fixed version is available.

## Scope

In scope, for example:
- credentials written somewhere they shouldn't be, with wrong permissions, or to the wrong account;
- a sequence of commands that loses a live login without a backup;
- secrets exposed through process arguments, logs, error messages or the GUI;
- the local GUI being reachable or controllable from other sites or hosts.

Out of scope: attacks that need code already running as your user. Such code can read the
same credential files and Keychain items that the AI tools themselves use (see the threat
model in the README).

## Supported versions

Only the latest release gets security fixes.
