#!/usr/bin/env python3
"""A stand-in for macOS /usr/bin/security, for testing MacKeychain on any OS.

Mimics what aiswitch relies on (from Apple's SecurityTool sources):
  * exit 44 + "could not be found" for errSecItemNotFound, exit 45 for duplicates,
    exit 36 for "User interaction is not allowed" (FAKE_SEC_FAIL=locked),
  * attribute dump on stdout with "acct"<blob>="..." (0xHEX  "..." for non-printable, <NULL>),
  * -g prints 'password: "..."' (or 'password: 0xHEX  "..."') on stderr,
  * -w prints the raw password, or bare lowercase hex when any byte is non-printable,
  * -i reads commands from stdin into a 4096-byte buffer: longer lines are split and each
    piece runs as its own command (so an over-long -X value gets truncated).
Items live in the JSON file named by $FAKE_SEC_DB; every argv is appended to $FAKE_SEC_LOG.
"""
import json
import os
import shlex
import sys

DB = os.environ["FAKE_SEC_DB"]


def load():
    try:
        with open(DB) as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def save(items):
    with open(DB, "w") as f:
        json.dump(items, f)


def printable(b):
    return all(0x20 <= c <= 0x7E and c != 0x5C for c in b)


def fmt(b):
    if printable(b):
        return '"' + b.decode() + '"'
    esc = "".join(chr(c) if 0x20 <= c <= 0x7E and c != 0x5C else "\\%03o" % c for c in b)
    return "0x" + b.hex().upper() + '  "' + esc + '"'


def opts(args):
    out, i = {}, 0
    while i < len(args):
        a = args[i]
        if a in ("-s", "-a", "-w", "-X", "-l"):
            out[a] = args[i + 1] if i + 1 < len(args) else None
            i += 2
        else:
            out[a] = True
            i += 1
    return out


def find(items, o):
    for it in items:
        if it["svc"] == o.get("-s") and ("-a" not in o or (it["acct"] or "") == o["-a"]):
            return it
    return None


def run(args, out, err):
    if os.environ.get("FAKE_SEC_FAIL") == "locked" and args and args[0] != "-i":
        err.write("security: SecKeychainSearchCopyNext: User interaction is not allowed.\n")
        return 36
    cmd, o = args[0], opts(args[1:])
    items = load()
    if cmd == "find-generic-password":
        it = find(items, o)
        if it is None:
            err.write("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n")
            return 44
        acct = "<NULL>" if it["acct"] is None else fmt(it["acct"].encode())
        out.write('keychain: "/Users/x/Library/Keychains/login.keychain-db"\nversion: 512\nclass: "genp"\n'
                  f'attributes:\n    0x00000007 <blob>="{it["svc"]}"\n    "acct"<blob>={acct}\n'
                  f'    "svce"<blob>="{it["svc"]}"\n')
        pw = bytes.fromhex(it["pw"])
        if "-g" in o:
            err.write("password: " + (fmt(pw) if pw else "") + "\n")
        if "-w" in o:
            out.write((pw.decode() if printable(pw) else pw.hex()) + "\n")
        return 0
    if cmd == "dump-keychain":
        for it in items:
            acct = "<NULL>" if it["acct"] is None else fmt(it["acct"].encode())
            out.write('keychain: "/Users/x/Library/Keychains/login.keychain-db"\nversion: 512\nclass: "genp"\n'
                      f'attributes:\n    "acct"<blob>={acct}\n    "svce"<blob>="{it["svc"]}"\n')
        return 0
    if cmd == "add-generic-password":
        pw = bytes.fromhex(o["-X"]) if "-X" in o else o.get("-w", "").encode()
        acct = o.get("-a", os.environ.get("USER", "me"))
        it = find(items, {"-s": o["-s"], "-a": acct})
        if it and "-U" not in o:
            err.write("security: SecKeychainItemCreateFromContent: The specified item already exists in the keychain.\n")
            return 45
        if it:
            it["pw"] = pw.hex()
        else:
            items.append({"svc": o["-s"], "acct": acct, "pw": pw.hex()})
        save(items)
        return 0
    if cmd == "delete-generic-password":
        it = find(items, o)
        if it is None:
            err.write("security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.\n")
            return 44
        items.remove(it)
        save(items)
        return 0
    err.write(f"security: unknown command {cmd}\n")
    return 2


def main():
    with open(os.environ.get("FAKE_SEC_LOG", os.devnull), "a") as log:
        log.write(json.dumps(sys.argv[1:]) + "\n")
    args = sys.argv[1:]
    if args[:1] == ["-i"]:
        data = sys.stdin.read()
        rc = 0
        for line in data.splitlines():
            for k in range(0, max(len(line), 1), 4095):        # MAX_LINE_LEN 4096 incl. NUL
                piece = line[k:k + 4095]
                if piece.strip():
                    try:
                        rc = run(shlex.split(piece), sys.stdout, sys.stderr) or rc
                    except (ValueError, KeyError, IndexError):
                        sys.stderr.write("security: parse error\n")
                        rc = 1
        return 0       # interactive mode reports success regardless, like the real tool
    return run(args, sys.stdout, sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
