"""Build dist/aiswitch.pyz (a zipapp runnable with any Python >= 3.9) and dist/SHA256SUMS."""
import hashlib
import shutil
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"


def main():
    DIST.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy2(ROOT / "aiswitch.py", Path(tmp) / "aiswitch.py")
        (Path(tmp) / "__main__.py").write_text("import sys\nimport aiswitch\nsys.exit(aiswitch.main())\n")
        zipapp.create_archive(tmp, DIST / "aiswitch.pyz", interpreter="/usr/bin/env python3")
    lines = []
    for f in sorted(DIST.iterdir()):
        if f.is_file() and f.name != "SHA256SUMS":
            lines.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n")
    (DIST / "SHA256SUMS").write_text("".join(lines))
    sys.stdout.write("".join(lines))


if __name__ == "__main__":
    main()
