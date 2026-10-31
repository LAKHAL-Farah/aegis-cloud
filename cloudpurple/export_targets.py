#!/usr/bin/env python3
"""terraform output of both range roots -> build/range/targets.json (mode 600, gitignored)."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "build" / "range"
ROOTS = {"purple": "cloudpurple/terraform/purple", "hardened": "cloudpurple/terraform/hardened"}


def main() -> int:
    data = {}
    for name, rel in ROOTS.items():
        proc = subprocess.run(["terraform", f"-chdir={ROOT / rel}", "output", "-json", "target"],
                              capture_output=True, text=True)
        if proc.returncode != 0 or not proc.stdout.strip():
            print(f"cannot read output of {name}: run `make range-up` first\n{proc.stderr}", file=sys.stderr)
            return 1
        data[name] = json.loads(proc.stdout)
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / "targets.json"
    path.write_text(json.dumps(data, indent=2))
    os.chmod(path, 0o600)
    print(f"wrote {path}  (purple={data['purple']['account_id']}, hardened={data['hardened']['account_id']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())