from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_FILE = ROOT_DIR / "config" / "sources.json"
REF_DIR = ROOT_DIR / "ref"


def main() -> int:
    print("=== Stage 0: Clone & Sync All Reference Repositories ===")
    REF_DIR.mkdir(parents=True, exist_ok=True)

    if not CONFIG_FILE.exists():
        print(f"Error: Config file {CONFIG_FILE} not found.")
        return 1

    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    sources = config.get("sources", [])

    for source in sources:
        sname = source.get("name")
        surl = source.get("url")
        spath = ROOT_DIR / source.get("path")

        if spath.exists() and any(spath.iterdir()):
            print(f"[{sname}] Repository already exists at {spath}, skipping clone.")
        else:
            print(f"[{sname}] Cloning {surl} into {spath}...")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", surl, str(spath)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"[{sname}] Successfully cloned.")
            except Exception as exc:
                print(f"[{sname}] Clone failed: {exc}")

    print("=== Stage 0 Complete: All Reference Repositories Ready ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
