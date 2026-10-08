from __future__ import annotations

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_FILE = ROOT_DIR / "config" / "sources.json"
REF_DIR = ROOT_DIR / "ref"


def clone_single_repo(source: dict) -> tuple[str, int, str]:
    """Clone a single git repository."""
    sname = source.get("name")
    surl = source.get("url")
    spath = ROOT_DIR / source.get("path")

    if spath.exists() and any(spath.iterdir()):
        return sname, 0, "Already exists"

    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", surl, str(spath)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45
        )
        return sname, 1, "Cloned successfully (depth 1)"
    except Exception as exc:
        return sname, -1, f"Failed: {exc}"


def main() -> int:
    print("=== Stage 0: Parallel Concurrent Clone of All 28 Repositories ===")
    REF_DIR.mkdir(parents=True, exist_ok=True)

    if not CONFIG_FILE.exists():
        print(f"Error: Config file {CONFIG_FILE} not found.")
        return 1

    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    sources = config.get("sources", [])

    print(f"Starting 16-worker concurrent clone for {len(sources)} repositories...")

    cloned, skipped, failed = 0, 0, 0
    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = {executor.submit(clone_single_repo, src): src for src in sources}
        for future in as_completed(futures):
            sname, status, msg = future.result()
            if status == 1:
                cloned += 1
                print(f"  [+] [{sname}] {msg}")
            elif status == 0:
                skipped += 1
            else:
                failed += 1
                print(f"  [-] [{sname}] {msg}")

    print(f"=== Stage 0 Complete: Cloned {cloned}, Skipped {skipped}, Failed {failed} ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
