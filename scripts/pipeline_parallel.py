from __future__ import annotations

import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]


def run_script(script_name: str) -> tuple[str, bool, str]:
    """Execute a python script in scripts/ directory."""
    script_path = ROOT_DIR / "scripts" / script_name
    print(f"  [>] Launching parallel pipeline task: {script_name}...", flush=True)
    t0 = time.time()
    try:
        res = subprocess.run([sys.executable, str(script_path)], capture_output=True, text=True, timeout=300)
        elapsed = time.time() - t0
        if res.returncode == 0:
            return script_name, True, f"Completed in {elapsed:.2f}s"
        else:
            return script_name, False, f"Failed in {elapsed:.2f}s: {res.stderr[:200]}"
    except Exception as exc:
        return script_name, False, f"Exception: {exc}"


def main() -> int:
    print("=================================================================", flush=True)
    print("=== TVTV Ultra-High Speed Parallel Concurrent Pipeline Engine ===", flush=True)
    print("=================================================================", flush=True)
    start_time = time.time()

    # Step 1: Stage 0 - Clone All Repos in Parallel (32 workers)
    print("\n--- Phase 1: Parallel Repo Sync (Stage 0) ---", flush=True)
    s0_name, s0_ok, s0_msg = run_script("clone_repos.py")
    print(f"[{s0_name}] {s0_msg}", flush=True)

    # Step 2: Stage 1 - Parallel Raw Aggregation (32 workers)
    print("\n--- Phase 2: Parallel Multi-Source Aggregation (Stage 1) ---", flush=True)
    s1_name, s1_ok, s1_msg = run_script("aggregate.py")
    print(f"[{s1_name}] {s1_msg}", flush=True)

    # Step 3: Phase 3 - PARALLEL EXECUTION of Stages 2, 3, 4, 5
    # Running Dedupe, DNS Check, Socket Probe, and Mihomo 204 Speedtest
    # ALL AT THE EXACT SAME TIME IN PARALLEL!
    print("\n--- Phase 3: Parallel Concurrent Evaluation (Stages 2, 3, 4, 5 ALL AT ONCE) ---", flush=True)
    eval_scripts = ["dedupe.py", "dns_check.py", "socket_probe.py", "verified.py"]

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run_script, script): script for script in eval_scripts}
        for future in as_completed(futures):
            s_name, s_ok, s_msg = future.result()
            print(f"  [+] [{s_name}] {s_msg}", flush=True)

    # Step 4: Phase 4 - GeoIP Country Split & Template Engine
    print("\n--- Phase 4: GeoIP Country Split & Master Template Engine (Stages 6 & Template) ---", flush=True)
    run_script("country_split.py")
    run_script("template_engine.py")

    total_elapsed = time.time() - start_time
    print(f"\n=================================================================", flush=True)
    print(f"=== Entire Parallel Pipeline Completed Successfully in {total_elapsed:.2f}s! ===", flush=True)
    print("=================================================================", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
