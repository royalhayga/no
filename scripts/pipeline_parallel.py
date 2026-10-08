from __future__ import annotations

import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text

RAW_OUTPUT_DIR = ROOT_DIR / "output" / "raw"


def run_script(script_name: str) -> tuple[str, bool, str]:
    """Execute a python script in scripts/ directory."""
    script_path = ROOT_DIR / "scripts" / script_name
    print(f"  [>] Launching parallel branch task: {script_name}...", flush=True)
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


def assign_unique_ids_to_raw_nodes() -> int:
    """Assign unique sequential ID (node_id: 1, 2, 3...) to every raw node."""
    nodes_file = RAW_OUTPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        return 0

    content = nodes_file.read_text(encoding="utf-8")
    nodes = extract_node_links_from_text(content)

    for idx, node in enumerate(nodes, start=1):
        node["node_id"] = idx

    export_stage_files(
        output_dir=RAW_OUTPUT_DIR,
        nodes=nodes,
        stage_title="Stage 1 - Raw Aggregation (ID Tagged)"
    )
    print(f"  [+] Tagged {len(nodes)} raw nodes with unique ID sequence (node_id: 1..{len(nodes)})", flush=True)
    return len(nodes)


def main() -> int:
    print("=================================================================", flush=True)
    print("=== TVTV 100% Non-Linear Pure Parallel Multi-Branch Pipeline Engine ===", flush=True)
    print("=================================================================", flush=True)
    start_time = time.time()

    # Step 1: Stage 0 - Clone Repositories
    print("\n--- Step 1: Repo Sync (Stage 0) ---", flush=True)
    s0_name, s0_ok, s0_msg = run_script("clone_repos.py")
    print(f"[{s0_name}] {s0_msg}", flush=True)

    # Step 2: Stage 1 - Multi-Source Aggregation & ID Tagging
    print("\n--- Step 2: Multi-Source Aggregation & ID Tagging (Stage 1) ---", flush=True)
    s1_name, s1_ok, s1_msg = run_script("aggregate.py")
    print(f"[{s1_name}] {s1_msg}", flush=True)

    total_tagged = assign_unique_ids_to_raw_nodes()

    # Step 3: PURE PARALLEL CONCURRENT MULTI-BRANCH EVALUATION (PROHIBIT LINEAR STACKING!)
    # All 5 evaluation branches run SIMULTANEOUSLY at the EXACT SAME INSTANT on ID-tagged raw nodes!
    print("\n--- Step 3: Pure Concurrent Parallel Multi-Branch Evaluation (5 Branches SIMULTANEOUSLY) ---", flush=True)
    parallel_branches = [
        "validate_and_prune.py",  # Branch 1: Mihomo Kernel Auditor
        "dedupe.py",              # Branch 2: Fingerprint Deduplication
        "dns_check.py",           # Branch 3: 3-DNS GFW Pollution Check
        "socket_probe.py",        # Branch 4: Socket TCP/TLS/QUIC Probe
        "verified.py"             # Branch 5: Mihomo Go Native 204 Speedtest
    ]

    branch_results = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(run_script, script): script for script in parallel_branches}
        for future in as_completed(futures):
            b_name, b_ok, b_msg = future.result()
            branch_results[b_name] = (b_ok, b_msg)
            print(f"  [+] [{b_name}] {b_msg}", flush=True)

    # Step 4: GeoIP Country Split & Master Template Engine
    print("\n--- Step 4: GeoIP Country Split & Master Template Engine (Stages 6 & Template) ---", flush=True)
    run_script("country_split.py")
    run_script("template_engine.py")

    total_elapsed = time.time() - start_time
    print(f"\n=================================================================", flush=True)
    print(f"=== 100% Non-Linear Pure Parallel Pipeline Completed in {total_elapsed:.2f}s! ===", flush=True)
    print("=================================================================", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
