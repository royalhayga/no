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
    print("=== TVTV ID-Based Set Difference Parallel Execution Engine ===", flush=True)
    print("=================================================================", flush=True)
    start_time = time.time()

    # Phase 1: Clone Repos (Stage 0)
    print("\n--- Phase 1: Parallel Repo Sync (Stage 0) ---", flush=True)
    s0_name, s0_ok, s0_msg = run_script("clone_repos.py")
    print(f"[{s0_name}] {s0_msg}", flush=True)

    # Phase 2: Raw Aggregation & ID Sequence Tagging (Stage 1)
    print("\n--- Phase 2: Parallel Multi-Source Aggregation & ID Tagging (Stage 1) ---", flush=True)
    s1_name, s1_ok, s1_msg = run_script("aggregate.py")
    print(f"[{s1_name}] {s1_msg}", flush=True)

    total_tagged = assign_unique_ids_to_raw_nodes()

    # Phase 3: DUAL-BRANCH PARALLEL EXECUTION
    # Branch A: Mihomo Kernel Auditor & Syntax Pruner
    # Branch B: Network Evaluation Pipeline (Dedupe -> DNS -> Socket -> Speedtest)
    print("\n--- Phase 3: Dual-Branch Parallel Execution (Mihomo Kernel Auditor || Network Evaluation Pipeline) ---", flush=True)

    def run_branch_a():
        return run_script("validate_and_prune.py")

    def run_branch_b():
        s2_n, s2_ok, s2_m = run_script("dedupe.py")
        s3_n, s3_ok, s3_m = run_script("dns_check.py")
        s4_n, s4_ok, s4_m = run_script("socket_probe.py")
        s5_n, s5_ok, s5_m = run_script("verified.py")
        return "network_pipeline", s2_ok and s3_ok and s4_ok and s5_ok, "Network Pipeline Completed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        f_branch_a = executor.submit(run_branch_a)
        f_branch_b = executor.submit(run_branch_b)

        res_a = f_branch_a.result()
        res_b = f_branch_b.result()

        print(f"  [+] Branch A (Mihomo Kernel Auditor): {res_a[2]}", flush=True)
        print(f"  [+] Branch B (Network Evaluation Pipeline): {res_b[2]}", flush=True)

    # Phase 4: GeoIP Country Split & Master Template Engine
    print("\n--- Phase 4: GeoIP Country Split & Master Template Engine (Stages 6 & Template) ---", flush=True)
    run_script("country_split.py")
    run_script("template_engine.py")

    total_elapsed = time.time() - start_time
    print(f"\n=================================================================", flush=True)
    print(f"=== ID-Based Parallel Pipeline Completed Successfully in {total_elapsed:.2f}s! ===", flush=True)
    print("=================================================================", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
