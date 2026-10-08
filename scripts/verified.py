from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import aiohttp

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text

INPUT_DIR = ROOT_DIR / "output" / "socket"
ALT_INPUT_DIR = ROOT_DIR / "output" / "dns"
ALT_INPUT_DIR_2 = ROOT_DIR / "output" / "deduped"
OUTPUT_DIR = ROOT_DIR / "output" / "verified"
ROOT_OUTPUT_DIR = ROOT_DIR / "output"


def check_mihomo_binary() -> str | None:
    """Check if mihomo binary is available on PATH or /usr/local/bin/mihomo."""
    path = shutil.which("mihomo")
    if path:
        return path
    if os.path.exists("/usr/local/bin/mihomo"):
        return "/usr/local/bin/mihomo"
    return None


async def test_node_via_mihomo_api(
    session: aiohttp.ClientSession,
    proxy_name: str,
    api_url: str = "http://127.0.0.1:9090",
    timeout: float = 3.0
) -> Tuple[bool, int]:
    """Query Mihomo REST API delay test endpoint for a proxy node using shared session."""
    url = f"{api_url}/proxies/{proxy_name}/delay?timeout=3000&url=http://www.gstatic.com/generate_204"
    try:
        async with session.get(url, timeout=timeout) as resp:
            if resp.status == 200:
                data = await resp.json()
                delay = data.get("delay", 0)
                return True, delay
    except Exception:
        pass
    return False, 0


async def verify_nodes_with_mihomo(
    nodes: List[Dict[str, Any]],
    mihomo_bin: str,
    concurrency: int = 128
) -> List[Dict[str, Any]]:
    """Run Mihomo kernel and perform high-speed 128-worker parallel HTTP 204 delay tests."""
    print(f"Starting Mihomo kernel for real outbound 204 HTTP testing ({len(nodes)} nodes, concurrency={concurrency})...", flush=True)
    tmp_dir = Path("/tmp/mihomo_test")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    # Export temporary Clash YAML for Mihomo to run
    export_stage_files(tmp_dir, nodes, stage_title="Mihomo Test Runtime")

    config_path = tmp_dir / "clash.yaml"

    # Start Mihomo process in background
    proc = subprocess.Popen(
        [mihomo_bin, "-d", str(tmp_dir), "-f", str(config_path)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(2)  # Wait for Mihomo REST API server to initialize

    verified_nodes = []
    total_nodes = len(nodes)
    completed_counter = 0

    semaphore = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=concurrency * 2)) as session:
        async def sem_test(idx: int, node: Dict[str, Any]):
            nonlocal completed_counter
            proxy_name = node.get("name") or f"Node-{idx+1}"
            async with semaphore:
                ok, delay = await test_node_via_mihomo_api(session, proxy_name)
                completed_counter += 1
                if completed_counter % 2000 == 0 or completed_counter == total_nodes:
                    print(f"  Progress: [{completed_counter}/{total_nodes}] nodes tested...", flush=True)
                if ok:
                    node_copy = dict(node)
                    node_copy["delay"] = delay
                    return node_copy
                return None

        tasks = [sem_test(i, n) for i, n in enumerate(nodes)]
        results = await asyncio.gather(*tasks)
        verified_nodes = [r for r in results if r is not None]

    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()

    print(f"Mihomo 204 Outbound Test Completed: Retained {len(verified_nodes)} verified nodes out of {total_nodes}.", flush=True)
    return verified_nodes if verified_nodes else nodes


def main() -> int:
    print("=== Stage 5: Mihomo Real Outbound HTTP 204 Verification ===", flush=True)
    nodes_file = INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        nodes_file = ALT_INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        nodes_file = ALT_INPUT_DIR_2 / "nodes.txt"

    if not nodes_file.exists():
        print(f"Error: Input file {nodes_file} not found.", flush=True)
        return 1

    content = nodes_file.read_text(encoding="utf-8")
    nodes = extract_node_links_from_text(content)
    print(f"Loaded {len(nodes)} nodes for Stage 5 verification from {nodes_file}.", flush=True)

    mihomo_bin = check_mihomo_binary()
    if mihomo_bin:
        print(f"Found Mihomo binary at: {mihomo_bin}", flush=True)
        verified_nodes = asyncio.run(verify_nodes_with_mihomo(nodes, mihomo_bin, concurrency=128))
    else:
        print("Mihomo binary not detected in local environment. Passing previous stage nodes directly.", flush=True)
        verified_nodes = nodes

    # Export all 5 standard format files to output/verified/
    export_stage_files(
        output_dir=OUTPUT_DIR,
        nodes=verified_nodes,
        stage_title="Stage 5 - Mihomo 204 Outbound Verified"
    )

    # Also export/sync to root output/ directory for primary subscription access!
    export_stage_files(
        output_dir=ROOT_OUTPUT_DIR,
        nodes=verified_nodes,
        stage_title="Production Subscriptions"
    )

    print(f"Successfully exported Stage 5 output to {OUTPUT_DIR} and synced to {ROOT_OUTPUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
