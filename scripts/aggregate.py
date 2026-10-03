from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml

from common import ROOT_DIR, extract_node_links_from_text, export_stage_files, sanitize_node

CONFIG_FILE = ROOT_DIR / "config" / "sources.json"
OUTPUT_DIR = ROOT_DIR / "output" / "raw"


def parse_clash_yaml_file(file_path: Path) -> List[Dict[str, Any]]:
    """Parse Clash YAML file and extract proxies."""
    nodes = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = yaml.safe_load(content)
        if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
            for proxy in data["proxies"]:
                if not isinstance(proxy, dict) or not proxy.get("name") or not proxy.get("server"):
                    continue
                ptype = str(proxy.get("type", "")).lower()
                if ptype not in ["vmess", "vless", "ss", "trojan", "hysteria2", "hy2", "tuic"]:
                    continue
                node = {
                    "type": ptype,
                    "name": str(proxy.get("name")).strip(),
                    "server": str(proxy.get("server")).strip(),
                    "port": int(proxy.get("port", 0)),
                    "uuid": str(proxy.get("uuid", "")).strip(),
                    "password": str(proxy.get("password", "")).strip(),
                    "cipher": str(proxy.get("cipher", "auto")).strip(),
                    "sni": str(proxy.get("servername", proxy.get("sni", ""))).strip(),
                    "raw_proxy_dict": proxy
                }
                sanitized = sanitize_node(node)
                if sanitized:
                    nodes.append(sanitized)
    except Exception:
        pass
    return nodes


def scan_local_repository(repo_path: Path) -> List[Dict[str, Any]]:
    """Recursively scan a local ref/ repository directory for all node files."""
    nodes = []
    if not repo_path.exists():
        return nodes

    for root, _, files in os.walk(repo_path):
        # Ignore git metadata
        if ".git" in root:
            continue
        for file in files:
            file_path = Path(root) / file
            if file.endswith((".yaml", ".yml")):
                yaml_nodes = parse_clash_yaml_file(file_path)
                nodes.extend(yaml_nodes)

            # Text / Base64 / JSON / Markdown files
            if file.endswith((".txt", ".json", ".md", ".sub", ".link")):
                try:
                    text_content = file_path.read_text(encoding="utf-8", errors="ignore")
                    extracted = extract_node_links_from_text(text_content)
                    nodes.extend(extracted)
                except Exception:
                    pass
    return nodes


def main() -> int:
    print("=== Stage 1: Local Multi-Source Repository Aggregation ===")
    if not CONFIG_FILE.exists():
        print(f"Error: Config file {CONFIG_FILE} not found.")
        return 1

    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    sources = config.get("sources", [])

    all_raw_nodes: List[Dict[str, Any]] = []
    source_stats = []

    for source in sources:
        sname = source.get("name")
        spath = ROOT_DIR / source.get("path")

        repo_nodes = scan_local_repository(spath)
        all_raw_nodes.extend(repo_nodes)

        source_stats.append({
            "source": sname,
            "path": str(spath),
            "found_nodes": len(repo_nodes)
        })
        print(f"[{sname}] Scanned '{spath}' -> Found {len(repo_nodes)} nodes")

    print(f"Stage 1 Total Raw Aggregated Nodes: {len(all_raw_nodes)}")

    # Export all 5 standard formats to output/raw/
    export_stage_files(
        output_dir=OUTPUT_DIR,
        nodes=all_raw_nodes,
        stage_title="Stage 1 - Raw Aggregation",
        extra_data={"sources": source_stats}
    )
    print(f"Successfully exported Stage 1 output to {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
