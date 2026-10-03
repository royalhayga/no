from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text, get_node_fingerprint

INPUT_DIR = ROOT_DIR / "output" / "raw"
OUTPUT_DIR = ROOT_DIR / "output" / "deduped"


def assign_standard_names(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Assign standardized names to deduplicated nodes."""
    geo_counters: Dict[str, int] = {}

    for idx, node in enumerate(nodes):
        raw_name = node.get("name", "").upper()
        # Simple GeoIP heuristic based on node name keywords
        if "HK" in raw_name or "香港" in raw_name:
            geo = "🇭🇰 HK"
        elif "TW" in raw_name or "台湾" in raw_name:
            geo = "🇹🇼 TW"
        elif "JP" in raw_name or "日本" in raw_name:
            geo = "🇯🇵 JP"
        elif "SG" in raw_name or "新加坡" in raw_name:
            geo = "🇸🇬 SG"
        elif "US" in raw_name or "美国" in raw_name:
            geo = "🇺🇸 US"
        elif "KR" in raw_name or "韩国" in raw_name:
            geo = "🇰🇷 KR"
        elif "DE" in raw_name or "德国" in raw_name:
            geo = "🇩🇪 DE"
        elif "UK" in raw_name or "英国" in raw_name:
            geo = "🇬🇧 UK"
        else:
            geo = "🌐 Node"

        geo_counters[geo] = geo_counters.get(geo, 0) + 1
        node["name"] = f"{geo}-{geo_counters[geo]:02d}"
    return nodes


def analyze_alias_collisions(raw_nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Process 2.2: Scan for potential alias collisions / same server endpoints.
    Groups nodes sharing the exact same server IP/domain and port.
    """
    endpoint_map: Dict[str, List[Dict[str, Any]]] = {}
    for node in raw_nodes:
        server = str(node.get("server", "")).lower().strip()
        port = str(node.get("port", ""))
        key = f"{server}:{port}"
        if key not in endpoint_map:
            endpoint_map[key] = []
        endpoint_map[key].append(node)

    alias_groups = []
    for endpoint, group in endpoint_map.items():
        if len(group) > 1:
            alias_groups.append({
                "endpoint": endpoint,
                "count": len(group),
                "unique_names": list({n.get("name") for n in group}),
                "protocols": list({n.get("type") for n in group})
            })

    return {
        "total_unique_endpoints": len(endpoint_map),
        "potential_alias_groups_count": len(alias_groups),
        "collision_details": alias_groups[:100]  # Top 100 alias groups
    }


def main() -> int:
    print("=== Stage 2: SHA256 Fingerprint Deduplication & Alias Analysis ===")
    nodes_file = INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        print(f"Error: Input file {nodes_file} not found. Run Stage 1 (scripts/aggregate.py) first.")
        return 1

    content = nodes_file.read_text(encoding="utf-8")
    raw_nodes = extract_node_links_from_text(content)
    print(f"Loaded {len(raw_nodes)} raw nodes from Stage 1.")

    # Process 2.1: Mainstream Fingerprint Deduplication
    seen_fingerprints = set()
    deduped_nodes: List[Dict[str, Any]] = []

    for node in raw_nodes:
        fp = get_node_fingerprint(node)
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)
        deduped_nodes.append(node)

    print(f"Process 2.1 Completed: Deduplicated from {len(raw_nodes)} -> {len(deduped_nodes)} unique nodes.")

    # Assign clean standardized node names
    deduped_nodes = assign_standard_names(deduped_nodes)

    # Process 2.2: Parallel Branch Alias / Endpoint Collision Report
    alias_report = analyze_alias_collisions(raw_nodes)
    print(f"Process 2.2 Completed: Found {alias_report['potential_alias_groups_count']} potential alias endpoint groups.")

    # Export all 5 standard format files + alias_report.json to output/deduped/
    export_stage_files(
        output_dir=OUTPUT_DIR,
        nodes=deduped_nodes,
        stage_title="Stage 2 - Deduplication & Alias Analysis",
        extra_data=alias_report
    )

    # Save dedicated alias_report.json
    (OUTPUT_DIR / "alias_report.json").write_text(
        json.dumps(alias_report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"Successfully exported Stage 2 output to {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
