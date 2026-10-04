from __future__ import annotations

import asyncio
import json
import re
import socket
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Tuple

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text

INPUT_DIR = ROOT_DIR / "output" / "verified"
ALT_INPUT_DIR = ROOT_DIR / "output" / "dns"
OUTPUT_DIR = ROOT_DIR / "output" / "by_country"

COUNTRY_FLAGS = {
    "HK": "🇭🇰", "TW": "🇹🇼", "JP": "🇯🇵", "SG": "🇸🇬",
    "US": "🇺🇸", "KR": "🇰🇷", "DE": "🇩🇪", "UK": "🇬🇧",
    "CA": "🇨🇦", "FR": "🇫🇷", "AU": "🇦🇺", "NL": "🇳🇱",
    "RU": "🇷🇺", "IN": "🇮🇳", "BR": "🇧🇷"
}


def resolve_server_ip(server: str) -> str:
    """Resolve domain to IPv4 address or return if already IP."""
    clean_server = server.strip().lower()
    if clean_server.replace(".", "").isdigit():
        return clean_server
    try:
        return socket.gethostbyname(clean_server)
    except Exception:
        return ""


def batch_lookup_geoip(ips: List[str]) -> Dict[str, Tuple[str, str]]:
    """Batch query IP geolocation using ip-api.com (100 IPs per batch POST)."""
    ip_geo_map: Dict[str, Tuple[str, str]] = {}
    valid_ips = [ip for ip in set(ips) if ip]

    # Process in chunks of 100 IPs
    chunk_size = 100
    for i in range(0, len(valid_ips), chunk_size):
        chunk = valid_ips[i:i + chunk_size]
        try:
            req_data = json.dumps([{"query": ip} for ip in chunk]).encode("utf-8")
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=query,country,countryCode,status",
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                results = json.loads(resp.read().decode("utf-8"))
                for res in results:
                    if res.get("status") == "success":
                        query_ip = res.get("query")
                        code = res.get("countryCode", "OTHER").upper()
                        country = res.get("country", "Unknown")
                        ip_geo_map[query_ip] = (code, country)
        except Exception as exc:
            print(f"GeoIP Batch Request Failed for chunk {i}: {exc}", flush=True)

    return ip_geo_map


def main() -> int:
    print("=== Stage 6 (Index 6): GeoIP Country/Region Categorization & Multi-Country Subscriptions ===", flush=True)
    nodes_file = INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        nodes_file = ALT_INPUT_DIR / "nodes.txt"

    if not nodes_file.exists():
        print(f"Error: Input file {nodes_file} not found.", flush=True)
        return 1

    content = nodes_file.read_text(encoding="utf-8")
    nodes = extract_node_links_from_text(content)
    print(f"Loaded {len(nodes)} nodes for GeoIP country splitting.", flush=True)

    # 1. Resolve server domains to IPs
    print("Resolving server domain IPs for GeoIP lookup...", flush=True)
    server_to_ip = {}
    for n in nodes:
        srv = n.get("server", "").strip()
        if srv and srv not in server_to_ip:
            server_to_ip[srv] = resolve_server_ip(srv)

    all_ips = list(set(server_to_ip.values()))
    print(f"Performing batch GeoIP lookup for {len(all_ips)} unique IPs...", flush=True)

    ip_geo_map = batch_lookup_geoip(all_ips)

    # 2. Group nodes by country code
    country_groups: Dict[str, List[Dict[str, Any]]] = {}
    country_counters: Dict[str, int] = {}

    for n in nodes:
        srv = n.get("server", "").strip()
        resolved_ip = server_to_ip.get(srv, "")
        code, country_name = ip_geo_map.get(resolved_ip, ("OTHER", "Other Regions"))

        if code not in country_groups:
            country_groups[code] = []
            country_counters[code] = 0

        country_counters[code] += 1
        flag = COUNTRY_FLAGS.get(code, "🌐")

        # Assign accurate GeoIP country flag and name
        n_copy = dict(n)
        n_copy["name"] = f"{flag} {code}-{country_counters[code]:02d}"
        n_copy["country_code"] = code
        n_copy["country"] = country_name
        country_groups[code].append(n_copy)

    # 3. Export all 5 standard format files into separate country subfolders in output/by_country/
    print(f"Splitting nodes into {len(country_groups)} country directories...", flush=True)
    summary_by_country = {}

    for code, country_nodes in country_groups.items():
        country_dir = OUTPUT_DIR / code
        flag = COUNTRY_FLAGS.get(code, "🌐")
        stage_title = f"{flag} {code} Country Subscription ({len(country_nodes)} nodes)"

        export_stage_files(
            output_dir=country_dir,
            nodes=country_nodes,
            stage_title=stage_title
        )
        summary_by_country[code] = {
            "country_code": code,
            "flag": flag,
            "count": len(country_nodes)
        }
        print(f"  [+] [{flag} {code}] Exported {len(country_nodes)} nodes to {country_dir}", flush=True)

    # Export overall summary of by_country
    (OUTPUT_DIR / "country_summary.json").write_text(
        json.dumps(summary_by_country, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"Successfully exported Stage 6 GeoIP Country Split to {OUTPUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
