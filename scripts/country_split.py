from __future__ import annotations

import asyncio
import json
import re
import socket
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text, safe_base64_encode, reconstruct_node_link

INPUT_DIR = ROOT_DIR / "output" / "verified"
ALT_INPUT_DIR = ROOT_DIR / "output" / "dns"
OUTPUT_DIR = ROOT_DIR / "output" / "by_country"
ROOT_OUTPUT_DIR = ROOT_DIR / "output"

COUNTRY_FLAGS = {
    "HK": "🇭🇰", "TW": "🇹🇼", "JP": "🇯🇵", "SG": "🇸🇬",
    "US": "🇺🇸", "KR": "🇰🇷", "DE": "🇩🇪", "UK": "🇬🇧",
    "CA": "🇨🇦", "FR": "🇫🇷", "AU": "🇦🇺", "NL": "🇳🇱",
    "RU": "🇷🇺", "IN": "🇮🇳", "BR": "🇧🇷"
}

COUNTRY_NAMES_ZH = {
    "HK": "香港节点", "TW": "台湾节点", "JP": "日本节点", "SG": "新加坡节点",
    "US": "美国节点", "KR": "韩国节点", "DE": "德国节点", "UK": "英国节点",
    "CA": "加拿大节点", "FR": "法国节点", "AU": "澳大利亚节点", "NL": "荷兰节点",
    "RU": "俄罗斯节点", "IN": "印度节点", "BR": "巴西节点", "OTHER": "其他国家节点"
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


def build_master_country_clash_yaml(country_groups: Dict[str, List[Dict[str, Any]]]) -> str:
    """
    Build Master All-Countries Clash YAML configuration.
    Includes per-country Proxy Groups (e.g. 🇭🇰 香港节点, 🇯🇵 日本节点, 🇺🇸 美国节点)
    so users can import ONE single master URL and switch countries easily!
    """
    all_proxies = []
    country_proxy_groups = []
    country_group_names = []

    # Sort countries by count
    sorted_codes = sorted(country_groups.keys(), key=lambda c: len(country_groups[c]), reverse=True)

    for code in sorted_codes:
        country_nodes = country_groups[code]
        flag = COUNTRY_FLAGS.get(code, "🌐")
        zh_name = COUNTRY_NAMES_ZH.get(code, f"{code}节点")
        group_tag = f"{flag} {zh_name}"
        country_group_names.append(group_tag)

        node_names_in_country = []
        for n in country_nodes:
            proxy_name = n.get("name")
            node_names_in_country.append(proxy_name)

            proxy = {
                "name": proxy_name,
                "type": n.get("type", "ss"),
                "server": n.get("server"),
                "port": n.get("port")
            }
            if n.get("type") == "vmess":
                proxy.update({"uuid": n.get("uuid"), "alterId": n.get("alterId", 0), "cipher": n.get("cipher", "auto"), "tls": bool(n.get("tls")), "network": n.get("network", "tcp")})
            elif n.get("type") == "vless":
                proxy.update({"uuid": n.get("uuid"), "cipher": "auto", "tls": bool(n.get("tls")), "servername": n.get("sni", "")})
            elif n.get("type") == "ss":
                proxy.update({"cipher": n.get("cipher", "aes-256-gcm"), "password": n.get("password", "")})
            elif n.get("type") == "trojan":
                proxy.update({"password": n.get("password", ""), "sni": n.get("sni", "")})
            elif n.get("type") in ["hysteria2", "hy2"]:
                proxy.update({"auth": n.get("auth") or n.get("password", ""), "sni": n.get("sni", "")})
            all_proxies.append(proxy)

        # Per-country Proxy Group
        country_proxy_groups.append({
            "name": group_tag,
            "type": "select",
            "proxies": ["⚡ 自动选择"] + node_names_in_country
        })

    all_proxy_names = [p["name"] for p in all_proxies]

    # Global Master Groups
    master_groups = [
        {"name": "🚀 节点选择", "type": "select", "proxies": ["⚡ 自动选择"] + country_group_names + ["DIRECT"]},
        {"name": "⚡ 自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": all_proxy_names if all_proxy_names else ["DIRECT"]}
    ] + country_proxy_groups

    clash_config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": all_proxies,
        "proxy-groups": master_groups,
        "rules": ["MATCH,🚀 节点选择"]
    }

    return f"# Master All-Countries Clash Config Generated at {datetime.now(timezone.utc).isoformat()}\n" + yaml.safe_dump(clash_config, allow_unicode=True, sort_keys=False)


def main() -> int:
    print("=== Stage 6 (Index 6): GeoIP Country Split & Master Multi-Country Clash Generator ===", flush=True)
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
    all_country_categorized_nodes = []

    for n in nodes:
        srv = n.get("server", "").strip()
        resolved_ip = server_to_ip.get(srv, "")
        code, country_name = ip_geo_map.get(resolved_ip, ("OTHER", "Other Regions"))

        if code not in country_groups:
            country_groups[code] = []
            country_counters[code] = 0

        country_counters[code] += 1
        flag = COUNTRY_FLAGS.get(code, "🌐")

        n_copy = dict(n)
        n_copy["name"] = f"{flag} {code}-{country_counters[code]:02d}"
        n_copy["country_code"] = code
        n_copy["country"] = country_name
        country_groups[code].append(n_copy)
        all_country_categorized_nodes.append(n_copy)

    # 3. Export per-country subfolders (with country prefix files)
    print(f"Splitting nodes into {len(country_groups)} country directories...", flush=True)
    summary_by_country = {}

    for code, country_nodes in country_groups.items():
        country_dir = OUTPUT_DIR / code
        flag = COUNTRY_FLAGS.get(code, "🌐")
        zh_name = COUNTRY_NAMES_ZH.get(code, f"{code}节点")
        stage_title = f"{flag} {zh_name} ({len(country_nodes)}个节点)"

        # Standard 5 format export
        export_stage_files(output_dir=country_dir, nodes=country_nodes, stage_title=stage_title)

        # Also write explicit country-prefixed files (e.g. HK_clash.yaml, HK_sub.txt)
        (country_dir / f"{code}_clash.yaml").write_text((country_dir / "clash.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        (country_dir / f"{code}_sub.txt").write_text((country_dir / "sub.txt").read_text(encoding="utf-8"), encoding="utf-8")
        (country_dir / f"{code}_singbox.json").write_text((country_dir / "singbox.json").read_text(encoding="utf-8"), encoding="utf-8")
        (country_dir / f"{code}_nodes.txt").write_text((country_dir / "nodes.txt").read_text(encoding="utf-8"), encoding="utf-8")

        summary_by_country[code] = {
            "country_code": code,
            "flag": flag,
            "name": zh_name,
            "count": len(country_nodes)
        }
        print(f"  [+] [{flag} {zh_name}] Exported {len(country_nodes)} nodes to {country_dir}", flush=True)

    # 4. Generate Master All-Countries Clash Config & Master Subscriptions in output/by_country/
    print("Generating Master All-Countries Clash Config with Per-Country Proxy Groups...", flush=True)
    master_clash_yaml_content = build_master_country_clash_yaml(country_groups)

    (OUTPUT_DIR / "all_countries_clash.yaml").write_text(master_clash_yaml_content, encoding="utf-8")
    (OUTPUT_DIR / "clash.yaml").write_text(master_clash_yaml_content, encoding="utf-8")

    export_stage_files(OUTPUT_DIR, all_country_categorized_nodes, "Master All-Countries GeoIP Subscriptions")

    # Sync Master All-Countries Clash to root output/clash.yaml!
    (ROOT_OUTPUT_DIR / "clash.yaml").write_text(master_clash_yaml_content, encoding="utf-8")

    # Export overall country summary
    (OUTPUT_DIR / "country_summary.json").write_text(
        json.dumps(summary_by_country, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"Successfully generated Master All-Countries Clash YAML and exported to {OUTPUT_DIR} and {ROOT_OUTPUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
