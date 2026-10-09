from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import yaml

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text, safe_base64_encode, reconstruct_node_link

INPUT_DIR = ROOT_DIR / "output" / "verified"
ALT_INPUT_DIR = ROOT_DIR / "output" / "dns"
ALT_INPUT_DIR_2 = ROOT_DIR / "output" / "deduped"
ALT_INPUT_DIR_3 = ROOT_DIR / "output" / "raw"
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


def infer_country_from_text_or_ip(server: str, name: str) -> Tuple[str, str]:
    """
    100% Pure Offline Local Country Categorization (Zero DNS Lookups, Zero Network API Calls):
    Infers country code and name purely from node name, domain keywords, or IP string.
    """
    text = f"{name} {server}".upper()

    keywords = [
        ("HK", ["HK", "HONGKONG", "香港"]),
        ("TW", ["TW", "TAIWAN", "台湾"]),
        ("JP", ["JP", "JAPAN", "日本", "TOKYO", "OSAKA"]),
        ("SG", ["SG", "SINGAPORE", "新加坡"]),
        ("US", ["US", "UNITED STATES", "AMERICA", "美国", "LOS ANGELES", "SAN JOSE"]),
        ("KR", ["KR", "KOREA", "韩国", "SEOUL"]),
        ("DE", ["DE", "GERMANY", "德国", "FRANKFURT"]),
        ("UK", ["UK", "GB", "UNITED KINGDOM", "英国", "LONDON"]),
        ("CA", ["CA", "CANADA", "加拿大"]),
        ("FR", ["FR", "FRANCE", "法国"]),
        ("AU", ["AU", "AUSTRALIA", "澳大利亚"]),
        ("NL", ["NL", "NETHERLANDS", "荷兰"]),
        ("RU", ["RU", "RUSSIA", "俄罗斯"]),
        ("IN", ["IN", "INDIA", "印度"]),
        ("BR", ["BR", "BRAZIL", "巴西"])
    ]

    for code, kw_list in keywords:
        if any(kw in text for kw in kw_list):
            return code, COUNTRY_NAMES_ZH.get(code, f"{code}节点")

    return "OTHER", "其他国家节点"


def build_master_country_clash_yaml(country_groups: Dict[str, List[Dict[str, Any]]]) -> str:
    """Build Master All-Countries Clash YAML configuration."""
    all_proxies = []
    country_proxy_groups = []
    country_group_names = []

    sorted_codes = sorted(country_groups.keys(), key=lambda c: len(country_groups[c]), reverse=True)
    seen_proxy_names: Set[str] = set()

    for code in sorted_codes:
        country_nodes = country_groups[code]
        flag = COUNTRY_FLAGS.get(code, "🌐")
        zh_name = COUNTRY_NAMES_ZH.get(code, f"{code}节点")
        group_tag = f"{flag} {zh_name}"
        country_group_names.append(group_tag)

        node_names_in_country = []
        for n in country_nodes:
            base_name = str(n.get("name") or "Node").strip()
            proxy_name = base_name
            idx = 2
            while proxy_name in seen_proxy_names:
                proxy_name = f"{base_name} #{idx}"
                idx += 1
            seen_proxy_names.add(proxy_name)
            node_names_in_country.append(proxy_name)

            proxy = {
                "name": proxy_name,
                "type": n.get("type", "ss"),
                "server": n.get("server"),
                "port": n.get("port")
            }
            if n.get("type") == "vmess":
                proxy.update({"uuid": n.get("uuid"), "alterId": n.get("alterId", 0), "cipher": n.get("cipher") or "auto", "tls": bool(n.get("tls")), "network": n.get("network", "tcp")})
            elif n.get("type") == "vless":
                proxy.update({"uuid": n.get("uuid"), "cipher": "auto", "tls": bool(n.get("tls")), "servername": n.get("sni", "")})
            elif n.get("type") == "ss":
                proxy.update({"cipher": n.get("cipher", "aes-256-gcm"), "password": n.get("password", "")})
            elif n.get("type") == "trojan":
                proxy.update({"password": n.get("password", ""), "sni": n.get("sni", "")})
            elif n.get("type") in ["hysteria2", "hy2"]:
                proxy.update({"auth": n.get("auth") or n.get("password", ""), "sni": n.get("sni", "")})
            all_proxies.append(proxy)

        country_proxy_groups.append({
            "name": group_tag,
            "type": "select",
            "proxies": ["⚡ 自动选择"] + node_names_in_country
        })

    all_proxy_names = [p["name"] for p in all_proxies]

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
    print("=== Stage 6: 100% Pure Offline Local Country Categorization ===", flush=True)

    input_files = [
        INPUT_DIR / "nodes.txt",
        ALT_INPUT_DIR / "nodes.txt",
        ALT_INPUT_DIR_2 / "nodes.txt",
        ALT_INPUT_DIR_3 / "nodes.txt"
    ]

    nodes_file = None
    for f in input_files:
        if f.exists() and f.stat().st_size > 0:
            nodes_file = f
            break

    if not nodes_file:
        print("Error: No input nodes.txt found for country split.", flush=True)
        return 1

    content = nodes_file.read_text(encoding="utf-8")
    nodes = extract_node_links_from_text(content)
    print(f"Loaded {len(nodes)} nodes for 100% offline country categorization from {nodes_file}.", flush=True)

    country_groups: Dict[str, List[Dict[str, Any]]] = {}
    country_counters: Dict[str, int] = {}
    all_country_categorized_nodes = []

    for n in nodes:
        srv = str(n.get("server", "")).strip()
        name = str(n.get("name", "")).strip()

        code, country_name = infer_country_from_text_or_ip(srv, name)

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

    print(f"Categorized nodes into {len(country_groups)} country directories (100% Offline, Zero DNS calls).", flush=True)
    summary_by_country = {}

    for code, country_nodes in country_groups.items():
        country_dir = OUTPUT_DIR / code
        flag = COUNTRY_FLAGS.get(code, "🌐")
        zh_name = COUNTRY_NAMES_ZH.get(code, f"{code}节点")
        stage_title = f"{flag} {zh_name} ({len(country_nodes)}个节点)"

        export_stage_files(output_dir=country_dir, nodes=country_nodes, stage_title=stage_title)

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

    master_clash_yaml_content = build_master_country_clash_yaml(country_groups)

    (OUTPUT_DIR / "all_countries_clash.yaml").write_text(master_clash_yaml_content, encoding="utf-8")
    (OUTPUT_DIR / "clash.yaml").write_text(master_clash_yaml_content, encoding="utf-8")

    export_stage_files(OUTPUT_DIR, all_country_categorized_nodes, "Master All-Countries Subscriptions")

    (ROOT_OUTPUT_DIR / "clash.yaml").write_text(master_clash_yaml_content, encoding="utf-8")

    (OUTPUT_DIR / "country_summary.json").write_text(
        json.dumps(summary_by_country, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print(f"Successfully exported 100% offline country-categorized configs to {OUTPUT_DIR} and {ROOT_OUTPUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
