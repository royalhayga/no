from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

import yaml

from common import ROOT_DIR, extract_node_links_from_text

FULL_TEMPLATE_FILE = ROOT_DIR / "config" / "rules_template.yaml"
ELITE_TEMPLATE_FILE = ROOT_DIR / "config" / "rules_elite_template.yaml"

INPUT_DIR = ROOT_DIR / "output" / "verified"
ALT_INPUT_DIR = ROOT_DIR / "output" / "dns"

OUTPUT_RULES_CLASH = ROOT_DIR / "output" / "clash_rules.yaml"
OUTPUT_ELITE_RULES_CLASH = ROOT_DIR / "output" / "clash_elite_rules.yaml"

COUNTRY_FLAGS = {
    "HK": "🇭🇰", "TW": "🇹🇼", "JP": "🇯🇵", "SG": "🇸🇬",
    "US": "🇺🇸", "KR": "🇰🇷", "DE": "🇩🇪", "UK": "🇬🇧",
    "CA": "🇨🇦", "FR": "🇫🇷", "AU": "🇦🇺", "NL": "🇳🇱",
    "RU": "🇷🇺", "IN": "🇮🇳", "BR": "🇧🇷"
}

COUNTRY_NAMES_ZH = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡",
    "US": "美国", "KR": "韩国", "DE": "德国", "UK": "英国",
    "CA": "加拿大", "FR": "法国", "AU": "澳大利亚", "NL": "荷兰",
    "RU": "俄罗斯", "IN": "印度", "BR": "巴西", "OTHER": "其他国家"
}


def build_clash_proxy_dict(node: Dict[str, Any]) -> Dict[str, Any]:
    """Convert node dictionary to Clash proxy definition."""
    ptype = node.get("type", "ss")
    proxy = {
        "name": node.get("name"),
        "type": ptype,
        "server": node.get("server"),
        "port": node.get("port")
    }
    if ptype == "vmess":
        proxy.update({"uuid": node.get("uuid"), "alterId": node.get("alterId", 0), "cipher": node.get("cipher", "auto"), "tls": bool(node.get("tls")), "network": node.get("network", "tcp")})
    elif ptype == "vless":
        proxy.update({"uuid": node.get("uuid"), "cipher": "auto", "tls": bool(node.get("tls")), "servername": node.get("sni", "")})
    elif ptype == "ss":
        proxy.update({"cipher": node.get("cipher", "aes-256-gcm"), "password": node.get("password", "")})
    elif ptype == "trojan":
        proxy.update({"password": node.get("password", ""), "sni": node.get("sni", "")})
    elif ptype in ["hysteria2", "hy2"]:
        proxy.update({"auth": node.get("auth") or node.get("password", ""), "sni": node.get("sni", "")})
    return proxy


def build_merged_clash_config(template_path: Path, crawled_nodes: List[Dict[str, Any]]) -> str:
    """Build a Clash configuration with 100% duplicate proxy group name prevention."""
    template_content = template_path.read_text(encoding="utf-8")
    template = yaml.safe_load(template_content)

    # 1. Identify Private Nodes
    private_proxies = template.get("proxies", [])
    private_proxy_names = [p.get("name") for p in private_proxies if isinstance(p, dict) and p.get("name")]

    # 2. Convert crawled nodes to Clash proxies and group by country
    crawled_clash_proxies = []
    country_groups: Dict[str, List[str]] = {}

    for node in crawled_nodes:
        pdict = build_clash_proxy_dict(node)
        crawled_clash_proxies.append(pdict)
        pname = pdict["name"]

        code = node.get("country_code", "OTHER")
        if code not in country_groups:
            country_groups[code] = []
        country_groups[code].append(pname)

    combined_proxies = private_proxies + crawled_clash_proxies
    all_crawled_proxy_names = [p["name"] for p in crawled_clash_proxies]

    # Track existing group names to 100% PREVENT DUPLICATE GROUP NAMES!
    existing_group_names: Set[str] = set()
    template_proxy_groups = template.get("proxy-groups", [])
    for g in template_proxy_groups:
        if isinstance(g, dict) and g.get("name"):
            existing_group_names.add(g["name"])

    # 3. Build Per-Country Load Balancing Groups
    country_lb_groups = []
    country_lb_group_names = []

    global_lb_name = "🌐 全球-全节点负载均衡"
    global_auto_name = "⚡ 全球-全节点自动选优"

    if global_lb_name not in existing_group_names:
        existing_group_names.add(global_lb_name)
        global_lb_group = {
            "name": global_lb_name,
            "type": "load-balance",
            "strategy": "round-robin",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": all_crawled_proxy_names if all_crawled_proxy_names else ["DIRECT"]
        }
    else:
        global_lb_group = None

    if global_auto_name not in existing_group_names:
        existing_group_names.add(global_auto_name)
        global_auto_group = {
            "name": global_auto_name,
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": all_crawled_proxy_names if all_crawled_proxy_names else ["DIRECT"]
        }
    else:
        global_auto_group = None

    sorted_codes = sorted(country_groups.keys(), key=lambda c: len(country_groups[c]), reverse=True)

    for code in sorted_codes:
        cnodes = country_groups[code]
        if not cnodes:
            continue
        flag = COUNTRY_FLAGS.get(code, "🌐")
        zh_name = COUNTRY_NAMES_ZH.get(code, f"{code}")

        lb_group_name = f"{flag} {zh_name}-负载均衡"
        auto_group_name = f"{flag} {zh_name}-自动选优"

        if lb_group_name not in existing_group_names:
            existing_group_names.add(lb_group_name)
            country_lb_group_names.append(lb_group_name)
            country_lb_groups.append({
                "name": lb_group_name,
                "type": "load-balance",
                "strategy": "round-robin",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": cnodes
            })

        if auto_group_name not in existing_group_names:
            existing_group_names.add(auto_group_name)
            country_lb_groups.append({
                "name": auto_group_name,
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": cnodes
            })

    # 4. Inject into Template Proxy Groups
    for group in template_proxy_groups:
        gname = group.get("name")
        if gname == "PROXY":
            group["proxies"] = private_proxy_names + [global_auto_name, global_lb_name] + country_lb_group_names + ["DIRECT", "REJECT"]
        elif gname == "📺 TVBox代理":
            group["proxies"] = [global_lb_name, global_auto_name] + country_lb_group_names + private_proxy_names + ["DIRECT", "REJECT"]
        else:
            group["proxies"] = private_proxy_names + ["PROXY", global_auto_name, global_lb_name] + country_lb_group_names + ["DIRECT", "REJECT"]

    # Assemble all generated proxy groups cleanly
    generated_extra_groups = []
    if global_lb_group:
        generated_extra_groups.append(global_lb_group)
    if global_auto_group:
        generated_extra_groups.append(global_auto_group)
    generated_extra_groups.extend(country_lb_groups)

    all_generated_proxy_groups = [template_proxy_groups[0]] + generated_extra_groups + template_proxy_groups[1:]

    final_config = {
        "mixed-port": template.get("mixed-port", 7890),
        "allow-lan": template.get("allow-lan", True),
        "mode": template.get("mode", "rule"),
        "dns": template.get("dns", {}),
        "log-level": template.get("log-level", "info"),
        "ipv6": template.get("ipv6", False),
        "external-controller": template.get("external-controller", "0.0.0.0:9090"),
        "proxies": combined_proxies,
        "proxy-groups": all_generated_proxy_groups,
        "rule-providers": template.get("rule-providers", {}),
        "rules": template.get("rules", [])
    }

    return f"# Generated by TVTV Dynamic Template Merger Engine at {datetime.now(timezone.utc).isoformat()}\n" + yaml.safe_dump(final_config, allow_unicode=True, sort_keys=False)


def main() -> int:
    print("=== Master Clash Dynamic Template Engine (Full & Elite Rulesets) ===", flush=True)

    # Read Crawled Verified Nodes
    nodes_file = INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        nodes_file = ALT_INPUT_DIR / "nodes.txt"

    crawled_nodes = []
    if nodes_file.exists():
        content = nodes_file.read_text(encoding="utf-8")
        crawled_nodes = extract_node_links_from_text(content)

    print(f"Loaded {len(crawled_nodes)} Crawled Verified Nodes.", flush=True)

    # 1. Build Full Ruleset Version (clash_rules.yaml)
    if FULL_TEMPLATE_FILE.exists():
        full_yaml = build_merged_clash_config(FULL_TEMPLATE_FILE, crawled_nodes)
        OUTPUT_RULES_CLASH.write_text(full_yaml, encoding="utf-8")
        print(f"Successfully generated Full Ruleset Clash Config -> {OUTPUT_RULES_CLASH}", flush=True)

    # 2. Build Elite Ruleset Version (clash_elite_rules.yaml)
    if ELITE_TEMPLATE_FILE.exists():
        elite_yaml = build_merged_clash_config(ELITE_TEMPLATE_FILE, crawled_nodes)
        OUTPUT_ELITE_RULES_CLASH.write_text(elite_yaml, encoding="utf-8")
        print(f"Successfully generated Elite Streamlined Clash Config -> {OUTPUT_ELITE_RULES_CLASH}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
