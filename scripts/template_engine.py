from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import yaml

from common import ROOT_DIR, extract_node_links_from_text

TEMPLATE_FILE = ROOT_DIR / "config" / "rules_template.yaml"
INPUT_DIR = ROOT_DIR / "output" / "verified"
ALT_INPUT_DIR = ROOT_DIR / "output" / "dns"
OUTPUT_CLASH = ROOT_DIR / "output" / "clash.yaml"
OUTPUT_BY_COUNTRY_CLASH = ROOT_DIR / "output" / "by_country" / "all_countries_clash.yaml"

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


def merge_template_and_nodes() -> int:
    print("=== Master Clash Dynamic Template Engine & Dual Load-Balancing Merger ===", flush=True)

    if not TEMPLATE_FILE.exists():
        print(f"Error: Template file {TEMPLATE_FILE} not found.", flush=True)
        return 1

    template_content = TEMPLATE_FILE.read_text(encoding="utf-8")
    template = yaml.safe_load(template_content)

    # 1. Identify Private Nodes in Template
    private_proxies = template.get("proxies", [])
    private_proxy_names = [p.get("name") for p in private_proxies if isinstance(p, dict) and p.get("name")]
    print(f"Preserved {len(private_proxy_names)} Top-Tier Private Nodes: {private_proxy_names}", flush=True)

    # 2. Read Crawled Verified Nodes
    nodes_file = INPUT_DIR / "nodes.txt"
    if not nodes_file.exists():
        nodes_file = ALT_INPUT_DIR / "nodes.txt"

    crawled_nodes = []
    if nodes_file.exists():
        content = nodes_file.read_text(encoding="utf-8")
        crawled_nodes = extract_node_links_from_text(content)

    print(f"Loaded {len(crawled_nodes)} Crawled Verified Nodes.", flush=True)

    # Convert crawled nodes to Clash proxy dicts & group by country
    crawled_clash_proxies = []
    country_groups: Dict[str, List[str]] = {}

    for node in crawled_nodes:
        pdict = build_clash_proxy_dict(node)
        crawled_clash_proxies.append(pdict)
        pname = pdict["name"]

        # Infer country code from name flag/code
        code = node.get("country_code", "OTHER")
        if code not in country_groups:
            country_groups[code] = []
        country_groups[code].append(pname)

    # Combine Private Proxies + Crawled Proxies
    combined_proxies = private_proxies + crawled_clash_proxies
    all_crawled_proxy_names = [p["name"] for p in crawled_clash_proxies]

    # 3. Build Per-Country Load Balancing Groups (ONLY CONTAINING CRAWLED NODES!)
    country_lb_groups = []
    country_lb_group_names = []

    # Global Load-Balancing Fallback Groups
    global_lb_name = "🌐 全球-全节点负载均衡"
    global_auto_name = "⚡ 全球-全节点自动选优"

    global_lb_group = {
        "name": global_lb_name,
        "type": "load-balance",
        "strategy": "round-robin",
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "proxies": all_crawled_proxy_names if all_crawled_proxy_names else ["DIRECT"]
    }
    global_auto_group = {
        "name": global_auto_name,
        "type": "url-test",
        "url": "http://www.gstatic.com/generate_204",
        "interval": 300,
        "proxies": all_crawled_proxy_names if all_crawled_proxy_names else ["DIRECT"]
    }

    # Sorted countries by node count
    sorted_codes = sorted(country_groups.keys(), key=lambda c: len(country_groups[c]), reverse=True)

    for code in sorted_codes:
        cnodes = country_groups[code]
        if not cnodes:
            continue
        flag = COUNTRY_FLAGS.get(code, "🌐")
        zh_name = COUNTRY_NAMES_ZH.get(code, f"{code}节点")

        lb_group_name = f"{flag} {zh_name}-负载均衡"
        auto_group_name = f"{flag} {zh_name}-自动选优"

        country_lb_group_names.append(lb_group_name)

        country_lb_groups.append({
            "name": lb_group_name,
            "type": "load-balance",
            "strategy": "round-robin",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": cnodes
        })
        country_lb_groups.append({
            "name": auto_group_name,
            "type": "url-test",
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300,
            "proxies": cnodes
        })

    # 4. Inject into Template Proxy Groups
    template_proxy_groups = template.get("proxy-groups", [])

    for group in template_proxy_groups:
        gname = group.get("name")

        if gname == "PROXY":
            group["proxies"] = private_proxy_names + [global_auto_name, global_lb_name] + country_lb_group_names + ["DIRECT", "REJECT"]
        elif gname == "📺 TVBox代理":
            # TVBox 100% uses Load Balancing first!
            group["proxies"] = [global_lb_name, global_auto_name] + country_lb_group_names + private_proxy_names + ["DIRECT", "REJECT"]
        else:
            # All other business groups (YouTube, OpenAI, Telegram, Netflix, etc.)
            group["proxies"] = private_proxy_names + ["PROXY", global_auto_name, global_lb_name] + country_lb_group_names + ["DIRECT", "REJECT"]

    # Insert global & country load balancing groups into template proxy-groups
    all_generated_proxy_groups = [template_proxy_groups[0], global_lb_group, global_auto_group] + country_lb_groups + template_proxy_groups[1:]

    # 5. Assemble Final Master Clash Config
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

    final_yaml_content = f"# Generated by TVTV Dynamic Template Merger Engine at {datetime.now(timezone.utc).isoformat()}\n" + yaml.safe_dump(final_config, allow_unicode=True, sort_keys=False)

    # Write output to output/clash.yaml & output/by_country/all_countries_clash.yaml
    OUTPUT_CLASH.write_text(final_yaml_content, encoding="utf-8")
    OUTPUT_BY_COUNTRY_CLASH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_BY_COUNTRY_CLASH.write_text(final_yaml_content, encoding="utf-8")

    print(f"Successfully generated Master Clash Config with Private Node Isolation & Load-Balancing to {OUTPUT_CLASH}!", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(merge_template_and_nodes())
