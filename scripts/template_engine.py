from __future__ import annotations

import copy
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

# 产物输出路径：凡是精炼版 (Elite 架构) 均在文件名中包含 elite
OUTPUT_RULES_CLASH = ROOT_DIR / "output" / "clash_rules.yaml"
OUTPUT_ELITE_RULES_CLASH = ROOT_DIR / "output" / "clash_elite_rules.yaml"
OUTPUT_PUBLIC_RULES_CLASH = ROOT_DIR / "output" / "clash_public_rules.yaml"
OUTPUT_PUBLIC_ELITE_RULES_CLASH = ROOT_DIR / "output" / "clash_public_elite_rules.yaml"
OUTPUT_MOBILE_RULES_CLASH = ROOT_DIR / "output" / "clash_mobile_elite_rules.yaml"
OUTPUT_PUBLIC_MOBILE_RULES_CLASH = ROOT_DIR / "output" / "clash_public_mobile_elite_rules.yaml"

PRIVATE_NODE_NAMES = ["手机", "reality funo", "JPreality", "39515", "reality", "tourism", "test"]

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


def build_merged_clash_config(template_path: Path, crawled_nodes: List[Dict[str, Any]], include_private: bool = True) -> str:
    """
    Build Clash config.
    include_private=True: 包含顶级私有占位节点 (手机, reality 等)
    include_private=False: 纯公开版，无任何私有占位符节点，仅依赖自动爬取节点与负载均衡
    """
    template_content = template_path.read_text(encoding="utf-8")
    template = yaml.safe_load(template_content)

    # 1. Identify Private Nodes
    if include_private:
        private_proxies = template.get("proxies", [])
        private_proxy_names = [p.get("name") for p in private_proxies if isinstance(p, dict) and p.get("name")]
    else:
        private_proxies = []
        private_proxy_names = []

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

    # Track existing group names
    existing_group_names: Set[str] = set()
    template_proxy_groups = copy.deepcopy(template.get("proxy-groups", []))

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
        g_proxies = group.get("proxies", [])

        # 如果是不带私有节点的公开版本，强行从策略组过滤掉私有占位符节点
        if not include_private:
            g_proxies = [p for p in g_proxies if p not in PRIVATE_NODE_NAMES]

        if gname == "PROXY":
            group["proxies"] = private_proxy_names + [global_auto_name, global_lb_name] + country_lb_group_names + [p for p in g_proxies if p not in private_proxy_names + [global_auto_name, global_lb_name] + country_lb_group_names]
        elif gname == "📺 TVBox代理":
            group["proxies"] = [global_lb_name, global_auto_name] + country_lb_group_names + private_proxy_names + [p for p in g_proxies if p not in private_proxy_names + [global_auto_name, global_lb_name] + country_lb_group_names]
        else:
            base_items = [p for p in g_proxies if p in ["PROXY", "DIRECT", "REJECT"]]
            group["proxies"] = private_proxy_names + base_items + [global_auto_name, global_lb_name] + country_lb_group_names

            # 去重保持顺序
            seen = set()
            clean_p = []
            for p in group["proxies"]:
                if p not in seen:
                    seen.add(p)
                    clean_p.append(p)
            group["proxies"] = clean_p

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

    # 1. 私有带占位节点版本 (clash_rules.yaml & clash_elite_rules.yaml)
    if FULL_TEMPLATE_FILE.exists():
        full_yaml = build_merged_clash_config(FULL_TEMPLATE_FILE, crawled_nodes, include_private=True)
        OUTPUT_RULES_CLASH.write_text(full_yaml, encoding="utf-8")
        print(f"Successfully generated Full Private Clash Config -> {OUTPUT_RULES_CLASH}", flush=True)

    if ELITE_TEMPLATE_FILE.exists():
        elite_yaml = build_merged_clash_config(ELITE_TEMPLATE_FILE, crawled_nodes, include_private=True)
        OUTPUT_ELITE_RULES_CLASH.write_text(elite_yaml, encoding="utf-8")
        print(f"Successfully generated Elite Private Clash Config -> {OUTPUT_ELITE_RULES_CLASH}", flush=True)

    # 2. 纯公开不带占位节点版本 (clash_public_rules.yaml & clash_public_elite_rules.yaml)
    if FULL_TEMPLATE_FILE.exists():
        public_full_yaml = build_merged_clash_config(FULL_TEMPLATE_FILE, crawled_nodes, include_private=False)
        OUTPUT_PUBLIC_RULES_CLASH.write_text(public_full_yaml, encoding="utf-8")
        print(f"Successfully generated Full Public Clash Config -> {OUTPUT_PUBLIC_RULES_CLASH}", flush=True)

    if ELITE_TEMPLATE_FILE.exists():
        public_elite_yaml = build_merged_clash_config(ELITE_TEMPLATE_FILE, crawled_nodes, include_private=False)
        OUTPUT_PUBLIC_ELITE_RULES_CLASH.write_text(public_elite_yaml, encoding="utf-8")
        print(f"Successfully generated Elite Public Clash Config -> {OUTPUT_PUBLIC_ELITE_RULES_CLASH}", flush=True)

    # 3. 手机端专享版 (包含私有版与纯公开版)
    if ELITE_TEMPLATE_FILE.exists():
        mobile_yaml = build_merged_clash_config(ELITE_TEMPLATE_FILE, crawled_nodes, include_private=True)
        OUTPUT_MOBILE_RULES_CLASH.write_text(mobile_yaml, encoding="utf-8")
        print(f"Successfully generated Dedicated Private Mobile Clash Config -> {OUTPUT_MOBILE_RULES_CLASH}", flush=True)

        public_mobile_yaml = build_merged_clash_config(ELITE_TEMPLATE_FILE, crawled_nodes, include_private=False)
        OUTPUT_PUBLIC_MOBILE_RULES_CLASH.write_text(public_mobile_yaml, encoding="utf-8")
        print(f"Successfully generated Dedicated Public Mobile Clash Config -> {OUTPUT_PUBLIC_MOBILE_RULES_CLASH}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
