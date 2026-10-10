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
FAKELOCATION_TEMPLATE_FILE = ROOT_DIR / "config" / "rules_fakelocation_template.yaml"

INPUT_DIR = ROOT_DIR / "output" / "verified"
ALT_INPUT_DIR = ROOT_DIR / "output" / "dns"

# 产物输出路径：纯规则文件、完整版与精炼版 (Elite) 产物
OUTPUT_RULES_ONLY_CLASH = ROOT_DIR / "output" / "clash_rules_only.yaml"
OUTPUT_MOBILE_RULES_ONLY_CLASH = ROOT_DIR / "output" / "clash_mobile_rules_only.yaml"

OUTPUT_RULES_CLASH = ROOT_DIR / "output" / "clash_rules.yaml"
OUTPUT_ELITE_RULES_CLASH = ROOT_DIR / "output" / "clash_elite_rules.yaml"
OUTPUT_PUBLIC_RULES_CLASH = ROOT_DIR / "output" / "clash_public_rules.yaml"
OUTPUT_PUBLIC_ELITE_RULES_CLASH = ROOT_DIR / "output" / "clash_public_elite_rules.yaml"
OUTPUT_MOBILE_RULES_CLASH = ROOT_DIR / "output" / "clash_mobile_elite_rules.yaml"
OUTPUT_PUBLIC_MOBILE_RULES_CLASH = ROOT_DIR / "output" / "clash_public_mobile_elite_rules.yaml"
OUTPUT_FAKELOCATION_RULES_CLASH = ROOT_DIR / "output" / "clash_fakelocation_rules.yaml"
OUTPUT_PUBLIC_FAKELOCATION_RULES_CLASH = ROOT_DIR / "output" / "clash_public_fakelocation_rules.yaml"

PRIVATE_NODE_NAMES = ["手机", "reality funo", "JPreality", "39515", "reality", "tourism", "test"]

# 全球全量国家/地区国旗 Emoji 映射表
COUNTRY_FLAGS = {
    "HK": "🇭🇰", "TW": "🇹🇼", "JP": "🇯🇵", "SG": "🇸🇬", "US": "🇺🇸", "KR": "🇰🇷", "DE": "🇩🇪", "UK": "🇬🇧",
    "CA": "🇨🇦", "FR": "🇫🇷", "AU": "🇦🇺", "NL": "🇳🇱", "RU": "🇷🇺", "IN": "🇮🇳", "BR": "🇧🇷", "IR": "🇮🇷",
    "IT": "🇮🇹", "ES": "🇪🇸", "SE": "🇸🇪", "NO": "🇳🇴", "FI": "🇫🇮", "TR": "🇹🇷", "PL": "🇵🇱", "UA": "🇺🇦",
    "EG": "🇪🇬", "ZA": "🇿🇦", "AR": "🇦🇷", "CL": "🇨🇱", "CO": "🇨🇴", "MX": "🇲🇽", "TH": "🇹🇭", "VN": "🇻🇳",
    "ID": "🇮🇩", "MY": "🇲🇾", "PH": "🇵🇭", "PK": "🇵🇰", "UZ": "🇺🇿", "KZ": "🇰🇿", "GE": "🇬🇪", "AM": "🇦🇲",
    "AZ": "🇦🇿", "BY": "🇧🇾", "MD": "🇲🇩", "RO": "🇷🇴", "HU": "🇭🇺", "CZ": "🇨🇿", "SK": "🇸🇰", "AT": "🇦🇹",
    "CH": "🇨🇭", "BE": "🇧🇪", "LU": "🇱🇺", "IE": "🇮🇪", "IS": "🇮🇸", "NZ": "🇳🇿", "AE": "🇦🇪", "SA": "🇸🇦",
    "IL": "🇮🇱", "KH": "🇰🇭", "MM": "🇲🇲", "BD": "🇧🇩", "LK": "🇱🇰", "NP": "🇳🇵", "GR": "🇬🇷", "BG": "🇧🇬",
    "HR": "🇭🇷", "SI": "🇸🇮", "BA": "🇧🇦", "RS": "🇷🇸", "MK": "🇲🇰", "AL": "🇦🇱", "CY": "🇨🇾", "MT": "🇲🇹",
    "LT": "🇱🇹", "LV": "🇱🇻", "EE": "🇪🇪", "PE": "🇵🇪", "VE": "🇻🇪", "EC": "🇪🇨", "CR": "🇨🇷", "PA": "🇵🇦",
    "UY": "🇺🇾", "DO": "🇩🇴", "KE": "🇰🇪", "NG": "🇳🇬", "GH": "🇬🇭", "TN": "🇹🇳", "MA": "🇲🇦", "OTHER": "🌐"
}

# 全球全量国家/地区中文名称映射表
COUNTRY_NAMES_ZH = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡", "US": "美国", "KR": "韩国", "DE": "德国", "UK": "英国",
    "CA": "加拿大", "FR": "法国", "AU": "澳大利亚", "NL": "荷兰", "RU": "俄罗斯", "IN": "印度", "BR": "巴西", "IR": "伊朗",
    "IT": "意大利", "ES": "西班牙", "SE": "瑞典", "NO": "挪威", "FI": "芬兰", "TR": "土耳其", "PL": "波兰", "UA": "乌克兰",
    "EG": "埃及", "ZA": "南非", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚", "MX": "墨西哥", "TH": "泰国", "VN": "越南",
    "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾", "PK": "巴基斯坦", "UZ": "乌兹别克斯坦", "KZ": "哈萨克斯坦", "GE": "格鲁吉亚", "AM": "亚美尼亚",
    "AZ": "阿塞拜疆", "BY": "白俄罗斯", "MD": "摩尔多瓦", "RO": "罗马尼亚", "HU": "匈牙利", "CZ": "捷克", "SK": "斯洛伐克", "AT": "奥地利",
    "CH": "瑞士", "BE": "比利时", "LU": "卢森堡", "IE": "爱尔兰", "IS": "冰岛", "NZ": "新西兰", "AE": "阿联酋", "SA": "沙特阿拉伯",
    "IL": "以色列", "KH": "柬埔寨", "MM": "缅甸", "BD": "孟加拉国", "LK": "斯里兰卡", "NP": "尼泊尔", "GR": "希腊", "BG": "保加利亚",
    "HR": "克罗地亚", "SI": "斯洛文尼亚", "BA": "波黑", "RS": "塞尔维亚", "MK": "北马其顿", "AL": "阿尔巴尼亚", "CY": "塞浦路斯", "MT": "马耳他",
    "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚", "PE": "秘鲁", "VE": "委内瑞拉", "EC": "厄瓜多尔", "CR": "哥斯达黎加", "PA": "巴拿马",
    "UY": "乌拉圭", "DO": "多米尼加", "KE": "肯尼亚", "NG": "尼日利亚", "GH": "加纳", "TN": "突尼斯", "MA": "摩洛哥", "OTHER": "其他地区"
}


VALID_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "chacha20-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    "rc4-md5", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "chacha20", "chacha20-ietf", "xchacha20-ietf-poly1305",
    "none"
}


def build_rules_only_clash_config(template_path: Path) -> str:
    """
    生成绝对纯净、不带任何爬取节点/私有节点的纯规则 YAML 配置文件。
    proxies 数组为空 []，供用户随时把自己的私有节点填进去直接使用！
    支持 UTF-8 容错解码（errors="ignore"）
    """
    template_content = template_path.read_text(encoding="utf-8", errors="ignore")
    template = yaml.safe_load(template_content)

    template_proxy_groups = copy.deepcopy(template.get("proxy-groups", []))

    for group in template_proxy_groups:
        g_proxies = group.get("proxies", [])
        clean_p = [p for p in g_proxies if p not in PRIVATE_NODE_NAMES]
        if not clean_p:
            clean_p = ["DIRECT"]
        group["proxies"] = clean_p

    final_config = {
        "mixed-port": template.get("mixed-port", 7890),
        "allow-lan": template.get("allow-lan", True),
        "mode": template.get("mode", "rule"),
        "dns": template.get("dns", {}),
        "log-level": template.get("log-level", "info"),
        "ipv6": template.get("ipv6", False),
        "external-controller": template.get("external-controller", "0.0.0.0:9090"),
        "proxies": [],
        "proxy-groups": template_proxy_groups,
        "rule-providers": template.get("rule-providers", {}),
        "rules": template.get("rules", [])
    }

    return f"# Pure Rules-Only Clash Config Generated at {datetime.now(timezone.utc).isoformat()}\n" + yaml.safe_dump(final_config, allow_unicode=True, sort_keys=False)


def build_clash_proxy_dict(node: Dict[str, Any]) -> Dict[str, Any] | None:
    """Convert node dictionary to Clash proxy definition with strict SS cipher & credential validation."""
    ptype = str(node.get("type", "ss")).lower().strip()
    server = str(node.get("server", "")).strip()
    port = node.get("port")
    name = str(node.get("name", "")).strip()

    if not server or not port or not name:
        return None

    proxy = {
        "name": name,
        "type": ptype,
        "server": server,
        "port": port
    }
    if ptype == "vmess":
        uuid = str(node.get("uuid", "")).strip()
        if not uuid:
            return None
        proxy.update({"uuid": uuid, "alterId": node.get("alterId", 0), "cipher": node.get("cipher", "auto"), "tls": bool(node.get("tls")), "network": node.get("network", "tcp")})
    elif ptype == "vless":
        uuid = str(node.get("uuid", "")).strip()
        if not uuid:
            return None
        proxy.update({"uuid": uuid, "cipher": "auto", "tls": bool(node.get("tls")), "servername": node.get("sni", "")})
    elif ptype == "ss":
        cipher = str(node.get("cipher", "aes-256-gcm")).lower().strip()
        pwd = str(node.get("password", "")).strip()
        if not pwd or cipher not in VALID_SS_CIPHERS:
            return None
        proxy.update({"cipher": cipher, "password": pwd})
    elif ptype == "trojan":
        pwd = str(node.get("password", "")).strip()
        if not pwd:
            return None
        proxy.update({"password": pwd, "sni": node.get("sni", "")})
    elif ptype in ["hysteria2", "hy2"]:
        auth = str(node.get("auth") or node.get("password", "")).strip()
        if not auth:
            return None
        proxy.update({"auth": auth, "sni": node.get("sni", "")})
    else:
        return None

    return proxy


def build_merged_clash_config(template_path: Path, crawled_nodes: List[Dict[str, Any]], include_private: bool = True) -> str:
    """
    Build Clash config.
    include_private=True: 包含顶级私有占位节点 (手机, reality 等)
    include_private=False: 纯公开版，无任何私有占位符节点，仅依赖自动爬取节点与负载均衡
    """
    template_content = template_path.read_text(encoding="utf-8", errors="ignore")
    template = yaml.safe_load(template_content)

    # 1. Identify Private Nodes
    if include_private:
        private_proxies = template.get("proxies", [])
        private_proxy_names = [p.get("name") for p in private_proxies if isinstance(p, dict) and p.get("name")]
    else:
        private_proxies = []
        private_proxy_names = []

    # 2. Convert crawled nodes to Clash proxies and ensure 100% UNIQUE proxy names
    crawled_clash_proxies = []
    country_groups: Dict[str, List[str]] = {}

    seen_proxy_names: Set[str] = set(private_proxy_names)

    for node in crawled_nodes:
        pdict = build_clash_proxy_dict(node)
        if not pdict:
            continue
        pname = pdict["name"]

        # 防止节点重名报错 "proxy United States is the duplicate name"
        if pname in seen_proxy_names:
            idx = 1
            new_name = f"{pname} {idx:02d}"
            while new_name in seen_proxy_names:
                idx += 1
                new_name = f"{pname} {idx:02d}"
            pdict["name"] = new_name
            pname = new_name

        seen_proxy_names.add(pname)
        crawled_clash_proxies.append(pdict)

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

    input_files = [
        ROOT_DIR / "output" / "deduped" / "nodes.txt",
        ROOT_DIR / "output" / "raw" / "nodes.txt",
        INPUT_DIR / "nodes.txt",
        ALT_INPUT_DIR / "nodes.txt"
    ]

    nodes_file = None
    for f in input_files:
        if f.exists() and f.stat().st_size > 0:
            nodes_file = f
            break

    crawled_nodes = []
    if nodes_file and nodes_file.exists():
        content = nodes_file.read_text(encoding="utf-8", errors="ignore")
        crawled_nodes = extract_node_links_from_text(content)

    print(f"Loaded {len(crawled_nodes)} Crawled Verified Nodes.", flush=True)

    # 1. 生成绝对纯净、0 节点的纯规则文件 (电脑全量纯规则 & 手机精炼纯规则)
    if FULL_TEMPLATE_FILE.exists():
        rules_only_yaml = build_rules_only_clash_config(FULL_TEMPLATE_FILE)
        OUTPUT_RULES_ONLY_CLASH.write_text(rules_only_yaml, encoding="utf-8")
        print(f"Successfully generated Pure Rules-Only Config -> {OUTPUT_RULES_ONLY_CLASH}", flush=True)

    if ELITE_TEMPLATE_FILE.exists():
        mobile_rules_only_yaml = build_rules_only_clash_config(ELITE_TEMPLATE_FILE)
        OUTPUT_MOBILE_RULES_ONLY_CLASH.write_text(mobile_rules_only_yaml, encoding="utf-8")
        print(f"Successfully generated Pure Mobile Rules-Only Config -> {OUTPUT_MOBILE_RULES_ONLY_CLASH}", flush=True)

    # 2. 传统带节点版本生成
    if FULL_TEMPLATE_FILE.exists():
        full_yaml = build_merged_clash_config(FULL_TEMPLATE_FILE, crawled_nodes, include_private=True)
        OUTPUT_RULES_CLASH.write_text(full_yaml, encoding="utf-8")
        print(f"Successfully generated Full Private Clash Config -> {OUTPUT_RULES_CLASH}", flush=True)

        public_full_yaml = build_merged_clash_config(FULL_TEMPLATE_FILE, crawled_nodes, include_private=False)
        OUTPUT_PUBLIC_RULES_CLASH.write_text(public_full_yaml, encoding="utf-8")
        print(f"Successfully generated Full Public Clash Config -> {OUTPUT_PUBLIC_RULES_CLASH}", flush=True)

    if ELITE_TEMPLATE_FILE.exists():
        elite_yaml = build_merged_clash_config(ELITE_TEMPLATE_FILE, crawled_nodes, include_private=True)
        OUTPUT_ELITE_RULES_CLASH.write_text(elite_yaml, encoding="utf-8")
        print(f"Successfully generated Elite Private Clash Config -> {OUTPUT_ELITE_RULES_CLASH}", flush=True)

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

    # 4. 独立 FakeLocation 社交 App 定位专享版 (私有版与纯公开版)
    if FAKELOCATION_TEMPLATE_FILE.exists():
        fl_yaml = build_merged_clash_config(FAKELOCATION_TEMPLATE_FILE, crawled_nodes, include_private=True)
        OUTPUT_FAKELOCATION_RULES_CLASH.write_text(fl_yaml, encoding="utf-8")
        print(f"Successfully generated Private FakeLocation Clash Config -> {OUTPUT_FAKELOCATION_RULES_CLASH}", flush=True)

        public_fl_yaml = build_merged_clash_config(FAKELOCATION_TEMPLATE_FILE, crawled_nodes, include_private=False)
        OUTPUT_PUBLIC_FAKELOCATION_RULES_CLASH.write_text(public_fl_yaml, encoding="utf-8")
        print(f"Successfully generated Public FakeLocation Clash Config -> {OUTPUT_PUBLIC_FAKELOCATION_RULES_CLASH}", flush=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
