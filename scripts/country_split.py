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

LOCAL_MMDB_PATHS = [
    ROOT_DIR / "GeoLite2-Country.mmdb",
    ROOT_DIR / "Country.mmdb",
    ROOT_DIR / "ref" / "SubCrawler" / "src" / "main" / "resources" / "GeoLite2-Country.mmdb",
    ROOT_DIR / "ref" / "mianfeijiedian" / "src" / "main" / "resources" / "GeoLite2-Country.mmdb",
    ROOT_DIR / "ref" / "NiceVPN" / "utils" / "clashcheck" / "Country.mmdb",
]


def calculate_node_quality_score(node: Dict[str, Any]) -> int:
    """计算节点的纯离线质量分 (Offline Quality Score)"""
    score = 0
    ptype = str(node.get("type", "")).lower().strip()
    port = node.get("port", 0)
    sni = str(node.get("sni") or "").lower().strip()

    # 1. 协议类型得分
    if ptype in ["hysteria2", "hy2"]:
        score += 100
    elif ptype == "vless":
        score += 90
    elif ptype == "trojan":
        score += 80
    elif ptype == "vmess":
        score += 60
    else:
        score += 30

    # 2. 优质 TLS 端口得分 (443, 8443, 2053, 2083, 2087, 2096, 2052, 2082, 2086, 8880)
    if port in {443, 8443, 2053, 2083, 2087, 2096, 2052, 2082, 2086, 8880}:
        score += 20

    # 3. TLS / SNI 域名加分
    if bool(node.get("tls")) or sni:
        score += 15
        if any(domain in sni for domain in ["cloudflare", "aws", "amazon", "google", "fastly", "azure"]):
            score += 15

    return score


def lookup_local_mmdb_ip(ip_str: str) -> Tuple[str, str] | None:
    """100% Local Offline GeoIP Lookup using local GeoLite2-Country.mmdb binary database."""
    for mmdb_p in LOCAL_MMDB_PATHS:
        if mmdb_p.exists() and mmdb_p.stat().st_size > 1000000:
            try:
                import maxminddb
                with maxminddb.open_database(str(mmdb_p)) as reader:
                    res = reader.get(ip_str) or {}
                    code = res.get("country", {}).get("iso_code") or res.get("registered_country", {}).get("iso_code") or "OTHER"
                    name = res.get("country", {}).get("names", {}).get("zh-CN") or res.get("country", {}).get("names", {}).get("en") or "Unknown"
                    return code.upper(), name
            except Exception:
                pass
    return None


def infer_country_from_text_or_ip(server: str, name: str) -> Tuple[str, str]:
    """100% Pure Offline Local Country Categorization."""
    clean_server = server.strip().lower()

    if clean_server.replace(".", "").isdigit():
        geo_res = lookup_local_mmdb_ip(clean_server)
        if geo_res and geo_res[0] != "OTHER":
            code = geo_res[0]
            zh_name = COUNTRY_NAMES_ZH.get(code, f"{code}节点")
            return code, zh_name

    domain_tld_map = {
        ".ir": "IR", ".hk": "HK", ".tw": "TW", ".jp": "JP", ".sg": "SG", ".us": "US",
        ".kr": "KR", ".de": "DE", ".uk": "UK", ".ca": "CA", ".fr": "FR", ".au": "AU",
        ".nl": "NL", ".ru": "RU", ".in": "IN", ".br": "BR", ".it": "IT", ".es": "ES",
        ".se": "SE", ".no": "NO", ".fi": "FI", ".tr": "TR", ".pl": "PL", ".ua": "UA",
        ".th": "TH", ".vn": "VN", ".id": "ID", ".my": "MY", ".ph": "PH", ".pk": "PK"
    }
    for tld, c_code in domain_tld_map.items():
        if clean_server.endswith(tld) or f"{tld}." in clean_server:
            return c_code, COUNTRY_NAMES_ZH.get(c_code, f"{c_code}节点")

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
        ("BR", ["BR", "BRAZIL", "巴西"]),
        ("IR", ["IR", "IRAN", "伊朗", "APARAT"]),
        ("IT", ["IT", "ITALY", "意大利"]),
        ("ES", ["ES", "SPAIN", "西班牙"]),
        ("SE", ["SE", "SWEDEN", "瑞典"]),
        ("TR", ["TR", "TURKEY", "土耳其"]),
        ("UA", ["UA", "UKRAINE", "乌克兰"]),
        ("PL", ["PL", "POLAND", "波兰"]),
        ("VN", ["VN", "VIETNAM", "越南"]),
        ("TH", ["TH", "THAILAND", "泰国"]),
        ("ID", ["ID", "INDONESIA", "印尼", "印度尼西亚"]),
        ("MY", ["MY", "MALAYSIA", "马来西亚"]),
        ("PH", ["PH", "PHILIPPINES", "菲律宾"])
    ]

    for code, kw_list in keywords:
        if any(kw in text for kw in kw_list):
            return code, COUNTRY_NAMES_ZH.get(code, f"{code}节点")

    return "OTHER", "其他地区"


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
    print("=== Stage 6: 100% Pure Offline Quality Scoring & SS Separation ===", flush=True)

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
    raw_nodes = extract_node_links_from_text(content)
    print(f"Loaded {len(raw_nodes)} raw verified nodes.", flush=True)

    # 1. 彻底分离 SS 节点并独立保存到 output/ss_nodes.txt
    ss_nodes = [n for n in raw_nodes if str(n.get("type", "")).lower().strip() == "ss"]
    non_ss_nodes = [n for n in raw_nodes if str(n.get("type", "")).lower().strip() != "ss"]

    print(f"Separated {len(ss_nodes)} Shadowsocks (SS) nodes into standalone export.", flush=True)
    ss_export_text = "\n".join([reconstruct_node_link(n) for n in ss_nodes if reconstruct_node_link(n)])
    (ROOT_OUTPUT_DIR / "ss_nodes.txt").write_text(ss_export_text, encoding="utf-8")

    # 2. 对非 SS 节点（VLess, Hysteria2, Trojan, VMess）计算离线质量分并精准排序
    scored_nodes = []
    for n in non_ss_nodes:
        n_copy = dict(n)
        score = calculate_node_quality_score(n_copy)
        n_copy["quality_score"] = score
        scored_nodes.append(n_copy)

    # 3. 按国家分组并实施“配额离线截断”，保持精选 500 顶流节点
    raw_country_groups: Dict[str, List[Dict[str, Any]]] = {}

    for n in scored_nodes:
        srv = str(n.get("server", "")).strip()
        raw_name = str(n.get("name", "")).strip()

        code, country_name = infer_country_from_text_or_ip(srv, raw_name)
        if code not in raw_country_groups:
            raw_country_groups[code] = []

        n["country_code"] = code
        n["country"] = country_name
        raw_country_groups[code].append(n)

    country_groups: Dict[str, List[Dict[str, Any]]] = {}
    country_counters: Dict[str, int] = {}
    all_country_categorized_nodes = []

    # 各国最高配额 (热门国家最多 35-40 个，冷门地区最多 15 个，保持全盘 ~500 节点)
    tier1_codes = {"US", "JP", "HK", "SG", "DE", "UK", "TW", "KR", "CA", "AU"}

    for code, group_nodes in raw_country_groups.items():
        # 组内按质量分降序排列，得分最高的前置
        group_nodes.sort(key=lambda x: x.get("quality_score", 0), reverse=True)

        quota = 35 if code in tier1_codes else 15
        selected_nodes = group_nodes[:quota]

        country_groups[code] = []
        country_counters[code] = 0

        for n in selected_nodes:
            country_counters[code] += 1
            flag = COUNTRY_FLAGS.get(code, "🌐")
            country_name = n["country"]

            n_copy = dict(n)
            n_copy["name"] = f"{flag} {country_name} {country_counters[code]:02d}"
            country_groups[code].append(n_copy)
            all_country_categorized_nodes.append(n_copy)

    print(f"Selected {len(all_country_categorized_nodes)} Premium Top-Tier Nodes across {len(country_groups)} countries.", flush=True)

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

    print(f"Successfully exported 100% offline premium country-categorized configs to {OUTPUT_DIR} and {ROOT_OUTPUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
