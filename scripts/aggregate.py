from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

import yaml

from common import ROOT_DIR, export_stage_files, extract_node_links_from_text, sanitize_node

CONFIG_FILE = ROOT_DIR / "config" / "sources.json"
OUTPUT_DIR = ROOT_DIR / "output" / "raw"

# Shadowsocks 标准合法加密算法白名单（拦截乱码）
VALID_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}


def is_valid_node(node: Dict[str, Any]) -> bool:
    """过滤含有非法乱码属性的坏节点"""
    ntype = str(node.get("type", "")).lower()
    if ntype == "ss":
        cipher = str(node.get("cipher", "")).lower()
        if cipher not in VALID_SS_CIPHERS:
            return False
    return True


def fetch_remote_url(url: str, timeout: int = 5) -> str:
    """Safely fetch remote HTTP subscription URL content."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception:
        return ""


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
                if not is_valid_node(node):
                    continue
                sanitized = sanitize_node(node)
                if sanitized and is_valid_node(sanitized):
                    nodes.append(sanitized)
    except Exception:
        pass
    return nodes


def filter_and_sanitize_nodes(raw_nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """过滤非法节点"""
    valid = []
    for node in raw_nodes:
        if isinstance(node, dict) and is_valid_node(node):
            valid.append(node)
    return valid


def scan_single_source(source: dict) -> tuple[dict, list[dict]]:
    """Scan a single repository source concurrently."""
    sname = source.get("name")
    spath = ROOT_DIR / source.get("path")
    nodes = []

    if spath.exists():
        for root, _, files in os.walk(spath):
            if ".git" in root:
                continue
            for file in files:
                file_path = Path(root) / file
                if file.endswith((".yaml", ".yml")):
                    nodes.extend(parse_clash_yaml_file(file_path))
                elif file.endswith((".txt", ".json", ".md", ".sub", ".link")):
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        extracted = extract_node_links_from_text(content)
                        nodes.extend(filter_and_sanitize_nodes(extracted))

                        urls = re.findall(r"https?://[^\s\"'\)>]+\.(?:yaml|yml|txt|sub)", content)
                        for url in urls[:5]:
                            res_text = fetch_remote_url(url)
                            if res_text:
                                remote_nodes = extract_node_links_from_text(res_text)
                                nodes.extend(filter_and_sanitize_nodes(remote_nodes))
                    except Exception:
                        pass

    stat = {"source": sname, "path": str(spath), "found_nodes": len(nodes)}
    return stat, nodes


def make_nodes_compact_and_unique(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """生成全局独一无二的极短后缀命名，绝不超长，杜绝 duplicate name"""
    seen_names = set()
    unique_nodes = []

    for node in nodes:
        raw_name = str(node.get("name", "Proxy")).strip()
        # 裁剪原名长度，保留美观性
        clean_name = raw_name[:24]

        # 基于核心网络参数生成 4 位十六进制短指纹
        ptype = str(node.get("type", "")).lower()
        server = str(node.get("server", "")).strip().lower()
        port = str(node.get("port", ""))
        pwd = str(node.get("uuid") or node.get("password") or "").strip()

        fp = hashlib.md5(f"{ptype}{pwd}{server}{port}".encode("utf-8")).hexdigest()[:4].upper()
        unique_name = f"{clean_name} #{fp}"

        # 极端防碰撞保险
        suffix = 1
        while unique_name in seen_names:
            unique_name = f"{clean_name} #{fp}{suffix}"
            suffix += 1

        seen_names.add(unique_name)
        node["name"] = unique_name
        if "raw_proxy_dict" in node and isinstance(node["raw_proxy_dict"], dict):
            node["raw_proxy_dict"]["name"] = unique_name

        unique_nodes.append(node)

    return unique_nodes


def main() -> int:
    print("=== Stage 1: 32-Worker Max-Speed Parallel Repository Aggregation ===", flush=True)
    if not CONFIG_FILE.exists():
        print(f"Error: Config file {CONFIG_FILE} not found.", flush=True)
        return 1

    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    sources = config.get("sources", [])

    all_raw_nodes: List[Dict[str, Any]] = []
    source_stats = []

    print(f"Scanning {len(sources)} repositories in parallel with 32 workers...", flush=True)
    with ThreadPoolExecutor(max_workers=32) as executor:
        futures = {executor.submit(scan_single_source, src): src for src in sources}
        for future in as_completed(futures):
            stat, nodes = future.result()
            all_raw_nodes.extend(nodes)
            source_stats.append(stat)
            print(f"  [+] [{stat['source']}] Found {len(nodes)} nodes", flush=True)

    # 1. 过滤乱码加密算法
    all_raw_nodes = [n for n in all_raw_nodes if is_valid_node(n)]

    # 2. 全局短后缀唯一命名（仅增 6 字符，如 "🇭🇰 香港 #8F2A"）
    all_raw_nodes = make_nodes_compact_and_unique(all_raw_nodes)

    print(f"Stage 1 Total Raw Aggregated Nodes: {len(all_raw_nodes)}", flush=True)

    # Export all 5 standard formats to output/raw/
    export_stage_files(
        output_dir=OUTPUT_DIR,
        nodes=all_raw_nodes,
        stage_title="Stage 1 - Raw Aggregation",
        extra_data={"sources": source_stats}
    )
    print(f"Successfully exported Stage 1 output to {OUTPUT_DIR}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
