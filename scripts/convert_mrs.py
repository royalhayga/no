from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_DIR = ROOT_DIR / "config"
OUTPUT_DIR = ROOT_DIR / "output"
MRS_OUTPUT_DIR = OUTPUT_DIR / "mrs"
MRS_DOMAIN_DIR = MRS_OUTPUT_DIR / "domain"
MRS_IP_DIR = MRS_OUTPUT_DIR / "ip"

# 确保输出目录存在
MRS_DOMAIN_DIR.mkdir(parents=True, exist_ok=True)
MRS_IP_DIR.mkdir(parents=True, exist_ok=True)

MIHOMO_BIN = shutil.which("mihomo") or "mihomo"


def is_ip_cidr(text: str) -> bool:
    """判断字符串是否为 IP CIDR 格式"""
    text = text.strip()
    if "/" in text:
        ip_part = text.split("/")[0]
        # 简单正则匹配 IPv4/IPv6
        if re.match(r"^[\d\.]+$", ip_part) or ":" in ip_part:
            return True
    return False


def classify_rules(lines: List[str]) -> Tuple[List[str], List[str]]:
    """拆分规则列表为 (域名规则列表, IP 规则列表)"""
    domains: List[str] = []
    ips: List[str] = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 剥离前缀格式如 - DOMAIN,example.com 或 DOMAIN-SUFFIX,example.com
        if line.startswith("-"):
            line = line.lstrip("-").strip()

        # 处理 TYPE,value 拆分
        if "," in line:
            parts = [p.strip() for p in line.split(",")]
            rtype = parts[0].upper()
            val = parts[1] if len(parts) > 1 else ""

            if rtype in ["IP-CIDR", "IP-CIDR6", "GEOIP"]:
                ips.append(val)
            elif rtype in ["DOMAIN", "DOMAIN-SUFFIX"]:
                domains.append(val)
            elif rtype == "DOMAIN-KEYWORD":
                # Keyword 不转纯域名，但可保留域名格式
                domains.append(val)
            else:
                if is_ip_cidr(val):
                    ips.append(val)
                elif val:
                    domains.append(val)
        else:
            # 纯文本列表 (如纯域名或纯 IP)
            if is_ip_cidr(line):
                ips.append(line)
            else:
                domains.append(line)

    return sorted(list(set(domains))), sorted(list(set(ips)))


def compile_to_mrs(behavior: str, input_file: Path, output_file: Path) -> bool:
    """调用 mihomo CLI 将文本规则转化为 .mrs 二进制规则集"""
    if not input_file.exists() or input_file.stat().st_size == 0:
        return False

    cmd = [MIHOMO_BIN, "convert-ruleset", behavior, "text", str(input_file), str(output_file)]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[MRS OK] Built {behavior} -> {output_file.name} ({output_file.stat().st_size} bytes)", flush=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[MRS FAIL] Failed to compile {input_file.name}: {e}", flush=True)
        return False


def process_yaml_file(yaml_path: Path):
    """解析 YAML 配置文件，按 Provider 或 规则拆分生成 .mrs"""
    if not yaml_path.exists():
        return

    print(f"=== Processing YAML: {yaml_path.name} ===", flush=True)
    try:
        content = yaml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
    except Exception as e:
        print(f"Error reading {yaml_path}: {e}", flush=True)
        return

    # 1. 拆分 YAML 内部直接定义的 rules:
    raw_rules = data.get("rules", [])
    if raw_rules:
        domains, ips = classify_rules([str(r) for r in raw_rules])

        prefix = yaml_path.stem.replace(".yaml", "").replace(".yml", "")

        if domains:
            tmp_domain_file = MRS_OUTPUT_DIR / f"_tmp_{prefix}_domains.txt"
            tmp_domain_file.write_text("\n".join(domains), encoding="utf-8")
            compile_to_mrs("domain", tmp_domain_file, MRS_DOMAIN_DIR / f"{prefix}_rules.mrs")
            tmp_domain_file.unlink(missing_ok=True)

        if ips:
            tmp_ip_file = MRS_OUTPUT_DIR / f"_tmp_{prefix}_ips.txt"
            tmp_ip_file.write_text("\n".join(ips), encoding="utf-8")
            compile_to_mrs("ipcidr", tmp_ip_file, MRS_IP_DIR / f"{prefix}_ip_rules.mrs")
            tmp_ip_file.unlink(missing_ok=True)


def main() -> int:
    print("=== Independent MRS Automated Converter Engine ===", flush=True)
    print(f"Domain MRS Dir: {MRS_DOMAIN_DIR}", flush=True)
    print(f"IP CIDR MRS Dir: {MRS_IP_DIR}", flush=True)

    # 处理 config 目录下的所有模版与规则
    for yaml_file in CONFIG_DIR.glob("*.yaml"):
        process_yaml_file(yaml_file)

    # 处理 output 目录下的产物规则
    for yaml_file in OUTPUT_DIR.glob("*.yaml"):
        process_yaml_file(yaml_file)

    print("=== MRS Automated Conversion Completed Successfully ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
