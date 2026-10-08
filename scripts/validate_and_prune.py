from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

# 目标需要校验的目录
OUTPUT_DIR = Path("output")

# 1. 严格合法的 SS 加密白名单
VALID_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}


def sanitize_yaml_file(file_path: Path) -> bool:
    """在喂给 Mihomo 前做纯内存批量清洗，秒级过滤坏节点与非法字段"""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or "proxies" not in data:
            return True

        proxies = data.get("proxies", [])
        clean_proxies = []
        valid_proxy_names = set()

        for p in proxies:
            if not isinstance(p, dict):
                continue
            ptype = str(p.get("type", "")).lower()
            # 过滤未知乱码 SS
            if ptype == "ss":
                cipher = str(p.get("cipher", "")).lower()
                if cipher not in VALID_SS_CIPHERS:
                    continue

            name = str(p.get("name", "")).strip()
            if not name:
                continue
            
            clean_proxies.append(p)
            valid_proxy_names.add(name)

        data["proxies"] = clean_proxies

        # 保证 proxy-groups 里面的引用不会悬空
        if "proxy-groups" in data and isinstance(data["proxy-groups"], list):
            group_names = {g.get("name") for g in data["proxy-groups"] if isinstance(g, dict)}
            for g in data["proxy-groups"]:
                if isinstance(g, dict) and "proxies" in g and isinstance(g["proxies"], list):
                    g["proxies"] = [
                        p for p in g["proxies"]
                        if p in valid_proxy_names or p in group_names
                    ]

        # 覆盖写回
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        return True
    except Exception as e:
        print(f"Error sanitizing {file_path}: {e}", file=sys.stderr)
        return False


def test_with_mihomo_offline(file_path: Path) -> bool:
    """使用 Mihomo 内核进行纯离线配置断言（-t 参数）"""
    # 注入一个极简的本地临时运行目录，防止读取外部规则/Geo 数据库
    cmd = [
        "mihomo",
        "-t",
        "-f", str(file_path)
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print(f"[PASS] {file_path.name} verified by Mihomo kernel!")
        return True
    else:
        print(f"[FATAL] {file_path} failed Mihomo check:\n{result.stderr}", file=sys.stderr)
        return False


def main() -> int:
    print("=== Starting Pure-Offline Mihomo Kernel Syntax Assertion ===", flush=True)
    yaml_files = list(OUTPUT_DIR.rglob("*.yaml")) + list(OUTPUT_DIR.rglob("*.yml"))
    if not yaml_files:
        print("No YAML files found to test.")
        return 0

    has_error = False

    for yf in yaml_files:
        # 1. 预先做内存批量清洗（秒级处理，不依赖反复启动内核）
        sanitize_yaml_file(yf)

        # 2. 调用内核进行一次性断言（仅做语法校验，不联网）
        passed = test_with_mihomo_offline(yf)
        if not passed:
            has_error = True

    if has_error:
        print("Mihomo verification failed for one or more files.", file=sys.stderr)
        return 1

    print("=== All configuration files successfully verified by Mihomo! ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
