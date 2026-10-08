from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
import yaml

OUTPUT_DIR = Path("output")

VALID_SS_CIPHERS = {
    "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
    "rc4-md5", "chacha20-ietf",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"
}

def auto_repair_clash_structure(file_path: Path) -> dict | None:
    """自动修复骨架缺失与脏节点，确保结构符合 Mihomo 规范"""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return None

        # 1. 补齐 Mihomo 最低骨架要求，避免缺失基础字段直接报 fatal
        if "mode" not in data:
            data["mode"] = "rule"
        if "proxies" not in data or not isinstance(data["proxies"], list):
            data["proxies"] = []
        if "proxy-groups" not in data or not isinstance(data["proxy-groups"], list):
            data["proxy-groups"] = []
        if "rules" not in data or not isinstance(data["rules"], list):
            data["rules"] = ["MATCH,DIRECT"]

        # 2. 清洗坏节点 (加密乱码、无名称、缺服务器)
        valid_proxies = []
        valid_names = set()
        for p in data["proxies"]:
            if not isinstance(p, dict):
                continue
            ptype = str(p.get("type", "")).lower()
            name = str(p.get("name", "")).strip()
            server = str(p.get("server", "")).strip()

            if not name or not server:
                continue
            if ptype == "ss" and str(p.get("cipher", "")).lower() not in VALID_SS_CIPHERS:
                continue

            valid_proxies.append(p)
            valid_names.add(name)

        data["proxies"] = valid_proxies

        # 3. 校验 proxy-groups，移除引用了不存在节点的悬空代理名
        group_names = {g.get("name") for g in data["proxy-groups"] if isinstance(g, dict)}
        builtin_targets = {"DIRECT", "REJECT", "GLOBAL"}

        clean_groups = []
        for g in data["proxy-groups"]:
            if not isinstance(g, dict) or not g.get("name"):
                continue
            g_proxies = g.get("proxies", [])
            if isinstance(g_proxies, list):
                # 过滤出真实存在的节点、策略组或内置策略
                g["proxies"] = [
                    px for px in g_proxies
                    if px in valid_names or px in group_names or px in builtin_targets
                ]
            # 策略组若空了，至少塞一个 DIRECT，防止 Mihomo 抛 empty proxy group
            if not g.get("proxies"):
                g["proxies"] = ["DIRECT"]
            clean_groups.append(g)

        data["proxy-groups"] = clean_groups

        # 4. 校验 rules，避免出现指向不存在 group 的坏规则
        all_available_targets = valid_names | group_names | builtin_targets
        clean_rules = []
        for r in data["rules"]:
            if not isinstance(r, str):
                continue
            parts = [seg.strip() for seg in r.split(",")]
            if len(parts) >= 2:
                target = parts[-1]  # 规则终点
                # 如果 target 既不是节点也不是策略组，改降级为 DIRECT，避免整条规则报崩
                if target not in all_available_targets:
                    parts[-1] = "DIRECT"
                    clean_rules.append(",".join(parts))
                else:
                    clean_rules.append(r)
            else:
                clean_rules.append(r)

        data["rules"] = clean_rules

        # 写回修复后的配置
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        return data
    except Exception as e:
        print(f"[REPAIR ERROR] {file_path.name}: {e}", file=sys.stderr)
        return None

def test_mihomo_offline(file_path: Path) -> bool:
    """执行 Mihomo 语法校验并打印真实错误日志"""
    cmd = ["mihomo", "-t", "-f", str(file_path)]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print(f"[PASS] {file_path.name} verified by Mihomo kernel!")
        return True

    # 打印真实的失败原因（排查到底是哪一行、什么 key 触发了 fatal）
    err_msg = result.stderr.strip() or result.stdout.strip()
    print(f"[FATAL] {file_path} failed Mihomo check:\n>>> {err_msg}", file=sys.stderr)
    return False

def main() -> int:
    print("=== Starting Pure-Offline Mihomo Kernel Syntax Assertion & Auto-Repair ===", flush=True)
    yaml_files = list(OUTPUT_DIR.rglob("*.yaml")) + list(OUTPUT_DIR.rglob("*.yml"))
    if not yaml_files:
        print("No YAML files found.")
        return 0

    has_error = False
    for yf in yaml_files:
        # 第一阶段：自动修复缺失字段、空 group 与坏规则
        auto_repair_clash_structure(yf)

        # 第二阶段：内核离线复检
        if not test_mihomo_offline(yf):
            has_error = True

    if has_error:
        print("Mihomo verification failed after repair.", file=sys.stderr)
        return 1

    print("=== All configuration files successfully verified! ===", flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
