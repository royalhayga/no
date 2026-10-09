from __future__ import annotations

import os
import re
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
    """自动修复骨架缺失、脏节点、VMess加密字段缺失及 MRS 格式，确保 100% 符合 Mihomo 规范"""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = yaml.safe_load(content)
        if not isinstance(data, dict):
            return None

        # 1. 补齐 Mihomo 最低骨架要求
        if "mode" not in data:
            data["mode"] = "rule"
        if "proxies" not in data or not isinstance(data["proxies"], list):
            data["proxies"] = []
        if "proxy-groups" not in data or not isinstance(data["proxy-groups"], list):
            data["proxy-groups"] = []
        if "rules" not in data or not isinstance(data["rules"], list):
            data["rules"] = ["MATCH,DIRECT"]

        # 2. 清洗坏节点 & 修复 VMess cipher & 保证节点名称 100% 唯一 (解决 duplicate name)
        valid_proxies = []
        seen_names = set()

        for p in data["proxies"]:
            if not isinstance(p, dict):
                continue
            ptype = str(p.get("type", "")).lower().strip()
            server = str(p.get("server", "")).strip()

            if not server:
                continue

            # VMess 缺加密算法修复
            if ptype == "vmess":
                if not p.get("cipher") or str(p.get("cipher")).strip() == "":
                    p["cipher"] = "auto"

            # SS 非法加密算法剔除
            if ptype == "ss" and str(p.get("cipher", "")).lower() not in VALID_SS_CIPHERS:
                continue

            # 自动唯一定义节点名称
            base_name = str(p.get("name") or "Node").strip()
            candidate = base_name
            idx = 2
            while candidate in seen_names:
                candidate = f"{base_name} #{idx}"
                idx += 1
            seen_names.add(candidate)
            p["name"] = candidate

            valid_proxies.append(p)

        data["proxies"] = valid_proxies
        valid_names = seen_names

        # 3. 修复 rule-providers 里的 format: mrs (兼容普通 Mihomo 二进制)
        rule_providers = data.get("rule-providers", {})
        if isinstance(rule_providers, dict):
            for rp_name, rp_val in rule_providers.items():
                if isinstance(rp_val, dict) and rp_val.get("format") == "mrs":
                    rp_val["format"] = "text" if rp_val.get("behavior") == "domain" else "yaml"
                    if rp_val.get("url", "").endswith(".mrs"):
                        rp_val["url"] = rp_val["url"].replace(".mrs", ".yaml").replace(".txt", ".yaml")
                        rp_val["path"] = rp_val["path"].replace(".mrs", ".yaml")

        # 4. 校验 proxy-groups，移除引用了不存在节点的悬空代理名
        group_names = {g.get("name") for g in data["proxy-groups"] if isinstance(g, dict)}
        builtin_targets = {"DIRECT", "REJECT", "GLOBAL"}

        clean_groups = []
        for g in data["proxy-groups"]:
            if not isinstance(g, dict) or not g.get("name"):
                continue
            g_proxies = g.get("proxies", [])
            if isinstance(g_proxies, list):
                g["proxies"] = [
                    px for px in g_proxies
                    if px in valid_names or px in group_names or px in builtin_targets
                ]
            if not g.get("proxies"):
                g["proxies"] = ["DIRECT"]
            clean_groups.append(g)

        data["proxy-groups"] = clean_groups

        # 5. 校验 rules (精准解析带/不带 no-resolve 的策略组目标)
        all_available_targets = valid_names | group_names | builtin_targets
        clean_rules = []
        for r in data["rules"]:
            if not isinstance(r, str):
                continue
            parts = [seg.strip() for seg in r.split(",")]
            if len(parts) >= 2:
                # 准确获取策略组/节点目标 (处理带 no-resolve 的 4 段规则)
                target = parts[-2] if parts[-1] == "no-resolve" and len(parts) >= 3 else parts[-1]
                if target not in all_available_targets:
                    if parts[-1] == "no-resolve" and len(parts) >= 3:
                        parts[-2] = "DIRECT"
                    else:
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


def prune_failing_proxies(file_path: Path, err_msg: str) -> bool:
    """动态解析 Mihomo 报错日志并精确剔除损坏节点或代理组"""
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = yaml.safe_load(content) or {}
        proxies = data.get("proxies", [])
        if not proxies:
            return False

        indices_to_remove = set()
        names_to_remove = set()

        # 匹配: proxy 488: vmess: unsupported security type: ""
        for match in re.finditer(r"proxy\s+(\d+):", err_msg):
            idx = int(match.group(1))
            if 0 <= idx < len(proxies):
                indices_to_remove.add(idx)

        # 匹配: proxy 'xxx' is the duplicate name
        for match in re.finditer(r"proxy\s+'?([^']+)'?\s+is the duplicate name", err_msg):
            names_to_remove.add(match.group(1).strip())

        # 匹配: proxy [xxx] not found
        for match in re.finditer(r"proxy\s+\[?([^\]]+)\]?\s+not found", err_msg):
            names_to_remove.add(match.group(1).strip())

        for i, p in enumerate(proxies):
            if isinstance(p, dict) and p.get("name") in names_to_remove:
                indices_to_remove.add(i)

        if not indices_to_remove:
            return False

        data["proxies"] = [p for i, p in enumerate(proxies) if i not in indices_to_remove]
        with open(file_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f, allow_unicode=True, sort_keys=False)
        print(f"[PRUNE OK] Dynamically removed {len(indices_to_remove)} failing proxies from {file_path.name}", flush=True)
        return True
    except Exception as e:
        print(f"[PRUNE FAIL] {file_path.name}: {e}", file=sys.stderr)
        return False


def test_mihomo_offline(file_path: Path) -> bool:
    """执行 Mihomo 语法校验并在失败时尝试迭代修复剔除"""
    cmd = ["mihomo", "-t", "-f", str(file_path)]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        print(f"[PASS] {file_path.name} verified by Mihomo kernel!")
        return True

    err_msg = result.stderr.strip() or result.stdout.strip()

    # 尝试多轮动态剔除重试
    for attempt in range(1, 5):
        if prune_failing_proxies(file_path, err_msg):
            auto_repair_clash_structure(file_path)
            res2 = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res2.returncode == 0:
                print(f"[RE-PASS] {file_path.name} verified after dynamic prune round {attempt}!")
                return True
            err_msg = res2.stderr.strip() or res2.stdout.strip()

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
        # 第一阶段：自动修复缺失字段、空 group、VMess cipher 与 MRS 格式
        auto_repair_clash_structure(yf)

        # 第二阶段：内核离线复检 (带动态剔除)
        if not test_mihomo_offline(yf):
            has_error = True

    if has_error:
        print("Mihomo verification failed after repair.", file=sys.stderr)
        return 1

    print("=== All configuration files successfully verified! ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
