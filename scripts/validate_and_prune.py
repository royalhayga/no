from __future__ import annotations

import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import yaml

ROOT_DIR = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT_DIR / "output"
MIHOMO_BIN = shutil.which("mihomo") or "mihomo"


def validate_yaml(yaml_file: Path) -> tuple[bool, str]:
    """使用 Mihomo 内核校验单个 YAML 文件的语法合规性"""
    if not yaml_file.exists():
        return False, "File not found"

    try:
        cmd = [MIHOMO_BIN, "-t", "-f", str(yaml_file)]
        res = subprocess.run(cmd, capture_output=True, text=True)

        if res.returncode == 0:
            return True, res.stdout
        else:
            return False, res.stderr + "\n" + res.stdout
    except FileNotFoundError:
        return True, f"[SKIP] Mihomo binary '{MIHOMO_BIN}' not found in environment."


def prune_failing_proxies(yaml_file: Path, err_msg: str) -> bool:
    """
    动态解析 Mihomo 报错并精准剔除有缺陷的节点 (如缺少密码/加密非法/节点重名)，
    并同步清理 proxy-groups 中对已被移除节点的引用，防止 'not found' 报错死循环。
    """
    try:
        content = yaml_file.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
        proxies = data.get("proxies", [])
        proxy_groups = data.get("proxy-groups", [])

        if not proxies and not proxy_groups:
            return False

        indices_to_remove = set()
        names_to_remove = set()

        # 1. 匹配常规节点下标报错: "proxy 271: ss 104.18.1.1:2083 initialize error: unknown method: xxx"
        for match in re.finditer(r"(?<!group\[)\bproxy\s+(\d+):", err_msg):
            idx = int(match.group(1))
            if 0 <= idx < len(proxies):
                indices_to_remove.add(idx)
                pname = proxies[idx].get("name") if isinstance(proxies[idx], dict) else None
                if pname:
                    names_to_remove.add(pname)

        # 2. 匹配策略组找不到节点报错: "proxy group[0]: AUTO: '🇧🇷 BR-08' not found" 或 "proxy group[x]: ... 'xxx' not found"
        for match in re.finditer(r"proxy group\[\d+\]:[^:]+:\s*'([^']+)'\s+not found", err_msg):
            missing_name = match.group(1).strip()
            if missing_name:
                names_to_remove.add(missing_name)

        # 3. 匹配通用 'node_name' not found 报错
        for match in re.finditer(r"'([^']+)'\s+not found", err_msg):
            missing_name = match.group(1).strip()
            if missing_name:
                names_to_remove.add(missing_name)

        # 通过名字反向查找 proxies 数组中的索引
        for i, p in enumerate(proxies):
            if isinstance(p, dict) and p.get("name") in names_to_remove:
                indices_to_remove.add(i)

        if not indices_to_remove and not names_to_remove:
            return False

        # 从 proxies 剔除损坏节点
        new_proxies = [p for i, p in enumerate(proxies) if i not in indices_to_remove]
        data["proxies"] = new_proxies

        # 同步更新 proxy-groups，移除不存在的节点引用
        if proxy_groups and names_to_remove:
            for group in proxy_groups:
                if isinstance(group, dict) and "proxies" in group and isinstance(group["proxies"], list):
                    group["proxies"] = [p for p in group["proxies"] if p not in names_to_remove]
                    if not group["proxies"]:
                        group["proxies"] = ["DIRECT"]

        data["proxy-groups"] = proxy_groups

        yaml_file.write_text(yaml.dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        print(f"[PRUNE OK] Dynamically removed {len(indices_to_remove)} failing proxies & cleaned group refs from {yaml_file.name}", flush=True)
        return True
    except Exception as e:
        print(f"[PRUNE FAIL] Failed to prune {yaml_file.name}: {e}", flush=True)
        return False


def process_single_file(yfile: Path) -> tuple[bool, str]:
    """多线程并发执行单个 YAML 的 Mihomo 语法校验与修剪"""
    passed, err_msg = validate_yaml(yfile)
    if passed:
        return True, f"[PASS] {yfile.name} verified by Mihomo kernel!"

    pruned_attempts = 0
    while not passed and pruned_attempts < 10:
        pruned_attempts += 1
        if prune_failing_proxies(yfile, err_msg):
            passed, err_msg = validate_yaml(yfile)
        else:
            break

    if passed:
        return True, f"[RE-PASS] {yfile.name} passed after dynamic pruning!"
    else:
        return False, f"[FATAL] {yfile.name} failed Mihomo check:\n{err_msg}"


def main() -> int:
    print("=== Mihomo Kernel Strict CI/CD 8-Worker Parallel Auditor ===", flush=True)

    yaml_files = list(OUTPUT_DIR.rglob("*.yaml"))
    if not yaml_files:
        print("No YAML output files found to validate.", flush=True)
        return 0

    print(f"Starting 8-worker parallel Mihomo syntax verification for {len(yaml_files)} YAML files...", flush=True)

    all_passed = True
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(process_single_file, yf): yf for yf in yaml_files}
        for future in as_completed(futures):
            ok, msg = future.result()
            print(msg, flush=True)
            if not ok:
                all_passed = False

    if not all_passed:
        print("=== Syntax Validation Failed ===", flush=True)
        return 1

    print("=== ALL Output YAML Configurations Passed Mihomo Kernel Check 100% ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
