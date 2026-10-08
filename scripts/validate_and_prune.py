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

    cmd = [MIHOMO_BIN, "-t", "-f", str(yaml_file)]
    res = subprocess.run(cmd, capture_output=True, text=True)

    if res.returncode == 0:
        return True, res.stdout
    else:
        return False, res.stderr + "\n" + res.stdout


def prune_failing_proxies(yaml_file: Path, err_msg: str) -> bool:
    """动态解析 Mihomo 报错并精准剔除有缺陷的节点 (如缺少密码/加密非法/节点重名)"""
    try:
        content = yaml_file.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
        proxies = data.get("proxies", [])
        if not proxies:
            return False

        indices_to_remove = set()

        for match in re.finditer(r"proxy\s+(\d+):", err_msg):
            idx = int(match.group(1))
            if 0 <= idx < len(proxies):
                indices_to_remove.add(idx)

        if not indices_to_remove:
            return False

        new_proxies = [p for i, p in enumerate(proxies) if i not in indices_to_remove]
        data["proxies"] = new_proxies

        yaml_file.write_text(yaml.dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
        print(f"[PRUNE OK] Dynamically removed {len(indices_to_remove)} failing proxies from {yaml_file.name}", flush=True)
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
