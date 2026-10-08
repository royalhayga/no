from __future__ import annotations

import re
import shutil
import subprocess
import sys
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

        # 匹配报错类似: proxy 5662: ss 177.1.187.251:443 initialize error: missing password
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


def main() -> int:
    print("=== Mihomo Kernel Strict CI/CD Syntax Auditor & Dynamic Pruner ===", flush=True)

    yaml_files = list(OUTPUT_DIR.rglob("*.yaml"))
    if not yaml_files:
        print("No YAML output files found to validate.", flush=True)
        return 0

    all_passed = True

    for yfile in yaml_files:
        passed, err_msg = validate_yaml(yfile)
        if passed:
            print(f"[PASS] {yfile.name} successfully verified by Mihomo kernel!", flush=True)
        else:
            print(f"[FAIL] {yfile.name} failed Mihomo kernel syntax check:\n{err_msg}", flush=True)

            # 循环精准剔除该 YAML 中的缺陷节点直至校验完全通过
            pruned_attempts = 0
            while not passed and pruned_attempts < 10:
                pruned_attempts += 1
                if prune_failing_proxies(yfile, err_msg):
                    passed, err_msg = validate_yaml(yfile)
                else:
                    break

            if passed:
                print(f"[RE-PASS] {yfile.name} passed after dynamic pruning!", flush=True)
            else:
                all_passed = False
                print(f"[FATAL] {yfile.name} still failed: {err_msg}", flush=True)

    if not all_passed:
        print("=== Syntax Validation Failed ===", flush=True)
        return 1

    print("=== ALL Output YAML Configurations Passed Mihomo Kernel Check 100% ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
