from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

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


def main() -> int:
    print("=== Mihomo Kernel Strict CI/CD Syntax Auditor ===", flush=True)

    yaml_files = list(OUTPUT_DIR.glob("*.yaml"))
    if not yaml_files:
        print("No YAML output files found to validate.", flush=True)
        return 0

    all_passed = True

    for yfile in yaml_files:
        passed, err_msg = validate_yaml(yfile)
        if passed:
            print(f"[PASS] {yfile.name} successfully verified by Mihomo kernel!", flush=True)
        else:
            all_passed = False
            print(f"[FAIL] {yfile.name} failed Mihomo kernel syntax check:\n{err_msg}", flush=True)

            # 如果检测到缺陷，重新执行 template_engine.py 进行兜底清洗
            print(f"Triggering auto-prune pass for {yfile.name}...", flush=True)
            try:
                subprocess.run([sys.executable, str(ROOT_DIR / "scripts" / "template_engine.py")], check=True)
                re_passed, re_err = validate_yaml(yfile)
                if re_passed:
                    print(f"[RE-PASS] {yfile.name} passed after auto-prune!", flush=True)
                    all_passed = True
                else:
                    print(f"[FATAL] {yfile.name} still failed after auto-prune: {re_err}", flush=True)
            except Exception as e:
                print(f"Failed to re-run template engine: {e}", flush=True)

    if not all_passed:
        print("=== Syntax Validation Failed ===", flush=True)
        return 1

    print("=== ALL Output YAML Configurations Passed Mihomo Kernel Check 100% ===", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
