"""Deterministic versions.lock.json writer for the evaluation environment.

Usage:
  python pipeline/lock_env.py pre
  python pipeline/lock_env.py post <tool_versions_file>
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / "versions.lock.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict[str, object]:
    if LOCK.exists():
        loaded: dict[str, object] = json.loads(LOCK.read_text())
        return loaded
    return {}


def pre() -> dict[str, object]:
    requirements = ROOT / "sandbox_template" / "requirements.lock"
    if not requirements.exists():
        raise SystemExit(
            "ERROR: sandbox_template/requirements.lock missing. "
            "Generate it with pip-compile or pip freeze first."
        )
    rules_dir = ROOT / "rules" / "semgrep"
    rule_hashes = [_sha256(path) for path in sorted(rules_dir.rglob("*.y*ml"))]
    data = _load()
    data["sandbox_template_requirements_lock_sha256"] = _sha256(requirements)
    data["semgrep_rules_sha256"] = (
        hashlib.sha256("".join(rule_hashes).encode()).hexdigest()
        if rule_hashes
        else "missing"
    )
    data["semgrep_rules_count"] = len(rule_hashes)
    return data


def post(tool_versions_file: Path) -> dict[str, object]:
    tools: dict[str, str] = {}
    for line in tool_versions_file.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            tools[key.strip()] = value.strip()
    digest = subprocess.check_output(
        ["docker", "inspect", "--format={{.Id}}", "ai-sec-eval:latest"],
        text=True,
    ).strip()
    data = _load()
    data["docker_image"] = "ai-sec-eval:latest"
    data["image_digest"] = digest
    data["tool_versions"] = tools
    return data


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in {"pre", "post"}:
        print(__doc__)
        return 2
    if argv[1] == "pre":
        data = pre()
    else:
        if len(argv) < 3:
            print("ERROR: post requires a tool_versions file path")
            return 2
        data = post(Path(argv[2]))
    LOCK.write_text(json.dumps(data, indent=2) + "\n")
    print(f"versions.lock.json written ({argv[1]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
