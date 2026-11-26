"""Deterministic versions.lock.json writer for the evaluation environment.

Usage:
  python pipeline/lock_env.py pre
  python pipeline/lock_env.py post <tool_versions_file> <codeql_packs_json>
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


def _codeql_packs(path: Path) -> dict[str, dict[str, str]]:
    """Normalize `codeql resolve packs --format=json` to name -> metadata.

    The CLI emits two shapes: `by-name` steps put `version` on scan entries,
    while `by-name-and-version` steps nest `found[name][version]` (the pack cache).
    """
    raw = json.loads(path.read_text())
    packs: dict[str, dict[str, str]] = {}
    for step in raw.get("steps", []):
        for name, versions in step.get("found", {}).items():
            if not isinstance(versions, dict):
                continue
            for version, info in versions.items():
                if isinstance(info, dict) and "path" in info:
                    packs[name] = {
                        "version": str(version),
                        "kind": str(info.get("kind", "")),
                        "path": str(info["path"]),
                    }
        for scan in step.get("scans", []):
            for name, info in scan.get("found", {}).items():
                if isinstance(info, dict) and "version" in info:
                    packs[name] = {
                        "version": str(info["version"]),
                        "kind": str(info.get("kind", "")),
                        "path": str(info.get("path", "")),
                    }
    if "codeql/python-queries" not in packs:
        raise SystemExit(
            "ERROR: codeql/python-queries missing from `codeql resolve packs`"
        )
    return dict(sorted(packs.items()))


def post(tool_versions_file: Path, codeql_packs_file: Path) -> dict[str, object]:
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
    data["codeql_packs"] = _codeql_packs(codeql_packs_file)
    return data


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in {"pre", "post"}:
        print(__doc__)
        return 2
    if argv[1] == "pre":
        data = pre()
    else:
        if len(argv) < 4:
            print(
                "ERROR: post requires a tool_versions file and a "
                "codeql_packs JSON file"
            )
            return 2
        data = post(Path(argv[2]), Path(argv[3]))
    LOCK.write_text(json.dumps(data, indent=2) + "\n")
    print(f"versions.lock.json written ({argv[1]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
