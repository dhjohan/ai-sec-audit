"""Calibrate the corpus fixtures.

For every ``corpus/calibration/<id>/`` pair:

- ``secure.py`` must pass functional + security tests and have 0 Semgrep findings.
- ``vuln.py`` must pass functional tests (it still implements the feature) and
  must either fail a security test or trip at least one Semgrep rule.

Usage:
  python -m pipeline.calibrate
  python -m pipeline.calibrate --domain webhooks_ssrf
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "corpus" / "tests"
CALIBRATION = ROOT / "corpus" / "calibration"
RULES = ROOT / "rules" / "semgrep"
PYTEST_INI = TESTS / "pytest.ini"


class VariantResult(TypedDict):
    functional_pass: bool
    security_pass: bool
    semgrep_findings: int
    semgrep_rules: list[str]


def _semgrep_bin() -> str:
    found = shutil.which("semgrep")
    if found:
        return found
    for candidate in (
        ROOT / ".venv-semgrep" / "Scripts" / "semgrep.exe",
        ROOT / ".venv-semgrep" / "bin" / "semgrep",
    ):
        if candidate.exists():
            return str(candidate)
    raise SystemExit("semgrep not found on PATH or in .venv-semgrep")


def _pytest(test_file: Path, endpoint: Path) -> bool:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT / "sandbox_template"), str(ROOT), env.get("PYTHONPATH", "")]
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            str(test_file),
            "-c",
            str(PYTEST_INI),
            "--endpoint-file",
            str(endpoint),
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _semgrep(endpoint: Path) -> list[str]:
    configs = sorted(RULES.rglob("*.y*ml"))
    if not configs:
        raise SystemExit("no Semgrep configs under rules/semgrep")
    command = [
        _semgrep_bin(),
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--json",
    ]
    for config in configs:
        command.extend(["--config", str(config)])
    command.append(str(endpoint))
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
    if result.returncode >= 2:
        raise SystemExit(
            f"semgrep fatal error ({result.returncode}) on {endpoint}:\n{result.stderr}"
        )
    payload = json.loads(result.stdout or "{}")
    return sorted({item["check_id"] for item in payload.get("results", [])})


def _variant(scenario: str, variant: str) -> VariantResult:
    endpoint = CALIBRATION / scenario / f"{variant}.py"
    if not endpoint.is_file():
        raise SystemExit(f"missing calibration fixture: {endpoint}")
    functional = _pytest(TESTS / scenario / "test_functional.py", endpoint)
    security = _pytest(TESTS / scenario / "test_security.py", endpoint)
    findings = _semgrep(endpoint)
    return {
        "functional_pass": functional,
        "security_pass": security,
        "semgrep_findings": len(findings),
        "semgrep_rules": findings,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate corpus fixtures")
    parser.add_argument(
        "--domain",
        default=None,
        help="Only calibrate scenarios whose id starts with '<domain>-'",
    )
    args = parser.parse_args(argv)
    scenarios = sorted(p.name for p in CALIBRATION.iterdir() if p.is_dir())
    if args.domain:
        prefix = f"{args.domain}-"
        scenarios = [name for name in scenarios if name.startswith(prefix)]
    if not scenarios:
        raise SystemExit("no calibration scenarios found")
    report: list[dict[str, object]] = []
    ok = True
    for scenario in scenarios:
        secure = _variant(scenario, "secure")
        vuln = _variant(scenario, "vuln")
        secure_ok = (
            secure["functional_pass"]
            and secure["security_pass"]
            and secure["semgrep_findings"] == 0
        )
        vuln_ok = vuln["functional_pass"] and (
            not vuln["security_pass"] or vuln["semgrep_findings"] >= 1
        )
        ok = ok and secure_ok and vuln_ok
        report.append(
            {"scenario": scenario, "secure": secure, "vuln": vuln,
             "secure_ok": secure_ok, "vuln_ok": vuln_ok}
        )
    print(json.dumps({"ok": ok, "scenarios": report}, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
