from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from pipeline.schemas import CorpusScenario, OWASPTop10_2025

ROOT = Path(__file__).resolve().parent.parent

_SECURITY_HINTS = (
    "escape",
    "parameteri",
    "autoescape",
    "markup",
    "compare_digest",
    "safe_load",
    "sanitiz",
    "vulnerab",
    "cwe-",
)


def _taxonomy() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(
        (ROOT / "taxonomies" / "cwe_owasp_2025.json").read_text()
    )
    return loaded


def test_taxonomy_uses_schema_enum_and_has_fallback() -> None:
    data = _taxonomy()
    categories = {category.value for category in OWASPTop10_2025}
    assert set(data["categories"]) == categories
    assert data["fallback_category"] in categories
    assert data["fallback_policy"] == "manual_triage"

    mapping: dict[str, str] = data["cwe_to_owasp"]
    assert all(value in categories for value in mapping.values())
    for cwe in (
        "CWE-79",
        "CWE-89",
        "CWE-78",
        "CWE-94",
        "CWE-22",
        "CWE-918",
        "CWE-287",
        "CWE-306",
        "CWE-639",
        "CWE-798",
        "CWE-327",
        "CWE-208",
        "CWE-502",
        "CWE-611",
        "CWE-117",
        "CWE-209",
        "CWE-755",
        "CWE-400",
        "CWE-362",
        "CWE-1395",
    ):
        assert cwe in mapping
    assert "CWE-999999" not in mapping


def test_templates_cover_required_constraints() -> None:
    templates: dict[str, Any] = yaml.safe_load(
        (ROOT / "corpus" / "templates.yaml").read_text()
    )
    secure: str = templates["arm_b_secure_preamble"]
    review: str = templates["arm_c_review_prompt"]

    for phrase in (
        "SQLAlchemy",
        "autoescape",
        "hmac.compare_digest",
        "Path.resolve",
        "loopback",
        "owner_id",
        "4xx/5xx",
    ):
        assert phrase in secure
    for phrase in ("Step 1", "Step 2", "OWASP Top 10:2025", "<code_output>"):
        assert phrase in review


def test_custom_rules_match_taxonomy() -> None:
    data = _taxonomy()
    categories = set(data["categories"])
    mapping: dict[str, str] = data["cwe_to_owasp"]

    rules: list[dict[str, Any]] = yaml.safe_load(
        (ROOT / "rules" / "semgrep" / "fastapi_custom.yaml").read_text()
    )["rules"]
    assert rules
    for rule in rules:
        metadata = rule["metadata"]
        assert metadata["cwe"], rule["id"]
        assert set(metadata["owasp"]) <= categories, rule["id"]
        for cwe in metadata["cwe"]:
            assert cwe in mapping, (rule["id"], cwe)


def test_prompts_validate_and_match_taxonomy() -> None:
    data = _taxonomy()
    categories = set(data["categories"])
    mapping: dict[str, str] = data["cwe_to_owasp"]

    corpus: dict[str, Any] = yaml.safe_load(
        (ROOT / "corpus" / "prompts.yaml").read_text()
    )
    scenarios = [CorpusScenario(**item) for item in corpus["scenarios"]]
    assert len(scenarios) == 5
    assert len({scenario.id for scenario in scenarios}) == len(scenarios)

    for item in corpus["scenarios"]:
        assert "arm" not in item
        assert "seed_code" not in item

    seen: set[tuple[str, tuple[str, ...], str]] = set()
    for scenario in scenarios:
        assert scenario.domain == corpus["domain"]
        assert scenario.route.startswith("/")
        surface = {category.value for category in scenario.owasp_surface}
        assert surface <= categories
        assert set(scenario.target_cwes) <= set(mapping), scenario.id
        for cwe in scenario.target_cwes:
            assert mapping[cwe] in surface, (scenario.id, cwe)
        assert scenario.functional_check.strip()
        assert scenario.security_check.strip()
        lowered = scenario.task.lower()
        for hint in _SECURITY_HINTS:
            assert hint not in lowered, (scenario.id, hint)
        key = (scenario.domain, tuple(scenario.target_cwes), scenario.title)
        assert key not in seen
        seen.add(key)
