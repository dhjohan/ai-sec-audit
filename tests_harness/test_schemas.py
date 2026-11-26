from __future__ import annotations

import pytest
from pydantic import ValidationError

from pipeline.schemas import (
    Arm,
    ArtifactEvaluation,
    NormalizedFinding,
    OWASPTop10_2025,
    PromptSpec,
    RunManifest,
    Severity,
    sha256_str,
)


def _prompt() -> PromptSpec:
    return PromptSpec(
        prompt_id="prompt-001",
        prompt_sha256=sha256_str("test prompt"),
        arm=Arm.A,
        provider="openai",
        model_id="gpt-4o",
        model_api_fingerprint="gpt-4o-2024-08-06",
        temperature=0.7,
        max_tokens=4096,
        user_prompt_sha256=sha256_str("user prompt"),
    )


def _artifact() -> ArtifactEvaluation:
    return ArtifactEvaluation(
        artifact_sha256="abc123",
        artifact_path="artifacts/run-001/generated_endpoint.py",
        findings=[],
        semgrep_duration_ms=100,
        codeql_duration_ms=200,
        pip_audit_duration_ms=50,
        pytest_duration_ms=300,
    )


def test_owasp_2025_categories() -> None:
    assert len(OWASPTop10_2025) == 10
    assert OWASPTop10_2025.A01_BROKEN_ACCESS_CONTROL == "A01:2025"
    assert OWASPTop10_2025.A03_SOFTWARE_SUPPLY_CHAIN_FAILURES == "A03:2025"
    assert OWASPTop10_2025.A05_INJECTION == "A05:2025"
    assert OWASPTop10_2025.A10_MISHANDLING_EXCEPTIONAL_CONDITIONS == "A10:2025"


def test_finding_serialization() -> None:
    finding = NormalizedFinding(
        rule_id="TEST-001",
        owasp_category=OWASPTop10_2025.A05_INJECTION,
        severity=Severity.HIGH,
        file_path="app/generated_endpoint.py",
        line_start=10,
        line_end=15,
        message="SQL injection via f-string",
        cwe_id="CWE-89",
    )
    data = finding.model_dump()
    assert data["owasp_category"] == "A05:2025"
    assert data["severity"] == "high"


def test_finding_is_frozen() -> None:
    finding = NormalizedFinding(
        rule_id="TEST-001",
        owasp_category=OWASPTop10_2025.A05_INJECTION,
        severity=Severity.HIGH,
        file_path="f.py",
        line_start=1,
        line_end=1,
        message="m",
    )
    with pytest.raises(ValidationError):
        finding.rule_id = "mutated"  # type: ignore[misc]


def test_prompt_spec_roundtrip() -> None:
    prompt = _prompt()
    assert prompt.arm is Arm.A
    assert PromptSpec.model_validate_json(prompt.model_dump_json()) == prompt


def test_artifact_evaluation_defaults() -> None:
    artifact = _artifact()
    assert artifact.status == "pass"
    assert artifact.functional_pass is False
    assert artifact.security_pass is False
    assert artifact.joint_pass is False


def test_runmanifest_roundtrip_is_deterministic() -> None:
    manifest = RunManifest(
        git_commit="abc123",
        docker_image_digest="sha256:deadbeef",
        versions_lock_sha256=sha256_str("{}"),
        prompt=_prompt(),
        artifact=_artifact(),
        total_duration_ms=650,
    )
    payload = manifest.model_dump_json()
    assert RunManifest.model_validate_json(payload) == manifest
    assert manifest.timestamp.tzinfo is not None
