"""Core schemas for the AI Security Benchmark - Phase 0.

Everything here is deterministic and JSON-serialisable so run manifests can be
version-stamped and compared across experiments.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class OWASPTop10_2025(str, Enum):
    """OWASP Top 10:2025 - authoritative 2025 edition.

    Note the 2025 changes versus 2021: SSRF folded into A01, supply chain moved
    to A03, and A10 is now mishandling of exceptional conditions.
    """

    A01_BROKEN_ACCESS_CONTROL = "A01:2025"  # includes SSRF
    A02_SECURITY_MISCONFIGURATION = "A02:2025"
    A03_SOFTWARE_SUPPLY_CHAIN_FAILURES = "A03:2025"
    A04_CRYPTOGRAPHIC_FAILURES = "A04:2025"
    A05_INJECTION = "A05:2025"
    A06_INSECURE_DESIGN = "A06:2025"
    A07_AUTHENTICATION_FAILURES = "A07:2025"
    A08_SOFTWARE_DATA_INTEGRITY = "A08:2025"
    A09_SECURITY_LOGGING_ALERTING = "A09:2025"
    A10_MISHANDLING_EXCEPTIONAL_CONDITIONS = "A10:2025"


class Arm(str, Enum):
    A = "A"
    B = "B"
    C = "C"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NormalizedFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: UUID = Field(default_factory=uuid4)
    rule_id: str
    owasp_category: OWASPTop10_2025
    severity: Severity
    file_path: str
    line_start: int
    line_end: int
    message: str
    cwe_id: str | None = None


class PromptSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    prompt_id: str
    prompt_sha256: str
    arm: Arm
    provider: str
    model_id: str
    model_api_fingerprint: str
    temperature: float
    max_tokens: int
    system_prompt_sha256: str | None = None
    user_prompt_sha256: str


_TAXONOMY_PATH = (
    Path(__file__).resolve().parent.parent / "taxonomies" / "cwe_owasp_2025.json"
)


@lru_cache(maxsize=1)
def _known_cwes() -> frozenset[str]:
    data = json.loads(_TAXONOMY_PATH.read_text())
    return frozenset(data["cwe_to_owasp"])


class CorpusScenario(BaseModel):
    """Arm-agnostic base scenario for ``corpus/prompts.yaml``.

    Deliberately has no ``arm`` or ``seed_code``: Phase 2 renders one scenario
    through all three arms. Vulnerable/secure code lives in calibration only.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    domain: str
    title: str
    route: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    owasp_surface: list[OWASPTop10_2025]
    target_cwes: list[str]
    task: str
    functional_check: str
    security_check: str

    @field_validator("target_cwes")
    @classmethod
    def _validate_cwes(cls, value: list[str]) -> list[str]:
        known = _known_cwes()
        unknown = [cwe for cwe in value if cwe not in known]
        if unknown:
            raise ValueError(f"CWEs missing from taxonomy: {unknown}")
        return value


class ArtifactEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True)

    artifact_id: UUID = Field(default_factory=uuid4)
    artifact_sha256: str
    artifact_path: str
    language: str = "python"
    findings: list[NormalizedFinding] = Field(default_factory=list)
    semgrep_duration_ms: int
    codeql_duration_ms: int
    pip_audit_duration_ms: int
    pytest_duration_ms: int
    functional_pass: bool = False
    security_pass: bool = False
    joint_pass: bool = False
    status: str = "pass"


class RunManifest(BaseModel):
    model_config = ConfigDict(frozen=True)

    run_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    git_commit: str
    docker_image_digest: str
    versions_lock_sha256: str
    prompt: PromptSpec
    artifact: ArtifactEvaluation
    total_duration_ms: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def sha256_str(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
