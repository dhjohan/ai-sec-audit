# Methodology

This document records how the AI code-security benchmark is built and how the
calibration corpus is validated. It is the reference for the dual SAST + DAST
gate and for the coverage signal tracked across scenario batches.

## 1. Purpose

Measure whether an AI coding arm produces a FastAPI endpoint that is both
functionally correct and free of the weakness the scenario targets. Every
scenario is rendered through each arm (A: naive, B: secure preamble, C: review
prompt) and evaluated by the same harness.

## 2. Corpus

- Base scenarios live in `corpus/prompts.yaml`. They are arm-agnostic: no
  `arm`, no `seed_code`, and no security hints in `task`.
- Each scenario names an exact route, method, request/response shape, and the
  sandbox tables it may use.
- A scenario ships with two calibration fixtures:
  - `corpus/calibration/<id>/secure.py` — reference implementation that must
    pass the security tests and trip no Semgrep rule.
  - `corpus/calibration/<id>/vuln.py` — implementation of the same feature that
    must fail at least one security test or trip at least one Semgrep rule.
- Tests live in `corpus/tests/<id>/` (`test_functional.py`,
  `test_security.py`) and share `corpus/tests/conftest.py`.
- CWE -> OWASP:2025 mappings come only from
  `taxonomies/cwe_owasp_2025.json`.
- Current size: 20 scenarios across 4 domains (`search_rendering`,
  `webhooks_ssrf`, `file_upload`, `auth_sessions`). Target: 40 across 8 domains.

## 3. Harness

`corpus/tests/conftest.py` mounts the candidate module as
`app/generated_endpoint.py`, points the app at a temporary SQLite database,
fails on duplicate `(method, path)` routes, and exposes sync and async clients.
No candidate file is imported from the repository tree; upload and file
directories are injected per test through `tmp_path` environment variables.

The calibration gate in `pipeline/calibrate.py` runs both test suites and every
config under `rules/semgrep/` for each fixture:

- **secure**: functional pass, security pass, 0 Semgrep findings.
- **vuln**: functional pass, and either a security-test failure or >= 1 Semgrep
  finding.

A scenario is only accepted when both variants pass this gate.

## 4. Calibration signal (current: 20 scenarios)

For each vulnerable fixture:

- **SAST caught** = `semgrep_findings >= 1` (any rule in the pinned pack fires).
- **DAST caught** = the targeted security suite fails.
- **Combined caught** = SAST or DAST.

| Domain | Scenarios | SAST caught | DAST caught | Combined |
|---|---:|---:|---:|---:|
| `search_rendering` | 5 | 5 | 5 | 5 |
| `webhooks_ssrf` | 5 | 1 | 5 | 5 |
| `file_upload` | 5 | 0 | 5 | 5 |
| `auth_sessions` | 5 | 1 | 5 | 5 |
| **Total** | **20** | **7 (35%)** | **20 (100%)** | **20 (100%)** |

The gap is the rationale for the dual gate: static analysis alone misses 13 of
the 20 known-vulnerable fixtures, while the targeted executable tests identify
all 20. Per-scenario rule IDs are in `results/calibration_summary.json`.

## 5. Threats to validity

1. **DAST 100% is by construction.** Each security test was written with
   knowledge of its fixture's weakness. It proves the fixture is detectable, not
   that the tests generalize to unseen code.
2. **SAST 40% is rule-pack coverage, not Semgrep's general power.** Several hits
   come from rules authored for these scenarios (for example the FastAPI
   HTMLResponse, autoescape, SSTI, and HMAC-comparison rules). It is an upper
   bound for this pinned pack.
3. **"Caught" means any finding on the file**, not a match to the intended CWE.
   A rule firing on an unrelated line still counts.
4. **Small sample.** 20 scenarios across 4 domains is not a statistical claim.
   Treat the ratio as a trend until the corpus reaches 40.
5. **Reference fixtures, not model output.** These numbers describe the
   calibration corpus, not the arms' measured performance.

## 6. Tracking across batches

`pipeline.calibrate` emits a deterministic `summary` block and can persist it:

```bash
python -m pipeline.calibrate \
  --output results/calibration_summary.json \
  --history results/calibration_history.jsonl
```

- `results/calibration_summary.json` is the cumulative source of truth. It is
  generated, never hand-edited.
- `results/calibration_history.jsonl` appends one line per distinct run (the
  writer is idempotent when the summary is unchanged).
- Update the table in section 4 after each batch and commit the summary,
  history, and this file together.

## 7. Reproduce

```bash
python -m pipeline.calibrate --domain <domain>   # one batch
python -m pipeline.calibrate                     # full corpus
ruff check --no-cache pipeline analysis tests_harness sandbox_template/app
mypy pipeline analysis tests_harness sandbox_template/app
pytest tests_harness
pytest sandbox_template/tests
```

The Docker gate (`make test`) runs the full calibration inside the pinned
`ai-sec-eval` image with `--network=none` and a read-only root.
