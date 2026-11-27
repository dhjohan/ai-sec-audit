---
description: Add a batch of arm-agnostic benchmark scenarios for one domain
---
# Add scenarios for $DOMAIN (batch size $COUNT)

Add **at most 5** scenarios for the `$DOMAIN` domain in this run. The full corpus
target is 40 scenarios; run this command once per batch so each context stays
small. If `$COUNT` is greater than 5, add 5 and report the remaining count.

## Read first

- `pipeline/schemas.py` — `CorpusScenario` is the authoritative shape. Every
  entry **must** validate against it.
- `corpus/prompts.yaml` — append here. This file is arm-agnostic: never write
  `arm` or `seed_code`.
- `corpus/templates.yaml` — `arm_b_secure_preamble` / `arm_c_review_prompt`
  are applied in Phase 2, not here.
- `taxonomies/cwe_owasp_2025.json` — the only source of CWE -> OWASP:2025
  mappings.
- `sandbox_template/` — the only permitted app structure, tables and columns.

## Scenario rules

1. Each scenario targets at least one CWE already present in the taxonomy
   (`cwe_to_owasp`). `CorpusScenario` rejects unknown CWEs; if one is missing,
   add it to the taxonomy first (do not invent an OWASP category).
2. `task` describes only the feature: exact route, HTTP method, query/JSON
   parameter names and types, response shape, status codes. It must contain
   **zero security hints** — no `escape`, `parameterize`, `autoescape`,
   `Markup`, `compare_digest`, `safe_load`, `resolve`, or CWE names.
3. Never put `arm`, `seed_code`, `vulnerable`, or reference code in
   `prompts.yaml`. Calibration code lives only in
   `corpus/calibration/<scenario_id>/{secure,vuln}.py`.
4. Do not repeat an existing `(domain, target_cwes, title)` tuple.
5. Keep the scenario compatible with the sandbox template: FastAPI + SQLAlchemy
   2.x sync SQLite; existing tables/columns only; no new dependencies.
6. `functional_check` and `security_check` are harness-only notes. They are
   never sent to a model.
7. Append under `scenarios:` in `corpus/prompts.yaml` using this shape:

```yaml
- id: "$DOMAIN-001"
  domain: "$DOMAIN"
  title: "Short, specific scenario title"
  route: "/exact/path"
  method: "GET"            # GET | POST | PUT | PATCH | DELETE
  owasp_surface: ["A05:2025"]
  target_cwes: ["CWE-79"]
  task: |
    The feature request given to the model (no security hints).
  functional_check: |
    How the harness proves the feature works.
  security_check: |
    How the harness proves the weakness is gone.
```

8. Use the next unused three-digit index for `$DOMAIN`. Keep IDs stable once written.

## Validate before finishing

```bash
PYTHONPATH=. .venv-verify/Scripts/python.exe - <<'PY'
import yaml
from pathlib import Path
from pipeline.schemas import CorpusScenario
data = yaml.safe_load(Path("corpus/prompts.yaml").read_text())
[CorpusScenario(**s) for s in data["scenarios"]]
print("ok", len(data["scenarios"]))
PY
```

Report the batch IDs added and the next index.
