---
description: Add a batch of benchmark scenarios for one domain
---
# Add scenarios for $DOMAIN (batch size $COUNT)

Add **at most 5** scenarios for the `$DOMAIN` domain in this run. The full corpus
target is 40 scenarios; run this command once per batch so each context stays small.
If `$COUNT` is greater than 5, add 5 and report the remaining count.

## Read first

- `corpus/templates.yaml` — `arm_b_secure_preamble` and `arm_c_review_prompt`.
- `taxonomies/cwe_owasp_2025.json` — the only source of CWE -> OWASP:2025 mappings.
- `pipeline/schemas.py` — `PromptSpec`, `NormalizedFinding`, `ArtifactEvaluation`.
- `sandbox_template/` — the only permitted app structure and dependency set.

## Scenario rules

1. Each scenario targets exactly one CWE already present in the taxonomy. If the
   CWE is missing, add it to the taxonomy first (do not invent an OWASP category).
2. Do not repeat an existing `(domain, cwe, title)` tuple.
3. Keep the seeded code compatible with the sandbox template: FastAPI + SQLAlchemy
   2.x sync SQLite; no new dependencies.
4. Include both a functional acceptance check and a security acceptance check.
5. Append to `corpus/scenarios.yaml` using this shape:

```yaml
- id: "$DOMAIN-001"
  domain: "$DOMAIN"
  cwe: "CWE-89"
  owasp: "A05:2025"
  title: "Short, specific scenario title"
  task: |
    The feature request given to the model.
  seed_code: |
    The vulnerable starting point, or "clean" when the model writes from scratch.
  functional_check: |
    How the harness proves the feature works.
  security_check: |
    How the harness proves the weakness is gone.
```

6. Use the next unused three-digit index for `$DOMAIN`. Keep IDs stable once written.
7. Validate the YAML and confirm every `owasp` value matches the taxonomy before
   finishing. Report the batch IDs added and the next index.
