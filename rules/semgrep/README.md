# Vendored Semgrep rules (offline)

`rules/semgrep/` is copied into the eval image at `/opt/semgrep-rules`, and all
scans run with `--network=none`. Registry configs such as `--config p/python`
would try to download rules at scan time and fail offline, so the packs are
vendored here at build/commit time instead.

Vendored from the Semgrep registry on 2026-11-26:

- `vendor/python.yaml`            <- `p/python`
- `vendor/owasp-top-ten.yaml`     <- `p/owasp-top-ten`
- `vendor/sql-injection.yaml`     <- `p/sql-injection`
- `vendor/xss.yaml`               <- `p/xss`

`python-baseline.yaml` is the project's own small ruleset.

Registry packs can share rule ids, so validate and run them **one config file
per Semgrep invocation** (the Dockerfile validates each file individually).
Hashes of every file here are recorded in `versions.lock.json` by
`pipeline/lock_env.py pre`.

## Scan-time overlap (Phase 3)

Empirically verified with Semgrep 1.187.0: `semgrep scan` given all five
`--config` files together exits 0 and does **not** raise a duplicate-ID error
(that only bit us when validating the whole directory at once, which is why the
Dockerfile validates per file).

The packs still overlap, so the same issue can be reported by more than one
pack. The Phase 3 pipeline must deduplicate findings by
`(cwe_id, file_path, line_bucket)` before scoring, or run each pack separately
and merge with the same key.
