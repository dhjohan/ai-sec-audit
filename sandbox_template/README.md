# Sandbox Template

A deliberately small, vulnerability-free FastAPI application used as the base
for the AI code security benchmark. It provides:

- SQLAlchemy 2.x models: `User`, `Product`, `Order`, `WebhookEvent`, `AuditLog`
- Cookie/JWT session auth (`/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`)
- A versioned REST API under `/api/v1`
- Jinja2 templates for the landing and login pages
- A single drop-in mount point for generated code: `app/generated_endpoint.py`

## Drop-in generated endpoint

The benchmark asks a model to add one route file, never to modify models.
Copy `app/generated_endpoint.py.example` to `app/generated_endpoint.py`; the
`app/api/generated.py` mount point includes its `APIRouter` automatically when
the file exists. The existing models are importable and reusable as-is.

The clean template intentionally does not ship `generated_endpoint.py`. The
import is only guarded by a file-existence check: once the file exists, any
import or syntax error fails loudly (matters for OWASP A03 supply-chain
detection).

## Local development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.lock
uvicorn app.main:app --reload
pytest
```

`docker compose up --build` runs the same app on port 8000.
