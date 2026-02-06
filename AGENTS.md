# AGENTS.md

Operational guide for coding agents working in this repository.
Applies to `/home/LightCA`.

## 1) Project Snapshot

- Backend stack: FastAPI, SQLAlchemy, Alembic, Pydantic, cryptography.
- Frontend stack: Jinja2 templates + static assets (Tailwind/DaisyUI from CDN).
- Runtime target: Python 3.11+ (CI currently uses Python 3.12).
- Main application entry: `backend/app/main.py`.
- API and web UI are served from the same FastAPI app.

## 2) Authoritative Files

- Tooling config: `backend/pyproject.toml`
- Python deps (CI install path): `backend/requirements.txt`
- CI pipeline: `.github/workflows/build.yml`
- Setup docs: `README.md`, `CONTRIBUTING.md`, `DEPLOYMENT.md`
- Container config: `backend/Dockerfile`, `docker-compose.yml`

## 3) Working Directory Rules

- Run almost all dev/test/lint/type commands from `backend/`.
- Run Docker orchestration from repo root `/home/LightCA`.
- Prefer `pip install -r requirements.txt` for consistency with CI.
- Poetry is configured; if you choose Poetry (`poetry install`), stay consistent.
- Never commit secrets (`.env`, keys, credentials, tokens).

## 4) Build and Run Commands

From repo root:

- `docker-compose up -d` (start full stack)
- `docker-compose down` (stop stack)

From `backend/`:

- `python -m pip install --upgrade pip`
- `pip install -r requirements.txt`
- `poetry install` (alternative to pip requirements flow)
- `alembic upgrade head`
- `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000` (dev)
- `uvicorn app.main:app --host 0.0.0.0 --port 8000` (prod-like local)

## 5) Test Commands (including single test)

Run from `backend/`:

- `pytest` (full suite)
- `pytest -q` (CI-style output)
- `pytest tests/test_api_auth.py` (single file)
- `pytest tests/test_api_auth.py::TestAuthAPI` (single class)
- `pytest tests/test_api_auth.py::TestAuthAPI::test_login_success` (single test)
- `pytest -k "login and not wrong_password"` (pattern select)

Notes:

- Pytest config is in `backend/pyproject.toml` (`[tool.pytest.ini_options]`).
- Coverage flags are enabled by default via `addopts`.

## 6) Lint, Format, and Type Check

Run from `backend/`:

- `ruff check .`
- `black .`
- `isort .`
- `mypy .`

Suggested pre-PR verification:

1. `ruff check .`
2. `black . && isort .`
3. `mypy .`
4. `pytest -q`

## 7) Style Rules from Config + Existing Code

### Formatting and linting

- Line length is 100 (Black/Ruff/isort aligned).
- Ruff rules enabled: `E,F,W,I,N,UP,B,C4`; `E501` ignored.
- Let Black own formatting; do not hand-format against it.

### Imports

- Use grouped imports: stdlib, third-party, local.
- Prefer absolute local imports from `app.*`.
- Function-local imports are acceptable when avoiding circular imports.

### Typing

- Function definitions should be typed (`disallow_untyped_defs = true`).
- Use explicit concrete types where practical.
- Avoid broad `Any` unless it is a clear interface boundary.

### Naming

- `snake_case`: functions, variables, filenames.
- `PascalCase`: classes, enums, Pydantic models.
- `_leading_underscore`: private/internal helper functions.

### API response and error handling

- Success responses commonly use `success_response(...).model_dump()`.
- Service layer raises `ValueError` for domain/business failures.
- API router layer translates `ValueError` to `HTTPException` with status codes.
- Global exception handlers in `backend/app/main.py` enforce envelope shape.

### Persistence conventions

- SQLAlchemy models live in `backend/app/models`.
- Soft-delete filtering (`is_deleted == False`) is common in reads.
- Keep pagination/filter/sort behavior aligned with existing endpoints.

## 8) Testing Conventions

- Framework: `pytest` + FastAPI `TestClient`.
- Tests are class-grouped by feature/domain (`TestAuthAPI`, etc.).
- Reuse fixtures from `backend/tests/conftest.py` (`client`, `db`, `auth_token`, `auth_headers`).
- Assert both status codes and JSON body semantics (often `success/message/data`).
- For behavior changes, update or add tests in the closest existing module.

## 9) Database and Migrations

- Alembic lives in `backend/alembic`.
- For schema changes: generate migration, review script, run `alembic upgrade head`, run tests.

## 10) CI Expectations

- CI runs backend tests in `backend/` via `pytest -q`.
- Docker image build runs after tests pass.
- Before PR: ensure at least `pytest -q` succeeds locally.

## 11) Cursor / Copilot Rule Files

Checked and not found at time of writing:

- `.cursorrules`
- `.cursor/rules/`
- `.github/copilot-instructions.md`

If these files are added later, treat them as higher-priority instructions and update this guide.

## 12) Agent Change Philosophy

- Keep changes focused and minimal.
- Do not mix broad refactors into bugfixes.
- Preserve current API contract shape unless task explicitly changes it.
- Follow existing module boundaries (`api/`, `services/`, `schemas/`, `models/`).
- Prefer extending existing services/helpers over introducing parallel abstractions.

## 13) Quick Command Cheat Sheet

From `backend/`:

- `pytest -q`
- `pytest tests/test_api_auth.py::TestAuthAPI::test_login_success`
- `ruff check . && black . && isort . && mypy .`
- `alembic upgrade head`
- `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000`

From repo root:

- `docker-compose up -d`
