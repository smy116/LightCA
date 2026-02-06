# Contributing

## Local Setup

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
```

Run app:

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Run tests:

```bash
pytest -q
```

## Contribution Rules

- Keep changes focused and minimal.
- Follow existing API response format and route style.
- Add or update tests when behavior changes.
- Do not commit secrets (`.env`, keys, credentials).

## Pull Requests

- Use a clear title describing intent.
- Include a short summary and test evidence.
- Confirm CI (`.github/workflows/build.yml`) is passing.
