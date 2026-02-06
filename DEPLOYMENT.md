# Deployment

## Docker Compose

1. Copy env file:

```bash
cp .env.example .env
```

2. Set required values in `.env`:

- `MASTER_KEY` (>= 32 chars)
- `ADMIN_PASSWORD`

3. Start service:

```bash
docker-compose up -d
```

4. Verify:

```bash
curl http://localhost:8000/public/health
```

## Upgrade / Rebuild

```bash
docker-compose pull
docker-compose up -d --build
```

## Local Production-like Run

```bash
cd backend
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Notes

- Keep `MASTER_KEY` stable across restarts; changing it invalidates encrypted key material.
- Back up database and env file together.
