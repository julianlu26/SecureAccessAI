# Docker Deployment Package and Operations Runbook (SCRUM-27)

This runbook describes how to deploy and operate SecureAccessAI with Docker.

## Package Contents

- `Dockerfile`: application container build definition
- `docker-compose.yml`: local or single-host container orchestration
- `.env.example`: required environment variable template
- `.github/workflows/ci.yml`: CI validation for code changes

## Pre-Deployment Checklist

- Install Docker Engine and Docker Compose plugin.
- Copy `.env.example` to `.env`.
- Replace `SECRET_KEY` with a non-default value.
- Confirm port `5000` is available on the host.

## Build and Start

```bash
cp .env.example .env
docker compose build
docker compose up -d
```

## Operational Verification

Check container status:

```bash
docker compose ps
```

Check health endpoint:

```bash
curl http://127.0.0.1:5000/health
```

Expected response:

```json
{"status":"ok"}
```

## Logs and Troubleshooting

View live logs:

```bash
docker compose logs -f api
```

Common checks:

- If the service fails on startup, confirm `.env` exists and contains all required variables.
- If `/health` is not reachable, confirm port mapping `5000:5000` is not blocked.
- If authentication fails unexpectedly, inspect security events via the admin API after login.

## Stop and Restart

Stop the stack:

```bash
docker compose down
```

Restart the stack:

```bash
docker compose up -d
```

## Update Procedure

When new code is pulled:

```bash
git pull origin main
docker compose build
docker compose up -d
```

## Backup and Persistence Note

The current classroom deployment uses SQLite and is suitable for demonstration only.
For production-style deployment, replace SQLite with a managed database and add persistent storage strategy.

## Rollback Procedure

If a deployment update fails, use the following rollback sequence:

1. Stop the current containers.
2. Revert to the previous known-good commit.
3. Rebuild the image.
4. Start the stack again and re-check the health endpoint.

## Environment Validation

Before deployment, confirm that the env file includes SECRET_KEY, DATABASE_URL, JWT expiry, rate-limit settings, and failure-threshold settings.
