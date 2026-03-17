# Deployment and Secrets Handling (SCRUM-17)

## Local Development
1. Copy `.env.example` to `.env`.
2. Set a non-default `SECRET_KEY`.
3. Run locally:
   - `python run.py` or
   - `docker compose up --build`

## Required Secrets
- `SECRET_KEY`: JWT signing secret. Must be strong and private.
- `DATABASE_URL`: SQLAlchemy database URL.
- `JWT_EXPIRES_MINUTES`: token expiry in minutes.
- `LOGIN_RATE_LIMIT_COUNT`: maximum login attempts allowed inside the rate-limit window.
- `LOGIN_RATE_LIMIT_WINDOW_SECONDS`: number of seconds used by the rate limiter window.
- `LOGIN_FAILURE_THRESHOLD`: failed login count before temporary blocking is triggered.
- `LOGIN_FAILURE_WINDOW_MINUTES`: number of minutes used to count failed login bursts.
- `RISK_IP_LOOKBACK_HOURS`: lookback window for detecting successful logins from different IP addresses.

## GitHub Actions
- CI runs tests on each push/PR.
- CI validates `docker compose` configuration before the test step.
- Do not commit `.env`.
- If deployment is added later, store secrets in repository settings:
  - `Settings -> Secrets and variables -> Actions`.

## Deployment Workflow Updates

Recommended lightweight deployment workflow:

1. Pull latest `main`
2. Copy or refresh `.env`
3. Run `docker compose build`
4. Run `docker compose up -d`
5. Check `/health`

## GitHub Actions Secret Mapping

If the project later uses hosted deployment, the following repository secrets are recommended:

- `SECRET_KEY`
- `DATABASE_URL`
- `JWT_EXPIRES_MINUTES`
- `LOGIN_RATE_LIMIT_COUNT`
- `LOGIN_RATE_LIMIT_WINDOW_SECONDS`
- `LOGIN_FAILURE_THRESHOLD`
- `LOGIN_FAILURE_WINDOW_MINUTES`
- `RISK_IP_LOOKBACK_HOURS`

## Minimal Production Notes
- Use managed DB instead of local SQLite for production.
- Rotate `SECRET_KEY` periodically.
- Add HTTPS and reverse proxy before public exposure.
