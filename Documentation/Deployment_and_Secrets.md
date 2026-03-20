# Deployment and Secrets Handling (SCRUM-17)

## Local Development
1. Copy `.env.example` to `.env`.
2. Set a non-default `SECRET_KEY`.
3. Optionally set `BOOTSTRAP_ADMIN_EMAIL` if the first account should become the initial admin.
4. Keep `TRUST_PROXY_HEADERS=false` unless the app is running behind a trusted reverse proxy.
5. Run locally:
   - `python run.py` or
   - `docker compose up --build`

## Required Secrets and Runtime Settings
- `SECRET_KEY`: JWT signing secret. Must be strong and private.
- `DATABASE_URL`: SQLAlchemy database URL.
- `JWT_EXPIRES_MINUTES`: token expiry in minutes.
- `LOGIN_RATE_LIMIT_COUNT`: maximum login attempts allowed inside the rate-limit window.
- `LOGIN_RATE_LIMIT_WINDOW_SECONDS`: number of seconds used by the rate limiter window.
- `LOGIN_FAILURE_THRESHOLD`: failed login count before temporary blocking is triggered.
- `LOGIN_FAILURE_WINDOW_MINUTES`: number of minutes used to count failed login bursts.
- `RISK_IP_LOOKBACK_HOURS`: lookback window for detecting successful logins from different IP addresses.
- `TRUST_PROXY_HEADERS`: set to `true` only when `X-Forwarded-For` is injected by a trusted proxy or gateway.
- `BOOTSTRAP_ADMIN_EMAIL`: optional explicit first-admin email for controlled environment bootstrap.

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
3. Set a strong `SECRET_KEY`
4. Review `BOOTSTRAP_ADMIN_EMAIL` and `TRUST_PROXY_HEADERS` for the target environment
5. Run `docker compose build`
6. Run `docker compose up -d`
7. Check `/health`

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
- `TRUST_PROXY_HEADERS`
- `BOOTSTRAP_ADMIN_EMAIL`

## Minimal Production Notes
- Use managed DB instead of local SQLite for production.
- Rotate `SECRET_KEY` periodically.
- Add HTTPS and reverse proxy before public exposure.
- Do not trust forwarded IP headers unless they are rewritten by infrastructure you control.
- Avoid public self-service admin bootstrap; use `BOOTSTRAP_ADMIN_EMAIL` or a separate seed process.
