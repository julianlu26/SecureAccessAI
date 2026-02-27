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

## GitHub Actions
- CI runs tests on each push/PR.
- Do not commit `.env`.
- If deployment is added later, store secrets in repository settings:
  - `Settings -> Secrets and variables -> Actions`.

## Minimal Production Notes
- Use managed DB instead of local SQLite for production.
- Rotate `SECRET_KEY` periodically.
- Add HTTPS and reverse proxy before public exposure.
