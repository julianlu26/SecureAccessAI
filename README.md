# SecureAccessAI (SP1 + SP2)

Flask-based backend for Sprint 1 and Sprint 2 deliverables:
- Core authentication (register/login/logout/me)
- Password hashing with bcrypt
- Session token validation with JWT + persisted session records
- RBAC models (User, Role, Permission)
- Authorization middleware and permission-protected endpoints
- Role assignment API

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Server runs on `http://127.0.0.1:5000`.

## API Summary

- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout` (Bearer token required)
- `GET /api/auth/me` (Bearer token required)
- `GET /api/admin/dashboard` (requires `admin:read` permission)
- `POST /api/rbac/assign-role` (requires `rbac:assign_role` permission)

## Test

```bash
pytest -q
```
