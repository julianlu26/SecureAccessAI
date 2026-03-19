# SecureAccessAI API Documentation (SP1 + SP3)

Base URL: `http://127.0.0.1:5000`

## Authentication

### GET /health
No authentication required.

Success 200:
{
  status: ok
}

### POST /api/auth/register
Request body:
```json
{
  "username": "lead",
  "email": "lead@example.com",
  "password": "Pass1234!"
}
```
Response `201`:
```json
{
  "id": 1,
  "username": "lead",
  "email": "lead@example.com",
  "roles": ["admin"]
}
```

### POST /api/auth/login
Request body:
```json
{
  "email": "lead@example.com",
  "password": "Pass1234!"
}
```
Response `200`:
```json
{
  "access_token": "<jwt>",
  "risk_assessment": {
    "score": 0,
    "signals": {
      "failed_attempt_burst": false,
      "failed_attempt_count": 0,
      "ip_change_detected": false,
      "rate_limited": false
    },
    "reasons": []
  }
}
```

Failure examples:
- `401` invalid credentials
- `403` repeated failed attempts threshold reached
- `429` rate limiter triggered

### POST /api/auth/logout
Headers:
- `Authorization: Bearer <jwt>`

Response `200`:
```json
{
  "message": "Logged out"
}
```

### GET /api/auth/me
Headers:
- `Authorization: Bearer <jwt>`

Response `200`:
```json
{
  "id": 1,
  "username": "lead",
  "email": "lead@example.com",
  "roles": ["admin"],
  "permissions": ["admin:read", "auth:read", "rbac:assign_role"]
}
```

## RBAC and Protected Endpoints

### GET /api/admin/dashboard
Permission required: `admin:read`

Headers:
- `Authorization: Bearer <jwt>`

Success `200`:
```json
{
  "message": "Admin dashboard data"
}
```

Failure `403`:
```json
{
  "error": "Forbidden"
}
```

### RBAC Protection Notes

- `GET /api/admin/dashboard` requires `admin:read`
- `GET /api/admin/security-events` requires `admin:read`
- `GET /api/admin/audit-logs` requires `admin:read`
- `GET /api/admin/risk-summary` requires `admin:read`
- `POST /api/rbac/assign-role` requires `rbac:assign_role`

### GET /api/admin/security-events
Permission required: `admin:read`

Headers:
- `Authorization: Bearer <jwt>`

Success `200`:
```json
{
  "events": [
    {
      "id": 1,
      "email": "lead@example.com",
      "ip_address": "10.0.0.31",
      "event_type": "login",
      "outcome": "success",
      "risk_score": 30,
      "detail": "new IP compared with recent successful login",
      "created_at": "2026-03-07T10:00:00"
    }
  ]
}
```

### GET /api/admin/audit-logs
Permission required: `admin:read`

Headers:
- `Authorization: Bearer <jwt>`

Success `200`:
```json
{
  "logs": [
    {
      "id": 1,
      "actor_user_id": 1,
      "action": "login",
      "target_email": "lead@example.com",
      "status": "success",
      "detail": "low risk",
      "created_at": "2026-03-18T10:00:00"
    }
  ]
}
```

### GET /api/admin/risk-summary
Permission required: `admin:read`

Headers:
- `Authorization: Bearer <jwt>`

Success `200`:
```json
{
  "system_summary": {
    "security_event_count": 6,
    "audit_log_count": 5,
    "blocked_attempt_count": 1,
    "failed_attempt_count": 3
  },
  "risk_summary": {
    "high_risk_user_count": 1,
    "medium_risk_user_count": 0,
    "users": [
      {
        "email": "peer@example.com",
        "failed_logins": 3,
        "blocked_logins": 1,
        "unique_ip_count": 1,
        "highest_risk_score": 40,
        "last_event_at": "2026-03-18T10:10:00",
        "evaluated_risk_score": 50,
        "risk_level": "medium"
      }
    ]
  }
}
```

### POST /api/rbac/assign-role
Permission required: `rbac:assign_role`

Request body:
```json
{
  "email": "peer@example.com",
  "role": "admin"
}
```

Success `200`:
```json
{
  "message": "Role assigned",
  "roles": ["user", "admin"]
}
```

Failure cases:
- `400` when `email` or `role` is missing
- `404` when the target user or requested role does not exist
