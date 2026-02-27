# SecureAccessAI API Documentation (SP1 + SP2)

Base URL: `http://127.0.0.1:5000`

## Authentication

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
  "access_token": "<jwt>"
}
```

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
