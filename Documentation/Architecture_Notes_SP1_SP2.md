# Architecture Notes (SP1 + SP2)

This document summarizes the early architecture decisions for the SecureAccessAI backend.

## Layered Structure

- `routes`: HTTP endpoints and request/response handling
- `middleware`: authentication and authorization gatekeeping
- `services`: business logic such as authentication, RBAC, and security rules
- `repositories`: persistence access wrappers for entities such as `User`
- `models`: SQLAlchemy entities and relationship definitions

## Core SP1 Design Decisions

- Flask was kept modular to avoid placing all logic in route files.
- Password storage uses bcrypt to prevent plain-text credential persistence.
- JWT was combined with persisted session records so tokens can be revoked on logout.
- The first registered user is bootstrapped as admin to simplify initial setup.

## Core SP2 Design Decisions

- RBAC is modeled with explicit `Role` and `Permission` entities.
- Authorization checks are separated from route handlers via middleware and policy abstractions.
- `AuthorizationEngine` resolves effective permissions from assigned roles.
- `PolicyEngine` provides an extension point for future non-RBAC policy rules.

## Request Flow Summary

1. A request enters a Flask route.
2. Authentication middleware validates the bearer token if required.
3. Authorization middleware checks the required permission for protected endpoints.
4. Services execute business logic and update persistence models.
5. JSON responses are returned to the client.
