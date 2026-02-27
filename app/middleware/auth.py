from functools import wraps

from flask import g, jsonify, request

from app.services.authentication_service import AuthenticationError, build_auth_service
from app.services.authorization_service import AuthorizationEngine, DefaultPolicyEngine


def _extract_bearer_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header.replace("Bearer ", "", 1).strip()


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = _extract_bearer_token()
        if not token:
            return jsonify({"error": "Missing bearer token"}), 401

        auth_service = build_auth_service()
        try:
            user = auth_service.validate_token(token)
        except AuthenticationError as exc:
            return jsonify({"error": str(exc)}), 401

        g.current_user = user
        g.current_token = token
        return fn(*args, **kwargs)

    return wrapper


def require_permission(permission_name: str):
    def decorator(fn):
        @wraps(fn)
        @require_auth
        def wrapper(*args, **kwargs):
            engine = AuthorizationEngine()
            policy = DefaultPolicyEngine(engine)
            if not policy.is_allowed(g.current_user, permission_name):
                return jsonify({"error": "Forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator
