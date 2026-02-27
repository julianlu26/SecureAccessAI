from flask import Blueprint, g, jsonify, request

from app.middleware.auth import require_auth
from app.services.authentication_service import AuthenticationError, build_auth_service
from app.services.authorization_service import AuthorizationEngine

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@auth_bp.post("/register")
def register():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "").strip()
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    try:
        user = build_auth_service().register(username=username, email=email, password=password)
    except AuthenticationError as exc:
        return jsonify({"error": str(exc)}), 400

    return (
        jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles],
        }),
        201,
    )


@auth_bp.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    try:
        token = build_auth_service().login(email=email, password=password)
    except AuthenticationError as exc:
        return jsonify({"error": str(exc)}), 401

    return jsonify({"access_token": token})


@auth_bp.post("/logout")
@require_auth
def logout():
    build_auth_service().logout(g.current_token)
    return jsonify({"message": "Logged out"})


@auth_bp.get("/me")
@require_auth
def me():
    user = g.current_user
    authz = AuthorizationEngine()
    return jsonify(
        {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "roles": [role.name for role in user.roles],
            "permissions": sorted(list(authz.collect_permissions(user))),
        }
    )
