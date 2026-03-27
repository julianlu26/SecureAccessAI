from flask import Blueprint, current_app, g, jsonify, request

from app.middleware.auth import require_auth
from app.services.authentication_service import AuthenticationError, build_auth_service
from app.services.authorization_service import AuthorizationEngine

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")



def _client_ip() -> str:
    if current_app.config.get("TRUST_PROXY_HEADERS"):
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


@auth_bp.post("/register")
def register():
    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "").strip()
    email = payload.get("email", "").strip().lower()
    password = payload.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    try:
        user = build_auth_service().register(
            username=username,
            email=email,
            password=password,
            ip_address=_client_ip(),
        )
    except AuthenticationError:
        return jsonify({"error": "Unable to register account"}), 400

    return (
        jsonify(
            {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "roles": [role.name for role in user.roles],
            }
        ),
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
        result = build_auth_service().login(
            email=email,
            password=password,
            ip_address=_client_ip(),
        )
    except AuthenticationError as exc:
        return jsonify({"error": str(exc), "risk_assessment": exc.risk_assessment}), exc.status_code

    return jsonify(result)


@auth_bp.post("/verify-code")
def verify_code():
    payload = request.get_json(silent=True) or {}
    challenge_id = payload.get("challenge_id", "").strip()
    code = payload.get("code", "").strip()

    if not challenge_id or not code:
        return jsonify({"error": "challenge_id and code are required"}), 400

    try:
        token, risk_assessment = build_auth_service().verify_code(
            challenge_id=challenge_id,
            code=code,
            ip_address=_client_ip(),
        )
    except AuthenticationError as exc:
        return jsonify({"error": str(exc), "risk_assessment": exc.risk_assessment}), exc.status_code

    return jsonify({"access_token": token, "risk_assessment": risk_assessment})


@auth_bp.post("/logout")
@require_auth
def logout():
    build_auth_service().logout(g.current_token, ip_address=_client_ip())
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
