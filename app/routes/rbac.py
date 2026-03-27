from flask import Blueprint, current_app, g, jsonify, request

from app.extensions import db
from app.middleware.auth import require_permission
from app.models import User
from app.services.audit_service import AuditLogger
from app.services.authorization_service import RBACService

rbac_bp = Blueprint("rbac", __name__, url_prefix="/api/rbac")



def _client_ip() -> str:
    if current_app.config.get("TRUST_PROXY_HEADERS"):
        forwarded_for = request.headers.get("X-Forwarded-For", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


@rbac_bp.post("/assign-role")
@require_permission("rbac:assign_role")
def assign_role():
    payload = request.get_json(silent=True) or {}
    email = payload.get("email", "").strip().lower()
    role_name = payload.get("role", "").strip().lower()

    if not email or not role_name:
        return jsonify({"error": "email and role are required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    ok = RBACService().assign_role(user, role_name)
    if not ok:
        return jsonify({"error": "Role not found"}), 404

    AuditLogger().log(
        actor_user=g.current_user,
        action="assign_role",
        status="success",
        target_email=user.email,
        detail=f"assigned role={role_name}; ip={_client_ip()}",
    )
    db.session.commit()
    return jsonify({"message": "Role assigned", "roles": [r.name for r in user.roles]})
