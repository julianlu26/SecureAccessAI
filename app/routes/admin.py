from flask import Blueprint, jsonify

from app.middleware.auth import require_permission

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/dashboard")
@require_permission("admin:read")
def admin_dashboard():
    return jsonify({"message": "Admin dashboard data"})
