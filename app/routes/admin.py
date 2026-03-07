from flask import Blueprint, jsonify

from app.middleware.auth import require_permission
from app.models import SecurityEvent

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")


@admin_bp.get("/dashboard")
@require_permission("admin:read")
def admin_dashboard():
    return jsonify({"message": "Admin dashboard data"})


@admin_bp.get("/security-events")
@require_permission("admin:read")
def security_events():
    events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(20).all()
    return jsonify(
        {
            "events": [
                {
                    "id": event.id,
                    "email": event.email,
                    "ip_address": event.ip_address,
                    "event_type": event.event_type,
                    "outcome": event.outcome,
                    "risk_score": event.risk_score,
                    "detail": event.detail,
                    "created_at": event.created_at.isoformat(),
                }
                for event in events
            ]
        }
    )
