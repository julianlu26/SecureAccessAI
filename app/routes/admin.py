from flask import Blueprint, current_app, jsonify

from app.middleware.auth import require_permission
from app.models import AuditLog, SecurityEvent
from app.services.behaviour_service import BehaviourAnalyzer, RiskEvaluator

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

DASHBOARD_RECENT_LIMIT = 5
ADMIN_FEED_LIMIT = 20


@admin_bp.get("/dashboard")
@require_permission("admin:read")
def admin_dashboard():
    analyzer = BehaviourAnalyzer()
    evaluator = RiskEvaluator()
    user_metrics = analyzer.user_metrics()
    return jsonify(
        {
            "system_summary": analyzer.system_metrics(),
            "risk_summary": _serialize_risk_summary(evaluator.evaluate_system(user_metrics)),
            "recent_security_events": _serialize_security_events(_recent_security_events(DASHBOARD_RECENT_LIMIT)),
            "recent_audit_logs": _serialize_audit_logs(_recent_audit_logs(DASHBOARD_RECENT_LIMIT)),
            "data_governance": _data_governance_notice(),
        }
    )


@admin_bp.get("/security-events")
@require_permission("admin:read")
def security_events():
    return jsonify(
        {
            "events": _serialize_security_events(_recent_security_events(ADMIN_FEED_LIMIT)),
            "data_governance": _data_governance_notice(),
        }
    )


@admin_bp.get("/audit-logs")
@require_permission("admin:read")
def audit_logs():
    return jsonify(
        {
            "logs": _serialize_audit_logs(_recent_audit_logs(ADMIN_FEED_LIMIT)),
            "data_governance": _data_governance_notice(),
        }
    )


@admin_bp.get("/risk-summary")
@require_permission("admin:read")
def risk_summary():
    analyzer = BehaviourAnalyzer()
    evaluator = RiskEvaluator()
    user_metrics = analyzer.user_metrics()
    return jsonify(
        {
            "system_summary": analyzer.system_metrics(),
            "risk_summary": _serialize_risk_summary(evaluator.evaluate_system(user_metrics)),
            "data_governance": _data_governance_notice(),
        }
    )


def _recent_security_events(limit: int) -> list[SecurityEvent]:
    return SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()


def _recent_audit_logs(limit: int) -> list[AuditLog]:
    return AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()


def _show_full_pii() -> bool:
    return bool(current_app.config.get("ADMIN_SHOW_FULL_PII", False))


def _mask_email(email: str | None) -> str | None:
    if not email or _show_full_pii():
        return email
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    local_mask = f"{local[:1]}***" if local else "***"
    domain_parts = domain.split(".")
    domain_name = domain_parts[0]
    domain_mask = f"{domain_name[:1]}***" if domain_name else "***"
    suffix = f".{'.'.join(domain_parts[1:])}" if len(domain_parts) > 1 else ""
    return f"{local_mask}@{domain_mask}{suffix}"


def _mask_ip(ip_address: str | None) -> str | None:
    if not ip_address or _show_full_pii():
        return ip_address
    if ":" in ip_address:
        head = ip_address.split(":", 1)[0]
        return f"{head}:****:****"
    parts = ip_address.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.***.***"
    return "***"


def _serialize_security_events(events: list[SecurityEvent]) -> list[dict]:
    return [
        {
            "id": event.id,
            "email": _mask_email(event.email),
            "ip_address": _mask_ip(event.ip_address),
            "event_type": event.event_type,
            "outcome": event.outcome,
            "risk_score": event.risk_score,
            "detail": event.detail,
            "created_at": event.created_at.isoformat(),
        }
        for event in events
    ]


def _serialize_audit_logs(logs: list[AuditLog]) -> list[dict]:
    return [
        {
            "id": log.id,
            "actor_user_id": log.actor_user_id,
            "action": log.action,
            "target_email": _mask_email(log.target_email),
            "status": log.status,
            "detail": log.detail,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]


def _serialize_risk_summary(summary: dict) -> dict:
    return {
        **summary,
        "users": [
            {
                **user,
                "email": _mask_email(user.get("email")),
            }
            for user in summary.get("users", [])
        ],
    }


def _data_governance_notice() -> dict:
    return {
        "pii_mode": "full" if _show_full_pii() else "masked",
        "controls": [
            "Time-limited verification codes are required before issuing a session token.",
            "Administrative feeds mask personal identifiers by default.",
            "Personal data exposure is limited to least-necessary administrative use.",
        ],
    }
