from flask import Blueprint, jsonify

from app.middleware.auth import require_permission
from app.models import AuditLog, SecurityEvent
from app.services.behaviour_service import BehaviourAnalyzer, RiskEvaluator

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

DASHBOARD_RECENT_LIMIT = 5
ADMIN_FEED_LIMIT = 20


@admin_bp.get('/dashboard')
@require_permission('admin:read')
def admin_dashboard():
    analyzer = BehaviourAnalyzer()
    evaluator = RiskEvaluator()
    user_metrics = analyzer.user_metrics()
    return jsonify(
        {
            'system_summary': analyzer.system_metrics(),
            'risk_summary': evaluator.evaluate_system(user_metrics),
            'recent_security_events': _serialize_security_events(_recent_security_events(DASHBOARD_RECENT_LIMIT)),
            'recent_audit_logs': _serialize_audit_logs(_recent_audit_logs(DASHBOARD_RECENT_LIMIT)),
        }
    )


@admin_bp.get('/security-events')
@require_permission('admin:read')
def security_events():
    return jsonify({'events': _serialize_security_events(_recent_security_events(ADMIN_FEED_LIMIT))})


@admin_bp.get('/audit-logs')
@require_permission('admin:read')
def audit_logs():
    return jsonify({'logs': _serialize_audit_logs(_recent_audit_logs(ADMIN_FEED_LIMIT))})


@admin_bp.get('/risk-summary')
@require_permission('admin:read')
def risk_summary():
    analyzer = BehaviourAnalyzer()
    evaluator = RiskEvaluator()
    user_metrics = analyzer.user_metrics()
    return jsonify(
        {
            'system_summary': analyzer.system_metrics(),
            'risk_summary': evaluator.evaluate_system(user_metrics),
        }
    )


def _recent_security_events(limit: int) -> list[SecurityEvent]:
    return SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(limit).all()


def _recent_audit_logs(limit: int) -> list[AuditLog]:
    return AuditLog.query.order_by(AuditLog.created_at.desc()).limit(limit).all()


def _serialize_security_events(events: list[SecurityEvent]) -> list[dict]:
    return [
        {
            'id': event.id,
            'email': event.email,
            'ip_address': event.ip_address,
            'event_type': event.event_type,
            'outcome': event.outcome,
            'risk_score': event.risk_score,
            'detail': event.detail,
            'created_at': event.created_at.isoformat(),
        }
        for event in events
    ]


def _serialize_audit_logs(logs: list[AuditLog]) -> list[dict]:
    return [
        {
            'id': log.id,
            'actor_user_id': log.actor_user_id,
            'action': log.action,
            'target_email': log.target_email,
            'status': log.status,
            'detail': log.detail,
            'created_at': log.created_at.isoformat(),
        }
        for log in logs
    ]
