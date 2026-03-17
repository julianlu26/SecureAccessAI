from collections import defaultdict

from app.models import AuditLog, SecurityEvent


class BehaviourAnalyzer:
    def user_metrics(self) -> list[dict]:
        grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
        for event in SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).all():
            grouped[event.email].append(event)

        metrics: list[dict] = []
        for email, events in grouped.items():
            unique_ips = {event.ip_address for event in events}
            failed_logins = sum(1 for event in events if event.outcome == "failed")
            blocked_logins = sum(1 for event in events if event.outcome == "blocked")
            highest_risk = max((event.risk_score for event in events), default=0)
            metrics.append(
                {
                    "email": email,
                    "failed_logins": failed_logins,
                    "blocked_logins": blocked_logins,
                    "unique_ip_count": len(unique_ips),
                    "highest_risk_score": highest_risk,
                    "last_event_at": events[0].created_at.isoformat(),
                }
            )

        return sorted(metrics, key=lambda item: item["highest_risk_score"], reverse=True)

    def system_metrics(self) -> dict:
        security_events = SecurityEvent.query.count()
        audit_logs = AuditLog.query.count()
        blocked_attempts = SecurityEvent.query.filter_by(outcome="blocked").count()
        failed_attempts = SecurityEvent.query.filter_by(outcome="failed").count()
        return {
            "security_event_count": security_events,
            "audit_log_count": audit_logs,
            "blocked_attempt_count": blocked_attempts,
            "failed_attempt_count": failed_attempts,
        }


class RiskEvaluator:
    def evaluate_user(self, metrics: dict) -> dict:
        score = metrics["highest_risk_score"]
        if metrics["blocked_logins"] > 0:
            score = min(100, score + 10)
        if metrics["unique_ip_count"] > 1:
            score = min(100, score + 5)

        if score >= 60:
            level = "high"
        elif score >= 25:
            level = "medium"
        else:
            level = "low"

        return {
            **metrics,
            "evaluated_risk_score": score,
            "risk_level": level,
        }

    def evaluate_system(self, metrics: list[dict]) -> dict:
        evaluated = [self.evaluate_user(item) for item in metrics]
        return {
            "high_risk_user_count": sum(1 for item in evaluated if item["risk_level"] == "high"),
            "medium_risk_user_count": sum(1 for item in evaluated if item["risk_level"] == "medium"),
            "users": evaluated,
        }
