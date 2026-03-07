from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from flask import current_app, has_app_context

from app.config import Config
from app.extensions import db
from app.models import SecurityEvent, User


class IPMonitor:
    def log_event(
        self,
        *,
        user: User | None,
        email: str,
        ip_address: str,
        event_type: str,
        outcome: str,
        risk_score: int = 0,
        detail: str | None = None,
    ) -> SecurityEvent:
        event = SecurityEvent(
            user_id=user.id if user else None,
            email=email,
            ip_address=ip_address,
            event_type=event_type,
            outcome=outcome,
            risk_score=risk_score,
            detail=detail,
        )
        db.session.add(event)
        db.session.flush()
        return event

    def recent_failed_attempts(self, *, email: str, ip_address: str, window_minutes: int) -> int:
        since = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=window_minutes)
        return (
            SecurityEvent.query.filter(
                SecurityEvent.email == email,
                SecurityEvent.ip_address == ip_address,
                SecurityEvent.event_type == "login",
                SecurityEvent.outcome.in_(("failed", "blocked")),
                SecurityEvent.created_at >= since,
            ).count()
        )

    def recent_ip_change(self, *, user: User | None, email: str, ip_address: str, lookback_hours: int) -> bool:
        since = datetime.now(UTC).replace(tzinfo=None) - timedelta(hours=lookback_hours)
        query = SecurityEvent.query.filter(
            SecurityEvent.event_type == "login",
            SecurityEvent.outcome == "success",
            SecurityEvent.created_at >= since,
        )
        if user:
            query = query.filter(SecurityEvent.user_id == user.id)
        else:
            query = query.filter(SecurityEvent.email == email)
        latest_success = query.order_by(SecurityEvent.created_at.desc()).first()
        return bool(latest_success and latest_success.ip_address != ip_address)


class RateLimiter:
    _attempts: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    def __init__(self, limit: int, window_seconds: int):
        self.limit = limit
        self.window_seconds = window_seconds

    def allow(self, *, ip_address: str, email: str) -> bool:
        key = (ip_address, email)
        now = datetime.now(UTC)
        window_start = now - timedelta(seconds=self.window_seconds)
        attempts = [stamp for stamp in self._attempts[key] if stamp >= window_start]
        if len(attempts) >= self.limit:
            self._attempts[key] = attempts
            return False
        attempts.append(now)
        self._attempts[key] = attempts
        return True

    @classmethod
    def reset(cls) -> None:
        cls._attempts.clear()


class AnomalyDetector(ABC):
    @abstractmethod
    def detect(self, *, user: User | None, email: str, ip_address: str, rate_limited: bool) -> dict:
        raise NotImplementedError


class BasicAnomalyDetector(AnomalyDetector):
    def __init__(self, ip_monitor: IPMonitor, config: Config):
        self.ip_monitor = ip_monitor
        self.config = config

    def detect(self, *, user: User | None, email: str, ip_address: str, rate_limited: bool) -> dict:
        failed_attempts = self.ip_monitor.recent_failed_attempts(
            email=email,
            ip_address=ip_address,
            window_minutes=self.config.LOGIN_FAILURE_WINDOW_MINUTES,
        )
        return {
            "failed_attempt_burst": failed_attempts >= self.config.LOGIN_FAILURE_THRESHOLD,
            "failed_attempt_count": failed_attempts,
            "ip_change_detected": self.ip_monitor.recent_ip_change(
                user=user,
                email=email,
                ip_address=ip_address,
                lookback_hours=self.config.RISK_IP_LOOKBACK_HOURS,
            ),
            "rate_limited": rate_limited,
        }


class ThreatScoringEngine:
    def score(self, signals: dict) -> tuple[int, list[str]]:
        score = 0
        reasons: list[str] = []

        if signals.get("failed_attempt_burst"):
            score += 35
            reasons.append("failed attempt threshold reached")
        elif signals.get("failed_attempt_count", 0) > 0:
            score += min(20, signals["failed_attempt_count"] * 5)
            reasons.append("repeated failed attempts")

        if signals.get("ip_change_detected"):
            score += 30
            reasons.append("new IP compared with recent successful login")

        if signals.get("rate_limited"):
            score += 40
            reasons.append("rate limiter triggered")

        return min(score, 100), reasons


def build_security_components() -> tuple[IPMonitor, RateLimiter, BasicAnomalyDetector, ThreatScoringEngine]:
    config = Config()
    if has_app_context():
        for key in (
            "LOGIN_RATE_LIMIT_COUNT",
            "LOGIN_RATE_LIMIT_WINDOW_SECONDS",
            "LOGIN_FAILURE_THRESHOLD",
            "LOGIN_FAILURE_WINDOW_MINUTES",
            "RISK_IP_LOOKBACK_HOURS",
        ):
            setattr(config, key, current_app.config.get(key, getattr(config, key)))
    ip_monitor = IPMonitor()
    rate_limiter = RateLimiter(
        limit=config.LOGIN_RATE_LIMIT_COUNT,
        window_seconds=config.LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    )
    anomaly_detector = BasicAnomalyDetector(ip_monitor=ip_monitor, config=config)
    threat_engine = ThreatScoringEngine()
    return ip_monitor, rate_limiter, anomaly_detector, threat_engine
