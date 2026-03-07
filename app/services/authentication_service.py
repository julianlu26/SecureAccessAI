from datetime import UTC, datetime, timedelta
import uuid

import jwt
from flask import current_app, has_app_context

from app.config import Config
from app.extensions import db
from app.models import Role, SessionToken, User
from app.repositories.user_repository import UserRepository
from app.services.security_service import build_security_components


class AuthenticationError(Exception):
    def __init__(self, message: str, *, status_code: int = 401, risk_assessment: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.risk_assessment = risk_assessment or {}


class AuthenticationService:
    def __init__(self, secret_key: str, expires_minutes: int):
        self.user_repo = UserRepository()
        self.secret_key = secret_key
        self.expires_minutes = expires_minutes

    def register(self, username: str, email: str, password: str) -> User:
        existing = self.user_repo.get_by_email(email)
        if existing:
            raise AuthenticationError("Email already exists")

        user = self.user_repo.create(username=username, email=email, password=password)

        admin_role = Role.query.filter_by(name="admin").first()
        user_role = Role.query.filter_by(name="user").first()

        # Bootstrap rule: first account becomes admin, others become user.
        total_users = User.query.count()
        if total_users == 1 and admin_role:
            user.roles.append(admin_role)
        elif user_role:
            user.roles.append(user_role)

        db.session.commit()
        return user

    def login(self, email: str, password: str, ip_address: str) -> tuple[str, dict]:
        ip_monitor, rate_limiter, anomaly_detector, threat_engine = build_security_components()

        if not rate_limiter.allow(ip_address=ip_address, email=email):
            signals = anomaly_detector.detect(
                user=None,
                email=email,
                ip_address=ip_address,
                rate_limited=True,
            )
            risk_score, reasons = threat_engine.score(signals)
            ip_monitor.log_event(
                user=None,
                email=email,
                ip_address=ip_address,
                event_type="login",
                outcome="blocked",
                risk_score=risk_score,
                detail="rate limit triggered",
            )
            db.session.commit()
            raise AuthenticationError(
                "Too many login attempts",
                status_code=429,
                risk_assessment={"score": risk_score, "signals": signals, "reasons": reasons},
            )

        failed_attempts = ip_monitor.recent_failed_attempts(
            email=email,
            ip_address=ip_address,
            window_minutes=self.config.LOGIN_FAILURE_WINDOW_MINUTES,
        )
        if failed_attempts >= self.config.LOGIN_FAILURE_THRESHOLD:
            signals = anomaly_detector.detect(
                user=None,
                email=email,
                ip_address=ip_address,
                rate_limited=False,
            )
            risk_score, reasons = threat_engine.score(signals)
            ip_monitor.log_event(
                user=None,
                email=email,
                ip_address=ip_address,
                event_type="login",
                outcome="blocked",
                risk_score=risk_score,
                detail="failure threshold reached",
            )
            db.session.commit()
            raise AuthenticationError(
                "Login temporarily blocked due to repeated failed attempts",
                status_code=403,
                risk_assessment={"score": risk_score, "signals": signals, "reasons": reasons},
            )

        user = self.user_repo.get_by_email(email)
        if not user or not user.check_password(password):
            event = ip_monitor.log_event(
                user=user,
                email=email,
                ip_address=ip_address,
                event_type="login",
                outcome="failed",
                detail="invalid credentials",
            )
            signals = anomaly_detector.detect(
                user=user,
                email=email,
                ip_address=ip_address,
                rate_limited=False,
            )
            risk_score, reasons = threat_engine.score(signals)
            event.risk_score = risk_score
            event.detail = ", ".join(reasons) if reasons else "invalid credentials"
            db.session.commit()
            failure_message = "Invalid credentials"
            if signals["failed_attempt_count"] >= self.config.LOGIN_FAILURE_THRESHOLD:
                failure_message = "Login temporarily blocked due to repeated failed attempts"
            raise AuthenticationError(
                failure_message,
                status_code=403 if failure_message != "Invalid credentials" else 401,
                risk_assessment={"score": risk_score, "signals": signals, "reasons": reasons},
            )

        if not user.is_active:
            raise AuthenticationError("User is inactive")

        now = datetime.now(UTC)
        exp = now + timedelta(minutes=self.expires_minutes)
        jti = uuid.uuid4().hex

        payload = {
            "sub": user.id,
            "jti": jti,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
        }
        token = jwt.encode(payload, self.secret_key, algorithm="HS256")

        # Store naive UTC in SQLite for predictable comparisons.
        session = SessionToken(
            jti=jti,
            user_id=user.id,
            issued_at=now.replace(tzinfo=None),
            expires_at=exp.replace(tzinfo=None),
            revoked=False,
        )
        db.session.add(session)
        signals = anomaly_detector.detect(
            user=user,
            email=email,
            ip_address=ip_address,
            rate_limited=False,
        )
        risk_score, reasons = threat_engine.score(signals)
        ip_monitor.log_event(
            user=user,
            email=email,
            ip_address=ip_address,
            event_type="login",
            outcome="success",
            risk_score=risk_score,
            detail=", ".join(reasons) if reasons else "low risk",
        )
        db.session.commit()

        return token, {"score": risk_score, "signals": signals, "reasons": reasons}

    def logout(self, token: str) -> None:
        payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
        jti = payload.get("jti")
        session = SessionToken.query.filter_by(jti=jti).first()
        if session:
            session.revoked = True
            db.session.commit()

    def validate_token(self, token: str) -> User:
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
        except jwt.PyJWTError as exc:
            raise AuthenticationError("Invalid or expired token") from exc

        user_id = payload.get("sub")
        jti = payload.get("jti")

        if not user_id or not jti:
            raise AuthenticationError("Malformed token")

        session = SessionToken.query.filter_by(jti=jti, user_id=user_id).first()
        if not session:
            raise AuthenticationError("Session not found")
        if session.revoked:
            raise AuthenticationError("Session revoked")
        if session.expires_at < datetime.now(UTC).replace(tzinfo=None):
            raise AuthenticationError("Session expired")

        user = self.user_repo.get_by_id(user_id)
        if not user or not user.is_active:
            raise AuthenticationError("User not found or inactive")

        return user

    @property
    def config(self) -> Config:
        config = Config()
        if has_app_context():
            for key in (
                "SECRET_KEY",
                "JWT_EXPIRES_MINUTES",
                "LOGIN_FAILURE_THRESHOLD",
                "LOGIN_FAILURE_WINDOW_MINUTES",
            ):
                setattr(config, key, current_app.config.get(key, getattr(config, key)))
        return config


def build_auth_service() -> AuthenticationService:
    cfg = Config()
    if has_app_context():
        cfg.SECRET_KEY = current_app.config.get("SECRET_KEY", cfg.SECRET_KEY)
        cfg.JWT_EXPIRES_MINUTES = current_app.config.get("JWT_EXPIRES_MINUTES", cfg.JWT_EXPIRES_MINUTES)
    return AuthenticationService(secret_key=cfg.SECRET_KEY, expires_minutes=cfg.JWT_EXPIRES_MINUTES)
