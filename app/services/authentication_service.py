from datetime import UTC, datetime, timedelta
import hashlib
import secrets
import uuid

import jwt
from flask import current_app, has_app_context

from app.config import Config
from app.extensions import db
from app.models import LoginChallenge, Role, SessionToken, User
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditLogger
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
        self.audit_logger = AuditLogger()

    def register(self, username: str, email: str, password: str) -> User:
        existing = self.user_repo.get_by_email(email)
        if existing:
            raise AuthenticationError("Email already exists")

        user = self.user_repo.create(username=username, email=email, password=password)

        admin_role = Role.query.filter_by(name="admin").first()
        user_role = Role.query.filter_by(name="user").first()

        total_users = User.query.count()
        bootstrap_admin_email = self.config.BOOTSTRAP_ADMIN_EMAIL
        if total_users == 1 and admin_role and bootstrap_admin_email and email == bootstrap_admin_email:
            user.roles.append(admin_role)
        elif user_role:
            user.roles.append(user_role)

        self.audit_logger.log(
            actor_user=user,
            action="register",
            status="success",
            target_email=user.email,
            detail="account created",
        )
        db.session.commit()
        return user

    def login(self, email: str, password: str, ip_address: str) -> dict:
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
            self.audit_logger.log(
                actor_user=None,
                action="login",
                status="blocked",
                target_email=email,
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
            self.audit_logger.log(
                actor_user=None,
                action="login",
                status="blocked",
                target_email=email,
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
            self.audit_logger.log(
                actor_user=user,
                action="login",
                status="failed",
                target_email=email,
                detail=event.detail,
            )
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

        risk_assessment = self._build_risk_assessment(user=user, email=email, ip_address=ip_address)

        if self.config.MFA_ENABLED:
            challenge, demo_code = self._create_login_challenge(user=user, email=email, ip_address=ip_address)
            ip_monitor.log_event(
                user=user,
                email=email,
                ip_address=ip_address,
                event_type="login_mfa",
                outcome="challenge",
                risk_score=risk_assessment["score"],
                detail="time-limited one-time code issued",
            )
            self.audit_logger.log(
                actor_user=user,
                action="login_challenge",
                status="success",
                target_email=email,
                detail="time-limited verification code issued",
            )
            db.session.commit()

            response = {
                "mfa_required": True,
                "challenge_id": challenge.challenge_id,
                "expires_in_seconds": self.config.MFA_CODE_TTL_SECONDS,
                "risk_assessment": risk_assessment,
            }
            if self.config.SHOW_DEMO_MFA_CODE or self.config.TESTING:
                response["demo_code"] = demo_code
            return response

        token = self._issue_session_token(user)
        ip_monitor.log_event(
            user=user,
            email=email,
            ip_address=ip_address,
            event_type="login",
            outcome="success",
            risk_score=risk_assessment["score"],
            detail=", ".join(risk_assessment["reasons"]) if risk_assessment["reasons"] else "low risk",
        )
        self.audit_logger.log(
            actor_user=user,
            action="login",
            status="success",
            target_email=email,
            detail="password login completed",
        )
        db.session.commit()
        return {"access_token": token, "risk_assessment": risk_assessment}

    def verify_code(self, challenge_id: str, code: str, ip_address: str) -> tuple[str, dict]:
        challenge = LoginChallenge.query.filter_by(challenge_id=challenge_id).first()
        if not challenge:
            raise AuthenticationError("Invalid verification challenge")
        if challenge.consumed:
            raise AuthenticationError("Verification code already used")
        if challenge.expires_at < datetime.now(UTC).replace(tzinfo=None):
            challenge.consumed = True
            db.session.commit()
            raise AuthenticationError("Verification code expired")
        if self.config.MFA_REQUIRE_SAME_IP and challenge.ip_address != ip_address:
            raise AuthenticationError("Verification request must come from the same client")
        if challenge.code_hash != self._hash_login_code(challenge.challenge_id, code):
            self.audit_logger.log(
                actor_user=challenge.user,
                action="login_code",
                status="failed",
                target_email=challenge.email,
                detail="invalid verification code",
            )
            db.session.commit()
            raise AuthenticationError("Invalid verification code")

        challenge.consumed = True
        user = challenge.user
        risk_assessment = self._build_risk_assessment(user=user, email=user.email, ip_address=ip_address)
        token = self._issue_session_token(user)

        ip_monitor, _, _, _ = build_security_components()
        ip_monitor.log_event(
            user=user,
            email=user.email,
            ip_address=ip_address,
            event_type="login",
            outcome="success",
            risk_score=risk_assessment["score"],
            detail="time-limited verification code accepted",
        )
        self.audit_logger.log(
            actor_user=user,
            action="login",
            status="success",
            target_email=user.email,
            detail="time-limited verification code accepted",
        )
        db.session.commit()
        return token, risk_assessment

    def logout(self, token: str) -> None:
        payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
        jti = payload.get("jti")
        session = SessionToken.query.filter_by(jti=jti).first()
        if session:
            session.revoked = True
            self.audit_logger.log(
                actor_user=session.user,
                action="logout",
                status="success",
                target_email=session.user.email,
                detail="session revoked",
            )
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

    def _build_risk_assessment(self, *, user: User | None, email: str, ip_address: str) -> dict:
        _, _, anomaly_detector, threat_engine = build_security_components()
        signals = anomaly_detector.detect(
            user=user,
            email=email,
            ip_address=ip_address,
            rate_limited=False,
        )
        risk_score, reasons = threat_engine.score(signals)
        return {"score": risk_score, "signals": signals, "reasons": reasons}

    def _create_login_challenge(self, *, user: User, email: str, ip_address: str) -> tuple[LoginChallenge, str]:
        LoginChallenge.query.filter_by(user_id=user.id, consumed=False).update({"consumed": True})
        code = f"{secrets.randbelow(1000000):06d}"
        challenge_id = uuid.uuid4().hex
        expires_at = datetime.now(UTC) + timedelta(seconds=self.config.MFA_CODE_TTL_SECONDS)
        challenge = LoginChallenge(
            challenge_id=challenge_id,
            user_id=user.id,
            email=email,
            ip_address=ip_address,
            code_hash=self._hash_login_code(challenge_id, code),
            expires_at=expires_at.replace(tzinfo=None),
            consumed=False,
        )
        db.session.add(challenge)
        db.session.flush()
        return challenge, code

    def _issue_session_token(self, user: User) -> str:
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

        session = SessionToken(
            jti=jti,
            user_id=user.id,
            issued_at=now.replace(tzinfo=None),
            expires_at=exp.replace(tzinfo=None),
            revoked=False,
        )
        db.session.add(session)
        return token

    def _hash_login_code(self, challenge_id: str, code: str) -> str:
        raw = f"{challenge_id}:{code}:{self.secret_key}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @property
    def config(self) -> Config:
        config = Config()
        if has_app_context():
            for key in (
                "TESTING",
                "SECRET_KEY",
                "JWT_EXPIRES_MINUTES",
                "LOGIN_FAILURE_THRESHOLD",
                "LOGIN_FAILURE_WINDOW_MINUTES",
                "BOOTSTRAP_ADMIN_EMAIL",
                "MFA_ENABLED",
                "MFA_CODE_TTL_SECONDS",
                "MFA_REQUIRE_SAME_IP",
                "SHOW_DEMO_MFA_CODE",
            ):
                setattr(config, key, current_app.config.get(key, getattr(config, key)))
        return config


def build_auth_service() -> AuthenticationService:
    cfg = Config()
    if has_app_context():
        cfg.SECRET_KEY = current_app.config.get("SECRET_KEY", cfg.SECRET_KEY)
        cfg.JWT_EXPIRES_MINUTES = current_app.config.get("JWT_EXPIRES_MINUTES", cfg.JWT_EXPIRES_MINUTES)
    return AuthenticationService(secret_key=cfg.SECRET_KEY, expires_minutes=cfg.JWT_EXPIRES_MINUTES)
