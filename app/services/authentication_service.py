from datetime import UTC, datetime, timedelta
import uuid

import jwt

from app.config import Config
from app.extensions import db
from app.models import Role, SessionToken, User
from app.repositories.user_repository import UserRepository


class AuthenticationError(Exception):
    pass


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

    def login(self, email: str, password: str) -> str:
        user = self.user_repo.get_by_email(email)
        if not user or not user.check_password(password):
            raise AuthenticationError("Invalid credentials")

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
        db.session.commit()

        return token

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


def build_auth_service() -> AuthenticationService:
    cfg = Config()
    return AuthenticationService(secret_key=cfg.SECRET_KEY, expires_minutes=cfg.JWT_EXPIRES_MINUTES)
