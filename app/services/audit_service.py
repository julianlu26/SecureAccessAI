from app.extensions import db
from app.models import AuditLog, User


class AuditLogger:
    def log(
        self,
        *,
        actor_user: User | None,
        action: str,
        status: str,
        target_email: str | None = None,
        detail: str | None = None,
    ) -> AuditLog:
        entry = AuditLog(
            actor_user_id=actor_user.id if actor_user else None,
            action=action,
            target_email=target_email,
            status=status,
            detail=detail,
        )
        db.session.add(entry)
        db.session.flush()
        return entry
