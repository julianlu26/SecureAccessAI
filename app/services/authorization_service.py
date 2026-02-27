from abc import ABC, abstractmethod

from app.extensions import db
from app.models import Permission, Role, User


class AuthorizationEngine:
    def has_permission(self, user: User, permission_name: str) -> bool:
        return permission_name in self.collect_permissions(user)

    def collect_permissions(self, user: User) -> set[str]:
        perms: set[str] = set()
        for role in user.roles:
            for permission in role.permissions:
                perms.add(permission.name)
        return perms


class PolicyEngine(ABC):
    @abstractmethod
    def is_allowed(self, user: User, permission_name: str) -> bool:
        raise NotImplementedError


class DefaultPolicyEngine(PolicyEngine):
    def __init__(self, authorization_engine: AuthorizationEngine):
        self.authorization_engine = authorization_engine

    def is_allowed(self, user: User, permission_name: str) -> bool:
        return self.authorization_engine.has_permission(user, permission_name)


class RBACService:
    def assign_role(self, user: User, role_name: str) -> bool:
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            return False
        if role not in user.roles:
            user.roles.append(role)
        return True


def seed_rbac() -> None:
    # Default permissions for SP1/SP2 scope.
    permission_names = ["admin:read", "rbac:assign_role", "auth:read"]
    existing_permissions = {p.name: p for p in Permission.query.all()}

    for name in permission_names:
        if name not in existing_permissions:
            existing_permissions[name] = Permission(name=name)

    existing_roles = {r.name: r for r in Role.query.all()}

    if "admin" not in existing_roles:
        existing_roles["admin"] = Role(name="admin")
    if "user" not in existing_roles:
        existing_roles["user"] = Role(name="user")

    admin = existing_roles["admin"]
    user_role = existing_roles["user"]

    admin.permissions = [
        existing_permissions["admin:read"],
        existing_permissions["rbac:assign_role"],
        existing_permissions["auth:read"],
    ]
    user_role.permissions = [existing_permissions["auth:read"]]

    db.session.add_all(list(existing_permissions.values()))
    db.session.add_all(list(existing_roles.values()))
