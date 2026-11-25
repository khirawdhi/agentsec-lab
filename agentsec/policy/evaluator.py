from datetime import datetime

from agentsec.core.authorization import (
    AuthorizationDecision,
    Delegation,
)
from agentsec.core.identity import Principal, PrincipalType
from agentsec.core.resource import Action, Permission, Resource


def evaluate(
    *,
    grantor: Principal,
    agent: Principal,
    resource: Resource,
    action: Action,
    delegation: Delegation | None,
    grantor_permissions: frozenset[Permission],
    agent_permissions: frozenset[Permission],
    now: datetime,
) -> AuthorizationDecision:
    if delegation is None:
        return AuthorizationDecision(False, "Missing delegation")

    if grantor.type != PrincipalType.USER:
        return AuthorizationDecision(False, "Invalid grantor type")

    if agent.type != PrincipalType.AGENT:
        return AuthorizationDecision(False, "Invalid agent type")

    if delegation.grantor_id != grantor.id:
        return AuthorizationDecision(False, "Grantor mismatch")

    if delegation.agent_id != agent.id:
        return AuthorizationDecision(False, "Agent mismatch")

    if now.utcoffset() is None:
        return AuthorizationDecision(False, "Invalid evaluation time")

    if delegation.expires_at.utcoffset() is None:
        return AuthorizationDecision(False, "Invalid delegation expiry")

    if delegation.expires_at <= now:
        return AuthorizationDecision(False, "Delegation expired")

    if not (grantor.tenant_id == delegation.tenant_id == resource.tenant_id):
        return AuthorizationDecision(False, "Tenant boundary violation")

    if agent.tenant_id not in (None, resource.tenant_id):
        return AuthorizationDecision(False, "Agent tenant mismatch")

    permission = Permission(action, resource.id)

    if permission not in grantor_permissions:
        return AuthorizationDecision(False, "Grantor lacks permission")

    if permission not in agent_permissions:
        return AuthorizationDecision(False, "Agent lacks permission")

    if permission not in delegation.permissions:
        return AuthorizationDecision(False, "Outside delegated scope")

    return AuthorizationDecision(True, "Authorized")
