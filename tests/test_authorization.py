from datetime import UTC, datetime, timedelta

from agentsec.core.authorization import (
    AuthorizationDecision,
    Delegation,
)
from agentsec.core.identity import Principal, PrincipalType
from agentsec.core.resource import Action, Permission, Resource


def test_principal_creation() -> None:
    alice = Principal(
        id="alice",
        type=PrincipalType.USER,
        tenant_id="tenant-a",
    )

    assert alice.type == PrincipalType.USER
    assert alice.tenant_id == "tenant-a"


def test_resource_creation() -> None:
    resource = Resource(
        id="document-a",
        tenant_id="tenant-a",
        owner_id="alice",
    )

    assert resource.owner_id == "alice"


def test_delegation_scope() -> None:
    permission = Permission(
        action=Action.READ,
        resource_id="document-a",
    )

    delegation = Delegation(
        id="delegation-001",
        grantor_id="alice",
        agent_id="agent-001",
        tenant_id="tenant-a",
        permissions=frozenset({permission}),
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )

    assert permission in delegation.permissions
    assert delegation.agent_id == "agent-001"


def test_authorization_decision() -> None:
    decision = AuthorizationDecision(
        allowed=False,
        reason="Permission not granted",
    )

    assert not decision.allowed
