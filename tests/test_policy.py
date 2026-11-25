from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from agentsec.core.authorization import Delegation
from agentsec.core.identity import Principal, PrincipalType
from agentsec.core.resource import Action, Permission, Resource
from agentsec.policy.evaluator import evaluate

NOW = datetime(2026, 1, 1, tzinfo=UTC)

ALICE = Principal("alice", PrincipalType.USER, "tenant-a")
AGENT = Principal("agent-001", PrincipalType.AGENT)

DOCUMENT = Resource("document-a", "tenant-a", "alice")
READ = Permission(Action.READ, DOCUMENT.id)
WRITE = Permission(Action.WRITE, DOCUMENT.id)

PERMISSIONS = frozenset({READ, WRITE})

DELEGATION = Delegation(
    id="delegation-001",
    grantor_id=ALICE.id,
    agent_id=AGENT.id,
    tenant_id="tenant-a",
    permissions=frozenset({READ}),
    expires_at=NOW + timedelta(minutes=5),
)


def test_valid_delegation() -> None:
    decision = evaluate(
        grantor=ALICE,
        agent=AGENT,
        resource=DOCUMENT,
        action=Action.READ,
        delegation=DELEGATION,
        grantor_permissions=PERMISSIONS,
        agent_permissions=PERMISSIONS,
        now=NOW,
    )

    assert decision.allowed


@pytest.mark.parametrize(
    ("delegation", "reason"),
    [
        (None, "Missing delegation"),
        (
            replace(DELEGATION, expires_at=NOW),
            "Delegation expired",
        ),
        (
            replace(DELEGATION, agent_id="agent-002"),
            "Agent mismatch",
        ),
        (
            replace(DELEGATION, grantor_id="bob"),
            "Grantor mismatch",
        ),
        (
            replace(DELEGATION, tenant_id="tenant-b"),
            "Tenant boundary violation",
        ),
        (
            replace(DELEGATION, permissions=frozenset()),
            "Outside delegated scope",
        ),
    ],
)
def test_invalid_delegation(
    delegation: Delegation | None,
    reason: str,
) -> None:
    decision = evaluate(
        grantor=ALICE,
        agent=AGENT,
        resource=DOCUMENT,
        action=Action.READ,
        delegation=delegation,
        grantor_permissions=PERMISSIONS,
        agent_permissions=PERMISSIONS,
        now=NOW,
    )

    assert not decision.allowed
    assert decision.reason == reason


def test_operation_outside_scope() -> None:
    decision = evaluate(
        grantor=ALICE,
        agent=AGENT,
        resource=DOCUMENT,
        action=Action.WRITE,
        delegation=DELEGATION,
        grantor_permissions=PERMISSIONS,
        agent_permissions=PERMISSIONS,
        now=NOW,
    )

    assert not decision.allowed
    assert decision.reason == "Outside delegated scope"


@pytest.mark.parametrize(
    ("grantor_permissions", "agent_permissions", "reason"),
    [
        (
            frozenset(),
            PERMISSIONS,
            "Grantor lacks permission",
        ),
        (
            PERMISSIONS,
            frozenset(),
            "Agent lacks permission",
        ),
    ],
)
def test_permission_attenuation(
    grantor_permissions: frozenset[Permission],
    agent_permissions: frozenset[Permission],
    reason: str,
) -> None:
    decision = evaluate(
        grantor=ALICE,
        agent=AGENT,
        resource=DOCUMENT,
        action=Action.READ,
        delegation=DELEGATION,
        grantor_permissions=grantor_permissions,
        agent_permissions=agent_permissions,
        now=NOW,
    )

    assert not decision.allowed
    assert decision.reason == reason


@pytest.mark.parametrize(
    ("resource", "reason"),
    [
        (
            Resource("document-b", "tenant-b", "bob"),
            "Tenant boundary violation",
        ),
        (
            Resource("document-c", "tenant-a", "alice"),
            "Outside delegated scope",
        ),
    ],
)
def test_resource_boundary(
    resource: Resource,
    reason: str,
) -> None:
    permissions = frozenset(
        {
            Permission(Action.READ, resource.id),
        }
    )

    decision = evaluate(
        grantor=ALICE,
        agent=AGENT,
        resource=resource,
        action=Action.READ,
        delegation=DELEGATION,
        grantor_permissions=permissions,
        agent_permissions=permissions,
        now=NOW,
    )

    assert not decision.allowed
    assert decision.reason == reason


@pytest.mark.parametrize(
    ("grantor", "agent", "reason"),
    [
        (
            replace(ALICE, type=PrincipalType.SERVICE),
            AGENT,
            "Invalid grantor type",
        ),
        (
            ALICE,
            replace(AGENT, type=PrincipalType.USER),
            "Invalid agent type",
        ),
        (
            ALICE,
            replace(AGENT, tenant_id="tenant-b"),
            "Agent tenant mismatch",
        ),
    ],
)
def test_principal_boundary(
    grantor: Principal,
    agent: Principal,
    reason: str,
) -> None:
    decision = evaluate(
        grantor=grantor,
        agent=agent,
        resource=DOCUMENT,
        action=Action.READ,
        delegation=DELEGATION,
        grantor_permissions=PERMISSIONS,
        agent_permissions=PERMISSIONS,
        now=NOW,
    )

    assert not decision.allowed
    assert decision.reason == reason


@pytest.mark.parametrize(
    ("now", "delegation", "reason"),
    [
        (
            NOW.replace(tzinfo=None),
            DELEGATION,
            "Invalid evaluation time",
        ),
        (
            NOW,
            replace(
                DELEGATION,
                expires_at=DELEGATION.expires_at.replace(
                    tzinfo=None,
                ),
            ),
            "Invalid delegation expiry",
        ),
    ],
)
def test_timestamp_boundary(
    now: datetime,
    delegation: Delegation,
    reason: str,
) -> None:
    decision = evaluate(
        grantor=ALICE,
        agent=AGENT,
        resource=DOCUMENT,
        action=Action.READ,
        delegation=delegation,
        grantor_permissions=PERMISSIONS,
        agent_permissions=PERMISSIONS,
        now=now,
    )

    assert not decision.allowed
    assert decision.reason == reason
