from datetime import UTC, datetime, timedelta

from agentsec.core.authorization import Delegation
from agentsec.core.identity import Principal, PrincipalType
from agentsec.core.resource import Action, Permission, Resource

NOW = datetime(2026, 1, 1, tzinfo=UTC)

USER = Principal("employee-001", PrincipalType.USER, "tenant-a")
AGENT = Principal("document-agent", PrincipalType.AGENT, "tenant-a")

PUBLIC_REPORT = Resource("team-report", "tenant-a", USER.id)
RESTRICTED_REPORT = Resource("finance-report", "tenant-a", "finance-admin")

PUBLIC_READ = Permission(Action.READ, PUBLIC_REPORT.id)
RESTRICTED_READ = Permission(Action.READ, RESTRICTED_REPORT.id)

USER_PERMISSIONS = frozenset({PUBLIC_READ})

AGENT_PERMISSIONS = frozenset(
    {
        PUBLIC_READ,
        RESTRICTED_READ,
    }
)

DELEGATION = Delegation(
    id="delegation-001",
    grantor_id=USER.id,
    agent_id=AGENT.id,
    tenant_id="tenant-a",
    permissions=USER_PERMISSIONS,
    expires_at=NOW + timedelta(minutes=15),
)
