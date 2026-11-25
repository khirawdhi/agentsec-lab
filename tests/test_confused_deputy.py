from agentsec.core.resource import Action, Resource
from labs.lab_001_confused_deputy.hardened.executor import (
    execute as hardened_execute,
)
from labs.lab_001_confused_deputy.scenario import (
    AGENT,
    AGENT_PERMISSIONS,
    DELEGATION,
    NOW,
    PUBLIC_REPORT,
    RESTRICTED_REPORT,
    USER,
    USER_PERMISSIONS,
)
from labs.lab_001_confused_deputy.vulnerable.executor import (
    execute as vulnerable_execute,
)


def vulnerable_read(resource: Resource) -> bool:
    return vulnerable_execute(
        resource=resource,
        action=Action.READ,
        agent_permissions=AGENT_PERMISSIONS,
    ).allowed


def hardened_read(resource: Resource) -> bool:
    return hardened_execute(
        grantor=USER,
        agent=AGENT,
        resource=resource,
        action=Action.READ,
        delegation=DELEGATION,
        grantor_permissions=USER_PERMISSIONS,
        agent_permissions=AGENT_PERMISSIONS,
        now=NOW,
    ).allowed


def test_vulnerable_allows_legitimate_access():
    assert vulnerable_read(PUBLIC_REPORT)


def test_vulnerable_reproduces_confused_deputy():
    assert vulnerable_read(RESTRICTED_REPORT)


def test_hardened_preserves_legitimate_access():
    assert hardened_read(PUBLIC_REPORT)


def test_hardened_prevents_confused_deputy():
    assert not hardened_read(RESTRICTED_REPORT)
