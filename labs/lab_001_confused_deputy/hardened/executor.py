from datetime import datetime

from agentsec.core.authorization import AuthorizationDecision, Delegation
from agentsec.core.identity import Principal
from agentsec.core.resource import Action, Permission, Resource
from agentsec.policy.evaluator import evaluate


def execute(
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
    return evaluate(
        grantor=grantor,
        agent=agent,
        resource=resource,
        action=action,
        delegation=delegation,
        grantor_permissions=grantor_permissions,
        agent_permissions=agent_permissions,
        now=now,
    )
