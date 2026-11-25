from agentsec.core.authorization import AuthorizationDecision
from agentsec.core.resource import Action, Permission, Resource


def execute(
    *,
    resource: Resource,
    action: Action,
    agent_permissions: frozenset[Permission],
) -> AuthorizationDecision:
    permission = Permission(action, resource.id)

    if permission not in agent_permissions:
        return AuthorizationDecision(False, "Agent lacks permission")

    return AuthorizationDecision(True, "Authorized using agent authority")
