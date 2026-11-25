from agentsec.core.resource import Action
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


def main() -> None:
    for resource in (PUBLIC_REPORT, RESTRICTED_REPORT):
        vulnerable = vulnerable_execute(
            resource=resource,
            action=Action.READ,
            agent_permissions=AGENT_PERMISSIONS,
        )

        hardened = hardened_execute(
            grantor=USER,
            agent=AGENT,
            resource=resource,
            action=Action.READ,
            delegation=DELEGATION,
            grantor_permissions=USER_PERMISSIONS,
            agent_permissions=AGENT_PERMISSIONS,
            now=NOW,
        )

        print(f"\nResource: {resource.id}")
        print(f"Vulnerable: {vulnerable.allowed} | {vulnerable.reason}")
        print(f"Hardened:   {hardened.allowed} | {hardened.reason}")


if __name__ == "__main__":
    main()
