# PoC-001: Agent Confused Deputy

## Research Question

Can an AI agent unintentionally exercise permissions beyond those granted to the requesting user?

## Hypothesis

An agent operating with an independent, privileged service identity may violate the original user's authorization boundary when downstream services fail to enforce delegated permissions.

## Security Properties

- User identity preservation
- Agent identity attribution
- Permission attenuation
- Resource-level authorization
- Tenant isolation
- Auditability

## Experimental Design

Compare two implementations:

- Baseline architecture with broad service-level permissions.
- Hardened architecture with explicit delegated authorization.

## Success Criteria

- Reproduce an authorization failure using synthetic resources.
- Identify the violated trust boundary.
- Implement preventive authorization controls.
- Demonstrate that unauthorized requests are denied.
- Confirm that legitimate requests remain functional.
- Measure the difference in reachable resources.

## Status

Research design in progress.