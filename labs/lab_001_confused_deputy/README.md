# Lab 001: Agent Confused Deputy

## Research Question

Can an AI agent exercise permissions beyond those granted
to the requesting user?

## Hypothesis

An agent operating with independent, privileged authority
may violate the user's authorization boundary when
downstream services fail to enforce delegated permissions.

## Threat Model

- User: Employee with limited resource permissions.
- Agent: Privileged intermediary with broader permissions.
- Resources: Team report and restricted finance report.
- Trust boundary: User-to-agent delegated authorization.
- Threat: Unauthorized use of the agent's authority.

## Experimental Design

Two implementations are evaluated against identical
synthetic resources and authorization requests.

### Vulnerable Implementation

Authorization relies exclusively on the agent's permissions,
without evaluating the requesting user's authority or
delegated scope.

### Hardened Implementation

Authorization requires:

- Valid user and agent identities.
- Matching delegation participants.
- Unexpired delegation.
- Tenant boundary enforcement.
- User-level resource permissions.
- Agent-level resource permissions.
- Explicit delegated permission.

## Experimental Results

| Resource | Vulnerable | Hardened | Expected |
|---|---|---|---|
| Team report | Allow | Allow | Allow |
| Finance report | Allow | Deny | Deny |

The vulnerable implementation authorizes access to both
resources. The hardened implementation preserves legitimate
access while denying the unauthorized finance report request.

## Security Invariant

Effective delegated permissions must not exceed the
intersection of user permissions, agent permissions,
and explicitly delegated permissions.

Tenant, identity, and temporal constraints must also hold.

## Security Impact

- Unauthorized resource authorization.
- Privilege escalation through delegated execution.
- Violation of the requesting user's authorization boundary.

## Mitigation

Enforce delegated authorization independently of the agent
at the resource execution boundary.

Do not rely solely on the agent's service-level permissions.

## Reproduce

From the repository root:

```bash
python -m labs.lab_001_confused_deputy.experiment
```

## Regression Tests

```bash
pytest -q tests/test_confused_deputy.py
```

The tests verify legitimate access, reproduce the vulnerable
authorization decision, and confirm that the hardened
implementation prevents it.

## Security References

- [CWE-441: Unintended Proxy or Intermediary](https://cwe.mitre.org/data/definitions/441.html)
- [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

## Limitations

- Uses deterministic synthetic resources.
- Evaluates authorization decisions rather than actual
  resource access or data disclosure.
- Assumes trusted identity and permission inputs.
- Does not implement cryptographic identity verification.
- Does not require an LLM or live MCP server.
- Does not claim discovery of a novel vulnerability.

## Status

Experimental reproduction and regression testing completed.

This lab establishes a baseline for subsequent research
into compositional authorization failures in agentic systems.
