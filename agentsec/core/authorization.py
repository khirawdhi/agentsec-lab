from dataclasses import dataclass
from datetime import datetime

from agentsec.core.resource import Permission


@dataclass(frozen=True, slots=True)
class Delegation:
    id: str
    grantor_id: str
    agent_id: str
    tenant_id: str
    permissions: frozenset[Permission]
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    allowed: bool
    reason: str
