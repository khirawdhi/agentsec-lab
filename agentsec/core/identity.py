from dataclasses import dataclass
from enum import StrEnum


class PrincipalType(StrEnum):
    USER = "user"
    AGENT = "agent"
    SERVICE = "service"


@dataclass(frozen=True, slots=True)
class Principal:
    id: str
    type: PrincipalType
    tenant_id: str | None = None
