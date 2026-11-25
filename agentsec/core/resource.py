from dataclasses import dataclass
from enum import StrEnum


class Action(StrEnum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"


@dataclass(frozen=True, slots=True)
class Resource:
    id: str
    tenant_id: str
    owner_id: str


@dataclass(frozen=True, slots=True)
class Permission:
    action: Action
    resource_id: str
