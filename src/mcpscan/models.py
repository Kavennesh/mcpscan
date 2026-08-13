from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field, model_validator


class TargetKind(str, Enum):
    STDIO = "stdio"   # local process, launched via docker
    HTTP = "http"     # remote streamable-http endpoint
    PATH = "path"     # local source tree, static analysis only


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class Target(BaseModel):
    """A thing to be scanned. Never holds secret values — only env var names."""

    kind: TargetKind
    label: str
    command: list[str] | None = None
    url: str | None = None
    path: Path | None = None
    env_keys: list[str] = Field(default_factory=list)
    origin: str = "cli"

    @model_validator(mode="after")
    def _check_shape(self) -> "Target":
        required = {
            TargetKind.STDIO: "command",
            TargetKind.HTTP: "url",
            TargetKind.PATH: "path",
        }[self.kind]
        if getattr(self, required) is None:
            raise ValueError(f"{self.kind.value} target requires '{required}'")
        if self.kind is TargetKind.STDIO and not self.command:
            raise ValueError("command must not be empty")
        return self

    def describe(self) -> str:
        detail = {
            TargetKind.STDIO: lambda: " ".join(self.command or []),
            TargetKind.HTTP: lambda: str(self.url),
            TargetKind.PATH: lambda: str(self.path),
        }[self.kind]()
        env = f"  env: {', '.join(self.env_keys)}" if self.env_keys else ""
        return f"[{self.kind.value}] {self.label}\n    {detail}{env}"
