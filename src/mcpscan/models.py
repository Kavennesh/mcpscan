from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, Field, field_validator, model_validator


class TargetKind(StrEnum):
    STDIO = "stdio"   # local process, launched via docker
    HTTP = "http"     # remote streamable-http endpoint
    PATH = "path"     # local source tree, static analysis only


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2}[self.value]


class Target(BaseModel):
    """A thing to be scanned. Never holds secret values -- only env var names."""

    kind: TargetKind
    label: str
    command: list[str] | None = None
    url: str | None = None
    path: Path | None = None
    env_keys: list[str] = Field(default_factory=list)
    origin: str = "cli"

    @model_validator(mode="after")
    def _check_shape(self) -> Target:
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


#: How much of a hostile payload is worth keeping as evidence. A sample, not the
#: artefact: the whole point of a cap is that the server does not get to choose
#: how much memory our report costs.
RAW_SAMPLE_BYTES: Final = 2048


class AnomalyKind(StrEnum):
    """Something a target did that a well-behaved MCP server would not.

    Not a severity and not a finding -- an observation. Step 4's rule engine
    decides what any of these are worth; the transport's job is only to notice
    and to keep enough of the evidence to argue about later.
    """

    # -- framing (jsonrpc.MessageStream) --------------------------------
    OVERSIZED_LINE = "oversized_line"
    NON_JSON_STDOUT = "non_json_stdout"
    BAD_UTF8 = "bad_utf8"
    EMBEDDED_NEWLINE = "embedded_newline"
    JSON_TOO_DEEP = "json_too_deep"
    BATCH_ARRAY = "batch_array"
    MISSING_JSONRPC = "missing_jsonrpc"
    MALFORMED_MESSAGE = "malformed_message"
    RESULT_AND_ERROR = "result_and_error"

    # -- correlation (jsonrpc.Dispatcher) -------------------------------
    DUPLICATE_ID = "duplicate_id"
    UNSOLICITED_RESPONSE = "unsolicited_response"
    UNEXPECTED_SERVER_REQUEST = "unexpected_server_request"

    # -- protocol semantics (client) ------------------------------------
    CURSOR_LOOP = "cursor_loop"
    PAGE_CAP = "page_cap"
    VERSION_DOWNGRADE = "version_downgrade"
    UNSUPPORTED_VERSION = "unsupported_version"
    UNDECLARED_CAPABILITY = "undeclared_capability"

    # -- transport lifecycle --------------------------------------------
    REQUEST_TIMEOUT = "request_timeout"
    TRANSPORT_CLOSED = "transport_closed"


class ProtocolAnomaly(BaseModel):
    """One observation, with a bounded sample of what provoked it.

    ``seq`` is arrival order rather than a timestamp. Ordering is the evidence
    that matters -- "the tool list changed *after* we called it" is a rug pull,
    the same two listings in the other order are nothing -- and a monotonic
    counter says that without dragging a clock into a pure module.
    """

    kind: AnomalyKind
    detail: str
    raw: bytes | None = None
    seq: int = 0

    @field_validator("raw")
    @classmethod
    def _truncate(cls, value: bytes | None) -> bytes | None:
        if value is None:
            return None
        return value[:RAW_SAMPLE_BYTES]


#: Same argument as RAW_SAMPLE_BYTES, one layer up: a finding quotes a target's
#: text back, and the target does not get to decide how long our report is.
EVIDENCE_CHARS: Final = 240


class Span(BaseModel):
    """Offsets into one field's text, in characters *and* UTF-8 bytes.

    Both, because they answer different questions and neither can be cheaply
    recovered from the other at report time. Character offsets slice the excerpt;
    byte offsets are what MCP-001 reports, what a user greps for, and what SARIF
    wants in step 7. Converting in the reporter would mean re-encoding the string
    there -- and the string is attacker-controlled, so the conversion belongs
    where the text is already in hand.
    """

    start: int
    end: int
    byte_start: int
    byte_end: int

    @classmethod
    def of(cls, text: str, start: int, end: int) -> Span:
        """Build a span from character offsets, deriving the byte offsets."""
        return cls(
            start=start,
            end=end,
            byte_start=len(text[:start].encode("utf-8")),
            byte_end=len(text[:end].encode("utf-8")),
        )

    def excerpt(self, text: str) -> str:
        return text[self.start : self.end]


class Location(BaseModel):
    """Where a finding is, in whichever coordinate systems are available.

    A scan can see a target three ways, and the location has to survive all
    three: a source tree gives a file and line range, a live server gives a JSON
    pointer into the metadata it served, and a target that is both gives both.
    Neither half is a fallback for the other -- ``#/tools/3/description`` is the
    only way to name a field on a server whose source we do not have, and a line
    number is the only thing a developer can act on.
    """

    path: Path | None = None
    start_line: int | None = None
    end_line: int | None = None
    pointer: str | None = None
    span: Span | None = None

    @model_validator(mode="after")
    def _locates_something(self) -> Location:
        if self.path is None and self.pointer is None:
            raise ValueError("a Location needs at least one of 'path' or 'pointer'")
        return self

    def describe(self) -> str:
        parts: list[str] = []
        if self.path is not None:
            where = str(self.path)
            if self.start_line is not None:
                where += f":{self.start_line}"
                if self.end_line is not None and self.end_line != self.start_line:
                    where += f"-{self.end_line}"
            parts.append(where)
        if self.pointer is not None:
            pointer = self.pointer
            if self.span is not None:
                pointer += f" [{self.span.byte_start}:{self.span.byte_end}]"
            parts.append(pointer)
        return "  ".join(parts)


class Finding(BaseModel):
    """One thing a rule decided is wrong. The shape every report serialises from."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    message: str
    location: Location
    #: Corroborating positions. MCP-003 findings are inherently two-place -- the
    #: sink is where the bug is, the tainted parameter is why it is one -- and
    #: SARIF has `relatedLocations` for exactly this, so step 7 stays mechanical.
    related: list[Location] = Field(default_factory=list)
    evidence: str | None = None
    subject: str = ""
    #: What to do about it. Required of every rule by the YAML schema: a rule
    #: that cannot say what to do about its finding is not finished, and a report
    #: full of "we detected a thing" is one nobody acts on. SARIF `help.text`.
    remediation: str = ""
    #: Absolute URL of the rule's documentation, plus an optional `#anchor`.
    #: Absolute rather than repo-relative because a finding outlives the checkout
    #: it came from, and because SARIF `helpUri` requires a real URI.
    help_uri: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("evidence")
    @classmethod
    def _truncate(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if len(value) <= EVIDENCE_CHARS:
            return value
        return value[:EVIDENCE_CHARS] + "..."

    @property
    def sort_key(self) -> tuple[int, int, str, str]:
        """Worst first, then most certain first, then stable."""
        return (
            -self.severity.rank,
            -self.confidence.rank,
            self.rule_id,
            self.location.describe(),
        )
