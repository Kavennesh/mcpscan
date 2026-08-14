"""JSON-RPC 2.0 framing for MCP's stdio transport. Pure: no I/O, no clock, no Docker.

Hand-rolled rather than taken from the official SDK, and the reason is the whole
premise of this tool. An SDK is built to talk to servers that work; it drops the
line it cannot parse, raises on the frame it does not like, and hands the caller a
tidy object. Every one of those discarded bytes is what mcpscan exists to look at.
So the rule here is inverted: **a hostile response is data to record, never an
exception that loses the evidence.** :class:`MessageStream` returns the messages it
could read and appends a :class:`~mcpscan.models.ProtocolAnomaly` for everything
else. It raises for nothing a server can do.

The framing itself is deliberately thin (revision 2025-11-25):

    Messages are delimited by newlines, and MUST NOT contain embedded newlines.
    The server MUST NOT write anything to its stdout that is not a valid MCP message.

Newline-delimited UTF-8 JSON. **There is no ``Content-Length`` header** -- that is
LSP, and conflating the two is the classic error when hand-rolling this. Batching
is gone too: 2025-03-26 allowed a top-level array, 2025-06-18 removed it, and
2025-11-25 keeps it removed, so an array is a spec violation to report rather than
a shape to support.

Three hostile cases drive the design and are worth calling out, because each one
is a place where the obvious implementation is wrong:

**No length prefix means no bound on a line.** A server can emit gigabytes with no
``\\n``. A bare ``readline()`` is an OOM. Lines are capped, and the excess is
discarded up to the next newline so the stream resynchronises instead of dying.

**Depth is checked before parsing, not caught after.** ``json.loads`` raises
``RecursionError`` -- not ``JSONDecodeError`` -- on deeply nested input, so the
natural ``except json.JSONDecodeError`` misses the attack entirely. Nesting is
counted with a byte scan first. (The ``RecursionError`` handler below is a second
belt for a limit lowered elsewhere in the process, not the primary defence.)

**A literal newline inside a message is detectable, but only in hindsight.** It
splits one message into two unparseable halves, so it cannot be spotted on either
half alone. When two consecutive lines both fail to parse, the halves are rejoined
and reparsed with ``strict=False`` -- which is what permits the raw control
character -- and a success proves the framing violation.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from mcpscan.models import RAW_SAMPLE_BYTES, AnomalyKind, ProtocolAnomaly

JSONRPC_VERSION: Final = "2.0"

#: Largest single message accepted. Generous for a legitimate ``tools/list`` and
#: nowhere near enough to matter as a memory cost.
MAX_LINE_BYTES: Final = 1024 * 1024

#: Nesting beyond this is not a document, it is a stack-exhaustion attempt.
MAX_DEPTH: Final = 64

# Standard JSON-RPC codes, plus the MCP-specific one we may see from servers.
PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603
RESOURCE_NOT_FOUND: Final = -32002

_QUOTE: Final = 0x22
_BACKSLASH: Final = 0x5C
_OPENERS: Final = frozenset({0x7B, 0x5B})  # { [
_CLOSERS: Final = frozenset({0x7D, 0x5D})  # } ]


class ProtocolError(RuntimeError):
    """mcpscan built a message it should not have.

    Ours, never theirs. Nothing a target sends can raise this -- that is what the
    anomaly log is for.
    """


class MessageKind(StrEnum):
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"


class Route(StrEnum):
    """What the transport should do with a message, decided without touching I/O."""

    DELIVER = "deliver"
    RETAIN = "retain"
    REFUSE = "refuse"
    DROP = "drop"


@dataclass(frozen=True, slots=True)
class Message:
    """One parsed JSON-RPC message, plus the bytes it came from.

    ``raw`` is kept because a report that says "the server sent something odd"
    without the bytes is not evidence. It is already bounded by the line cap.
    """

    kind: MessageKind
    id: str | int | None = None
    method: str | None = None
    params: dict[str, Any] | None = None
    result: Any = None
    error: dict[str, Any] | None = None
    raw: bytes = b""

    @property
    def is_error(self) -> bool:
        return self.error is not None

    def error_text(self) -> str:
        """Render the error object for a human, tolerating a malformed one."""
        if self.error is None:
            return ""
        code = self.error.get("code", "?")
        message = self.error.get("message", "")
        return f"{code}: {message}"


class AnomalyLog:
    """Ordered record of everything a target did wrong.

    Shared by the framing layer, the dispatcher, the transport and the client so
    that ``seq`` is a single global ordering across all of them. Interleaving is
    the point: "the tool list changed after we called it" is the entire rug-pull
    signal, and it is only visible if one counter covers every layer.
    """

    __slots__ = ("_items",)

    def __init__(self) -> None:
        self._items: list[ProtocolAnomaly] = []

    def record(
        self,
        kind: AnomalyKind,
        detail: str,
        raw: bytes | None = None,
    ) -> ProtocolAnomaly:
        anomaly = ProtocolAnomaly(kind=kind, detail=detail, raw=raw, seq=len(self._items))
        self._items.append(anomaly)
        return anomaly

    @property
    def items(self) -> tuple[ProtocolAnomaly, ...]:
        return tuple(self._items)

    def of_kind(self, kind: AnomalyKind) -> tuple[ProtocolAnomaly, ...]:
        return tuple(item for item in self._items if item.kind is kind)

    def kinds(self) -> frozenset[AnomalyKind]:
        return frozenset(item.kind for item in self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[ProtocolAnomaly]:
        return iter(self._items)


# --------------------------------------------------------------------------
# encoding
# --------------------------------------------------------------------------
def _dump(payload: Mapping[str, Any]) -> bytes:
    """Serialise one message to a single newline-terminated line.

    ``json.dumps`` escapes control characters inside strings and we never pass
    ``indent``, so the result is inherently one line. The check is here anyway:
    it is one comparison, and the alternative is silently emitting the exact
    framing violation this module exists to detect in others.
    """
    text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    line = text.encode("utf-8")
    if b"\n" in line or b"\r" in line:
        raise ProtocolError(f"refusing to emit a message containing a newline: {line[:200]!r}")
    return line + b"\n"


def encode_request(
    method: str,
    request_id: str | int,
    params: Mapping[str, Any] | None = None,
) -> bytes:
    payload: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "id": request_id, "method": method}
    if params is not None:
        payload["params"] = dict(params)
    return _dump(payload)


def encode_notification(method: str, params: Mapping[str, Any] | None = None) -> bytes:
    payload: dict[str, Any] = {"jsonrpc": JSONRPC_VERSION, "method": method}
    if params is not None:
        payload["params"] = dict(params)
    return _dump(payload)


def encode_error(request_id: str | int | None, code: int, message: str) -> bytes:
    return _dump(
        {
            "jsonrpc": JSONRPC_VERSION,
            "id": request_id,
            "error": {"code": code, "message": message},
        }
    )


# --------------------------------------------------------------------------
# depth scanning
# --------------------------------------------------------------------------
def nesting_depth(raw: bytes) -> int:
    """Deepest bracket nesting in ``raw``, ignoring brackets inside strings.

    A byte scan rather than a parse, because the whole point is to answer this
    *before* handing the bytes to ``json.loads``. Safe on UTF-8 without decoding:
    every byte of a multi-byte sequence is >= 0x80, so none can be mistaken for
    an ASCII quote, backslash or bracket.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for byte in raw:
        if in_string:
            if escaped:
                escaped = False
            elif byte == _BACKSLASH:
                escaped = True
            elif byte == _QUOTE:
                in_string = False
            continue
        if byte == _QUOTE:
            in_string = True
        elif byte in _OPENERS:
            depth += 1
            deepest = max(deepest, depth)
        elif byte in _CLOSERS:
            depth -= 1
    return deepest


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------
@dataclass(slots=True)
class MessageStream:
    """Byte chunks in, messages out, anomalies on the side.

    Holds no file handle and performs no I/O, so the entire hostile-input surface
    is testable without a Docker daemon. That matters more than it sounds: CI has
    a daemon but never runs ``make images``, so every sandbox-marked test skips
    there. If this logic were only reachable through a live container it would be
    effectively untested in CI.
    """

    anomalies: AnomalyLog
    max_line: int = MAX_LINE_BYTES
    max_depth: int = MAX_DEPTH
    _buffer: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _discarding: bool = field(default=False, init=False, repr=False)
    _orphan: bytes | None = field(default=None, init=False, repr=False)

    def feed(self, chunk: bytes) -> list[Message]:
        """Consume a chunk and return every complete message it completed."""
        self._buffer.extend(chunk)
        messages: list[Message] = []

        while True:
            index = self._buffer.find(b"\n")

            if self._discarding:
                # Mid-overrun: throw bytes away until the stream resynchronises
                # on a newline. Dropping the tail is what keeps one oversized
                # line from poisoning every message after it.
                if index < 0:
                    self._buffer.clear()
                    return messages
                del self._buffer[: index + 1]
                self._discarding = False
                continue

            if index < 0:
                if len(self._buffer) > self.max_line:
                    self.anomalies.record(
                        AnomalyKind.OVERSIZED_LINE,
                        f"no newline after {len(self._buffer)} bytes "
                        f"(cap {self.max_line}); discarding to the next newline",
                        raw=bytes(self._buffer[:RAW_SAMPLE_BYTES]),
                    )
                    self._buffer.clear()
                    self._discarding = True
                return messages

            line = bytes(self._buffer[:index])
            del self._buffer[: index + 1]

            if len(line) > self.max_line:
                self.anomalies.record(
                    AnomalyKind.OVERSIZED_LINE,
                    f"message of {len(line)} bytes exceeds cap {self.max_line}",
                    raw=line[:RAW_SAMPLE_BYTES],
                )
                continue

            message = self._parse(line.rstrip(b"\r"))
            if message is not None:
                messages.append(message)

    def close(self) -> None:
        """Report whatever was left dangling at EOF."""
        if self._buffer and not self._discarding:
            self.anomalies.record(
                AnomalyKind.MALFORMED_MESSAGE,
                f"stream ended mid-message with {len(self._buffer)} unterminated bytes",
                raw=bytes(self._buffer[:RAW_SAMPLE_BYTES]),
            )
        self._buffer.clear()
        self._orphan = None

    # -- parsing --------------------------------------------------------
    def _parse(self, line: bytes) -> Message | None:
        if not line.strip():
            # Blank lines between messages are harmless and common enough that
            # flagging them would bury the real findings in noise.
            return None

        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError as exc:
            self._orphan = None
            self.anomalies.record(
                AnomalyKind.BAD_UTF8,
                f"stdout line is not valid UTF-8: {exc.reason} at byte {exc.start}",
                raw=line[:RAW_SAMPLE_BYTES],
            )
            return None

        depth = nesting_depth(line)
        if depth > self.max_depth:
            self._orphan = None
            self.anomalies.record(
                AnomalyKind.JSON_TOO_DEEP,
                f"nesting depth {depth} exceeds cap {self.max_depth}; not parsed",
                raw=line[:RAW_SAMPLE_BYTES],
            )
            return None

        try:
            parsed = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            return self._parse_failed(line)

        self._orphan = None
        return self._classify(parsed, line)

    def _parse_failed(self, line: bytes) -> Message | None:
        """Handle a line that is not JSON, checking first for a split message.

        Two consecutive unparseable lines that parse as one when rejoined is the
        signature of a literal newline inside a message -- a framing-confusion
        primitive, and one that cannot be seen in either half alone.
        ``strict=False`` is what allows the raw control character through.
        """
        orphan = self._orphan
        if orphan is not None and len(orphan) + len(line) + 1 <= self.max_line:
            joined = orphan + b"\n" + line
            try:
                parsed = json.loads(joined.decode("utf-8"), strict=False)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                parsed = None
            if isinstance(parsed, dict):
                self._orphan = None
                self.anomalies.record(
                    AnomalyKind.EMBEDDED_NEWLINE,
                    "message contained a literal newline, splitting it across two lines "
                    "(2025-11-25: messages MUST NOT contain embedded newlines)",
                    raw=joined[:RAW_SAMPLE_BYTES],
                )
                return self._classify(parsed, joined)

        self._orphan = line
        self.anomalies.record(
            AnomalyKind.NON_JSON_STDOUT,
            "stdout line is not JSON (2025-11-25: servers MUST NOT write "
            "non-MCP content to stdout)",
            raw=line[:RAW_SAMPLE_BYTES],
        )
        return None

    def _classify(self, parsed: object, raw: bytes) -> Message | None:
        if isinstance(parsed, list):
            self.anomalies.record(
                AnomalyKind.BATCH_ARRAY,
                f"top-level JSON array of {len(parsed)} items; JSON-RPC batching was "
                "removed in revision 2025-06-18 and is not part of 2025-11-25",
                raw=raw[:RAW_SAMPLE_BYTES],
            )
            return None

        if not isinstance(parsed, dict):
            self.anomalies.record(
                AnomalyKind.MALFORMED_MESSAGE,
                f"message is a bare {type(parsed).__name__}, expected an object",
                raw=raw[:RAW_SAMPLE_BYTES],
            )
            return None

        if parsed.get("jsonrpc") != JSONRPC_VERSION:
            # Recorded, then ignored. The message is still the best evidence we
            # have of what the server is doing; refusing to read it would hand a
            # server an opt-out from inspection for the price of one wrong field.
            self.anomalies.record(
                AnomalyKind.MISSING_JSONRPC,
                f"jsonrpc field is {parsed.get('jsonrpc')!r}, expected '2.0'",
                raw=raw[:RAW_SAMPLE_BYTES],
            )

        has_method = "method" in parsed
        has_id = "id" in parsed
        message_id = parsed.get("id")

        # `bool` is a subclass of `int`, and `"id": true` is not a valid id.
        if has_id and (isinstance(message_id, bool) or not isinstance(message_id, (str, int))):
            self.anomalies.record(
                AnomalyKind.MALFORMED_MESSAGE,
                f"id is {type(message_id).__name__}, expected a string or number",
                raw=raw[:RAW_SAMPLE_BYTES],
            )
            return None

        if has_method:
            method = parsed.get("method")
            if not isinstance(method, str):
                self.anomalies.record(
                    AnomalyKind.MALFORMED_MESSAGE,
                    f"method is {type(method).__name__}, expected a string",
                    raw=raw[:RAW_SAMPLE_BYTES],
                )
                return None
            params = parsed.get("params")
            return Message(
                kind=MessageKind.REQUEST if has_id else MessageKind.NOTIFICATION,
                id=message_id if has_id else None,
                method=method,
                params=params if isinstance(params, dict) else None,
                raw=raw,
            )

        if not has_id:
            self.anomalies.record(
                AnomalyKind.MALFORMED_MESSAGE,
                "message has neither 'method' nor 'id'",
                raw=raw[:RAW_SAMPLE_BYTES],
            )
            return None

        has_result = "result" in parsed
        error = parsed.get("error")
        has_error = "error" in parsed

        if has_result and has_error:
            self.anomalies.record(
                AnomalyKind.RESULT_AND_ERROR,
                f"response id={message_id!r} carries both 'result' and 'error'",
                raw=raw[:RAW_SAMPLE_BYTES],
            )
        elif not has_result and not has_error:
            self.anomalies.record(
                AnomalyKind.MALFORMED_MESSAGE,
                f"response id={message_id!r} carries neither 'result' nor 'error'",
                raw=raw[:RAW_SAMPLE_BYTES],
            )
            return None

        return Message(
            kind=MessageKind.RESPONSE,
            id=message_id,
            result=parsed.get("result"),
            error=error if isinstance(error, dict) else None,
            raw=raw,
        )


# --------------------------------------------------------------------------
# correlation
# --------------------------------------------------------------------------
class Dispatcher:
    """Tracks in-flight request ids and decides what each message is for.

    Deliberately holds no futures and awaits nothing. The transport owns the
    async machinery; this owns the bookkeeping, which is the part with the
    interesting failure modes -- and, being pure, the part CI can actually test.
    """

    __slots__ = ("_anomalies", "_answered", "_next_id", "_pending")

    def __init__(self, anomalies: AnomalyLog) -> None:
        self._anomalies = anomalies
        self._pending: set[str | int] = set()
        self._answered: set[str | int] = set()
        self._next_id = 0

    def next_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def expect(self, request_id: str | int) -> None:
        self._pending.add(request_id)

    def forget(self, request_id: str | int) -> None:
        """Abandon a request without an answer -- a timeout, or a dead transport."""
        self._pending.discard(request_id)
        self._answered.add(request_id)

    @property
    def pending(self) -> frozenset[str | int]:
        return frozenset(self._pending)

    def classify(self, message: Message) -> Route:
        if message.kind is MessageKind.NOTIFICATION:
            return Route.RETAIN

        if message.kind is MessageKind.REQUEST:
            # We advertise no client capabilities we cannot serve, so a server
            # request here means it is reaching for something it was never
            # offered -- sampling, elicitation, roots. Worth recording precisely
            # because a compliant server would not try.
            self._anomalies.record(
                AnomalyKind.UNEXPECTED_SERVER_REQUEST,
                f"server sent request {message.method!r} but no matching client "
                "capability was negotiated",
                raw=message.raw[:RAW_SAMPLE_BYTES],
            )
            return Route.REFUSE

        request_id = message.id
        if request_id is None:
            return Route.DROP

        if request_id in self._pending:
            self._pending.discard(request_id)
            self._answered.add(request_id)
            return Route.DELIVER

        if request_id in self._answered:
            self._anomalies.record(
                AnomalyKind.DUPLICATE_ID,
                f"second response for id={request_id!r}, which was already answered",
                raw=message.raw[:RAW_SAMPLE_BYTES],
            )
            return Route.DROP

        self._anomalies.record(
            AnomalyKind.UNSOLICITED_RESPONSE,
            f"response for id={request_id!r}, which was never requested",
            raw=message.raw[:RAW_SAMPLE_BYTES],
        )
        return Route.DROP


def text_of(content: Sequence[Any]) -> str:
    """Concatenate the text blocks of an MCP ``content`` array.

    Tolerant by design: a hostile server's content array is arbitrary JSON, so
    anything that is not a well-formed text block is skipped rather than raised
    on. Used for reporting, never for control flow.
    """
    parts: list[str] = []
    for block in content:
        if isinstance(block, dict) and block.get("type") == "text":
            text = block.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "".join(parts)
