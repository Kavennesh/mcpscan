"""An MCP client for revision 2025-11-25, written to be lied to.

This is not a client that wants to use a server; it is a client that wants to find
out what a server is. The difference shows up in three places, and each one is
the opposite of what an ordinary implementation does:

**It probes capabilities the server did not declare.** Only asking for what was
advertised would miss the most interesting case -- a server that declares no
``tools`` capability and answers ``tools/list`` anyway is misrepresenting its own
surface, and that is exactly the kind of thing this tool exists to notice.

**It advertises nothing.** :data:`CLIENT_CAPABILITIES` is empty. Declaring
``sampling`` or ``elicitation`` would invite server-to-client requests we cannot
serve; declaring nothing means any such request is unambiguous evidence that the
server reaches for capabilities it was never offered.

**It never trusts a self-description.** The spec is explicit that clients "**MUST**
consider tool annotations to be untrusted"; ``readOnlyHint`` is a claim, not a
fact. The same goes for ``serverInfo.name``, a resource's declared ``size``, and
the ``instructions`` string -- which is free text that ordinary clients feed
straight into a model's context, and therefore one of the highest-value artefacts
a scan can extract. All of it is recorded verbatim and acted on never.

Pagination deserves its own note. Cursors are opaque by definition -- clients
**MUST NOT** parse, modify or persist them -- so there is no way to validate one.
A server can hand back a fresh cursor forever and a naive client will loop until
it dies. :class:`PaginationGuard` is the whole defence: a page cap plus a
seen-cursor set.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from mcpscan.jsonrpc import AnomalyLog, Message, text_of
from mcpscan.models import AnomalyKind
from mcpscan.transport import StdioTransport, TransportClosed, TransportTimeout

#: The revision we speak. Sent as-is in `initialize`.
PROTOCOL_VERSION: Final = "2025-11-25"

#: Revisions we can still hold a conversation in if a server counter-offers.
#: Every one of them is older than :data:`PROTOCOL_VERSION`, so any of them
#: coming back is a downgrade worth recording.
SUPPORTED_VERSIONS: Final = frozenset(
    {"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}
)

CLIENT_NAME: Final = "mcpscan"
CLIENT_VERSION: Final = "0.1.0"

#: Empty on purpose -- see the module docstring.
CLIENT_CAPABILITIES: Final[Mapping[str, Any]] = {}

#: A server can paginate forever. This is where we stop believing it.
MAX_PAGES: Final = 50

#: `instructions` is attacker-controlled text destined for a model's context.
#: Worth keeping; not worth keeping a megabyte of.
MAX_INSTRUCTIONS_CHARS: Final = 8192

_LIST_METHODS: Final = {
    "tools": ("tools/list", "tools"),
    "resources": ("resources/list", "resources"),
    "resourceTemplates": ("resources/templates/list", "resourceTemplates"),
    "prompts": ("prompts/list", "prompts"),
}


class HandshakeError(Exception):
    """Initialization could not complete, so there is nothing further to scan."""


class VersionDecision(StrEnum):
    MATCHED = "matched"
    DOWNGRADE = "downgrade"
    UNSUPPORTED = "unsupported"


def negotiate_version(offered: object) -> tuple[VersionDecision, str]:
    """Decide what to do with the ``protocolVersion`` a server responded with.

    Pure, and separated out because it is the one piece of the handshake with
    real branching. The rule from the 2025-11-25 lifecycle:

        If the server supports the requested protocol version, it MUST respond
        with the same version. Otherwise, the server MUST respond with another
        protocol version it supports. If the client does not support the version
        in the server's response, it SHOULD disconnect.

    There is no range and no overlap calculation: one proposal, one counter-offer,
    then accept or leave.
    """
    if not isinstance(offered, str) or not offered:
        return VersionDecision.UNSUPPORTED, ""
    if offered == PROTOCOL_VERSION:
        return VersionDecision.MATCHED, offered
    if offered in SUPPORTED_VERSIONS:
        return VersionDecision.DOWNGRADE, offered
    return VersionDecision.UNSUPPORTED, offered


class PaginationGuard:
    """Bounds one paginated listing. Pure -- no I/O, no awaits.

    Cursors being opaque means there is nothing to validate, so the only two
    defences available are "stop after N pages" and "stop if a cursor repeats".
    Both are here; a server that wants to loop us has to at least generate a
    fresh cursor every time, and even then it gets fifty pages.
    """

    __slots__ = ("_anomalies", "_max_pages", "_method", "_pages", "_seen")

    def __init__(self, anomalies: AnomalyLog, method: str, max_pages: int = MAX_PAGES) -> None:
        self._anomalies = anomalies
        self._method = method
        self._max_pages = max_pages
        self._seen: set[str] = set()
        self._pages = 0

    @property
    def pages(self) -> int:
        return self._pages

    def advance(self, cursor: object) -> str | None:
        """Record that a page arrived; return the next cursor, or None to stop."""
        self._pages += 1

        if cursor is None:
            return None

        if not isinstance(cursor, str) or not cursor:
            self._anomalies.record(
                AnomalyKind.MALFORMED_MESSAGE,
                f"{self._method} returned nextCursor of type "
                f"{type(cursor).__name__}, expected a non-empty string",
            )
            return None

        if cursor in self._seen:
            self._anomalies.record(
                AnomalyKind.CURSOR_LOOP,
                f"{self._method} returned a cursor already seen after "
                f"{self._pages} page(s); pagination does not terminate",
            )
            return None

        if self._pages >= self._max_pages:
            self._anomalies.record(
                AnomalyKind.PAGE_CAP,
                f"{self._method} still paginating after {self._pages} pages; "
                f"stopping at the cap. Results are incomplete.",
            )
            return None

        self._seen.add(cursor)
        return cursor


@dataclass(frozen=True, slots=True)
class ServerProfile:
    """What a server said about itself during the handshake. All of it unverified."""

    protocol_version: str
    decision: VersionDecision
    server_info: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    instructions: str | None = None

    @property
    def name(self) -> str:
        name = self.server_info.get("name")
        return name if isinstance(name, str) else "<unnamed>"

    @property
    def version(self) -> str:
        version = self.server_info.get("version")
        return version if isinstance(version, str) else "<unversioned>"

    def declares(self, capability: str) -> bool:
        return isinstance(self.capabilities.get(capability), dict)

    def sub_capability(self, capability: str, name: str) -> bool:
        block = self.capabilities.get(capability)
        return isinstance(block, dict) and block.get(name) is True


@dataclass(frozen=True, slots=True)
class ToolCallResult:
    """One ``tools/call`` outcome, keeping the two failure modes apart.

    A protocol error and an ``isError: true`` result are different things: the
    first says the request was unusable, the second is a *successful* exchange
    whose payload happens to describe a failure. Both carry attacker-controlled
    text that reaches a model, so both are worth keeping -- but conflating them
    loses the fact that the server understood us perfectly well.
    """

    name: str
    content: list[Any] = field(default_factory=list)
    structured: dict[str, Any] | None = None
    is_error: bool = False
    protocol_error: dict[str, Any] | None = None

    @property
    def text(self) -> str:
        return text_of(self.content)

    @property
    def failed(self) -> bool:
        return self.is_error or self.protocol_error is not None


@dataclass(frozen=True, slots=True)
class ServerSurvey:
    """Everything a server exposed in one pass -- the baseline a rug pull is measured against."""

    profile: ServerProfile
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    resource_templates: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)


def tool_fingerprint(tools: list[dict[str, Any]]) -> dict[str, str]:
    """Map each tool name to a stable digest of everything that steers a model.

    Name, title, description, schemas and annotations -- the fields whose silent
    mutation between two listings *is* the rug pull. Sorted keys so the digest
    does not change when a server reorders its JSON.
    """
    fingerprints: dict[str, str] = {}
    for tool in tools:
        name = tool.get("name")
        if not isinstance(name, str):
            continue
        salient = {
            key: tool.get(key)
            for key in ("title", "description", "inputSchema", "outputSchema", "annotations")
            if key in tool
        }
        fingerprints[name] = json.dumps(salient, sort_keys=True, default=str)
    return fingerprints


class MCPClient:
    """Drives one MCP conversation over a :class:`~mcpscan.transport.StdioTransport`."""

    def __init__(self, transport: StdioTransport) -> None:
        self._transport = transport
        self.anomalies: AnomalyLog = transport.anomalies
        self.profile: ServerProfile | None = None

    # -- handshake ------------------------------------------------------
    async def initialize(self, *, timeout: float | None = None) -> ServerProfile:
        """Perform the handshake and send ``notifications/initialized``.

        Raises :class:`HandshakeError` if the server errors, answers with
        something unusable, or offers a revision we cannot speak -- in which case
        the spec says to disconnect, and there is nothing left to scan anyway.
        """
        params = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": dict(CLIENT_CAPABILITIES),
            "clientInfo": {
                "name": CLIENT_NAME,
                "title": "mcpscan security scanner",
                "version": CLIENT_VERSION,
            },
        }

        try:
            response = await self._request("initialize", params, timeout=timeout)
        except (TransportTimeout, TransportClosed) as exc:
            raise HandshakeError(f"initialize failed: {exc}") from exc

        if response.is_error:
            raise HandshakeError(f"server rejected initialize -- {response.error_text()}")

        result = response.result
        if not isinstance(result, dict):
            raise HandshakeError(
                f"initialize result is {type(result).__name__}, expected an object"
            )

        decision, version = negotiate_version(result.get("protocolVersion"))
        if decision is VersionDecision.UNSUPPORTED:
            self.anomalies.record(
                AnomalyKind.UNSUPPORTED_VERSION,
                f"server offered protocolVersion {result.get('protocolVersion')!r}, "
                f"which mcpscan cannot speak; disconnecting as the spec directs",
            )
            raise HandshakeError(f"unsupported protocol version {version!r}")
        if decision is VersionDecision.DOWNGRADE:
            self.anomalies.record(
                AnomalyKind.VERSION_DOWNGRADE,
                f"requested {PROTOCOL_VERSION}, server answered {version}; "
                "continuing on the older revision",
            )

        instructions = result.get("instructions")
        if isinstance(instructions, str):
            instructions = instructions[:MAX_INSTRUCTIONS_CHARS]
        else:
            instructions = None

        server_info = result.get("serverInfo")
        capabilities = result.get("capabilities")

        profile = ServerProfile(
            protocol_version=version,
            decision=decision,
            server_info=server_info if isinstance(server_info, dict) else {},
            capabilities=capabilities if isinstance(capabilities, dict) else {},
            instructions=instructions,
        )
        self.profile = profile

        await self._transport.notify("notifications/initialized")
        return profile

    # -- discovery ------------------------------------------------------
    async def list_tools(self) -> list[dict[str, Any]]:
        return await self._list("tools", "tools")

    async def list_resources(self) -> list[dict[str, Any]]:
        return await self._list("resources", "resources")

    async def list_resource_templates(self) -> list[dict[str, Any]]:
        return await self._list("resources", "resourceTemplates")

    async def list_prompts(self) -> list[dict[str, Any]]:
        return await self._list("prompts", "prompts")

    async def survey(self) -> ServerSurvey:
        """Handshake, then enumerate everything the server will admit to.

        The result is the baseline a later re-survey is diffed against: capture,
        exercise, re-list unprompted, compare. The notification is never the
        trigger -- a server that mutates its tools without sending one is the
        case that matters.
        """
        profile = self.profile or await self.initialize()
        return ServerSurvey(
            profile=profile,
            tools=await self.list_tools(),
            resources=await self.list_resources(),
            resource_templates=await self.list_resource_templates(),
            prompts=await self.list_prompts(),
        )

    # -- invocation -----------------------------------------------------
    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> ToolCallResult:
        params: dict[str, Any] = {"name": name, "arguments": dict(arguments or {})}
        try:
            response = await self._request("tools/call", params, timeout=timeout)
        except (TransportTimeout, TransportClosed):
            return ToolCallResult(name=name, protocol_error={"code": 0, "message": "no response"})

        if response.is_error:
            return ToolCallResult(name=name, protocol_error=response.error)

        result = response.result
        if not isinstance(result, dict):
            self.anomalies.record(
                AnomalyKind.MALFORMED_MESSAGE,
                f"tools/call result for {name!r} is {type(result).__name__}, expected an object",
                raw=response.raw,
            )
            return ToolCallResult(name=name)

        content = result.get("content")
        structured = result.get("structuredContent")
        return ToolCallResult(
            name=name,
            content=list(content) if isinstance(content, list) else [],
            structured=structured if isinstance(structured, dict) else None,
            is_error=result.get("isError") is True,
        )

    async def read_resource(self, uri: str) -> list[dict[str, Any]]:
        """Read one resource. Bounded by the transport's line cap, not by declared size.

        A resource's ``size`` field is a server's claim about itself; a resource
        that announces ten bytes and returns ten gigabytes is a normal thing for
        a hostile server to try. The cap that actually holds is the one in
        :mod:`mcpscan.jsonrpc`, which does not consult the server about it.
        """
        try:
            response = await self._request("resources/read", {"uri": uri})
        except (TransportTimeout, TransportClosed):
            return []
        if response.is_error or not isinstance(response.result, dict):
            return []
        contents = response.result.get("contents")
        if not isinstance(contents, list):
            return []
        return [entry for entry in contents if isinstance(entry, dict)]

    async def get_prompt(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        params: dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = dict(arguments)
        try:
            response = await self._request("prompts/get", params)
        except (TransportTimeout, TransportClosed):
            return None
        if response.is_error or not isinstance(response.result, dict):
            return None
        return response.result

    # -- internals ------------------------------------------------------
    async def _request(
        self,
        method: str,
        params: Mapping[str, Any] | None,
        *,
        timeout: float | None = None,
    ) -> Message:
        if timeout is None:
            return await self._transport.request(method, params)
        return await self._transport.request(method, params, timeout=timeout)

    async def _list(self, capability: str, key: str) -> list[dict[str, Any]]:
        """Collect a paginated listing, probing whether or not it was declared."""
        method, result_key = _LIST_METHODS[key]
        declared = self.profile is not None and self.profile.declares(capability)

        items = await self._collect(method, result_key)

        if items is None:
            return []

        if not declared and items:
            self.anomalies.record(
                AnomalyKind.UNDECLARED_CAPABILITY,
                f"server answered {method} with {len(items)} item(s) but never "
                f"declared the {capability!r} capability; both parties MUST only "
                "use capabilities that were negotiated",
            )
        return items

    async def _collect(self, method: str, key: str) -> list[dict[str, Any]] | None:
        """Page through a list method. ``None`` means the server would not answer."""
        guard = PaginationGuard(self.anomalies, method)
        items: list[dict[str, Any]] = []
        cursor: str | None = None

        while True:
            params = {"cursor": cursor} if cursor is not None else None
            try:
                response = await self._request(method, params)
            except (TransportTimeout, TransportClosed):
                return items or None

            if response.is_error:
                # A plain "I don't do that" -- the common, honest answer from a
                # server without this capability. Not an anomaly by itself; the
                # anomaly is answering when it said it could not.
                return None if not items else items

            result = response.result
            if not isinstance(result, dict):
                self.anomalies.record(
                    AnomalyKind.MALFORMED_MESSAGE,
                    f"{method} result is {type(result).__name__}, expected an object",
                    raw=response.raw,
                )
                return items

            page = result.get(key)
            if isinstance(page, list):
                items.extend(entry for entry in page if isinstance(entry, dict))
            else:
                self.anomalies.record(
                    AnomalyKind.MALFORMED_MESSAGE,
                    f"{method} result has no {key!r} array",
                    raw=response.raw,
                )

            cursor = guard.advance(result.get("nextCursor"))
            if cursor is None:
                return items
