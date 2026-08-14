"""MCP's stdio transport: JSON-RPC over a sandboxed container's stdin and stdout.

Deliberately thin. Framing lives in :mod:`mcpscan.jsonrpc` and protocol semantics
in :mod:`mcpscan.client`; what is left here is the pumping, and pumping is the one
part that cannot be tested without a Docker daemon. Keeping it small keeps the
untestable-in-CI surface small -- CI has a daemon but never runs ``make images``,
so every sandbox-marked test skips there.

:class:`StdioTransport` takes a :class:`~mcpscan.sandbox.SandboxSession` **and
nothing else**. There is no constructor parameter, no subclass hook and no
fallback that would let it read from a pipe the sandbox did not create. That is
the point of ``tests/test_containment.py``, restated at the level of an object:
process spawning is confined to ``sandbox.py``, so a transport that accepted an
arbitrary channel would be a way around it.

Two behaviours here are scanner-specific rather than client-specific:

**Every unsolicited notification is retained, in arrival order.** An ordinary
client drops notifications it has no handler for. For us
``notifications/tools/list_changed`` is the entire polite half of the rug-pull
signal, and its *position* relative to our own calls is what makes it evidence.

**Nothing a target sends raises.** Malformed, oversized and hostile output is
recorded on the :class:`~mcpscan.jsonrpc.AnomalyLog` and the conversation
continues. The two exceptions below are ours -- a request we gave up waiting for,
and a target that is gone -- and exist so the client can stop asking, not to
report a fault.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from types import TracebackType
from typing import Any, Final

from mcpscan.jsonrpc import (
    METHOD_NOT_FOUND,
    AnomalyLog,
    Dispatcher,
    Message,
    MessageStream,
    Route,
    encode_error,
    encode_notification,
    encode_request,
)
from mcpscan.models import AnomalyKind
from mcpscan.sandbox import SandboxSession

_READ_CHUNK: Final = 64 * 1024

#: Per-request budget. The spec asks implementations to time out every request
#: and to enforce a maximum regardless of progress notifications; a target that
#: stalls the handshake is the first hostile behaviour a scan can meet.
DEFAULT_REQUEST_TIMEOUT_S: Final = 10.0

#: How long to let the reader settle before snapshotting notifications. A server
#: that emits ``list_changed`` immediately after a call would otherwise be missed
#: by a re-list issued in the same breath.
SETTLE_S: Final = 0.05


class TransportTimeout(Exception):
    """A request went unanswered. Recorded as an anomaly; raised so callers move on."""


class TransportClosed(Exception):
    """The target's stdout reached EOF. Nothing further can be asked of it."""


class StdioTransport:
    """Newline-delimited JSON-RPC over a sandboxed target's stdio."""

    def __init__(self, session: SandboxSession) -> None:
        self._session = session
        self.anomalies = AnomalyLog()
        self._stream = MessageStream(self.anomalies)
        self._dispatcher = Dispatcher(self.anomalies)
        self._pending: dict[str | int, asyncio.Future[Message]] = {}
        self._notifications: list[Message] = []
        self._server_requests: list[Message] = []
        self._closed = False
        self._reader = asyncio.create_task(self._read_loop())

    async def __aenter__(self) -> StdioTransport:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        self._reader.cancel()
        await asyncio.gather(self._reader, return_exceptions=True)
        self._fail_pending("transport closed")

    # -- asking ---------------------------------------------------------
    async def request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        timeout: float = DEFAULT_REQUEST_TIMEOUT_S,
    ) -> Message:
        """Send a request and wait for its response.

        Raises :class:`TransportTimeout` if nothing comes back in time, having
        first recorded the anomaly and sent ``notifications/cancelled`` as the
        spec asks. Raises :class:`TransportClosed` if the target is already gone.
        """
        if self._closed:
            raise TransportClosed(f"cannot send {method!r}: the target's stdout is at EOF")

        request_id = self._dispatcher.next_id()
        future: asyncio.Future[Message] = asyncio.get_running_loop().create_future()
        self._pending[request_id] = future
        self._dispatcher.expect(request_id)

        await self._session.send(encode_request(method, request_id, params))

        try:
            return await asyncio.wait_for(future, timeout)
        except TimeoutError:
            self._pending.pop(request_id, None)
            self._dispatcher.forget(request_id)
            self.anomalies.record(
                AnomalyKind.REQUEST_TIMEOUT,
                f"no response to {method!r} (id={request_id}) within {timeout}s",
            )
            # Best effort. The spec says a sender SHOULD cancel a request it has
            # stopped waiting for; whether this target honours it is its business.
            await self.notify(
                "notifications/cancelled",
                {"requestId": request_id, "reason": "mcpscan request timeout"},
            )
            raise TransportTimeout(f"{method} timed out after {timeout}s") from None

    async def notify(self, method: str, params: Mapping[str, Any] | None = None) -> None:
        await self._session.send(encode_notification(method, params))

    async def settle(self, delay: float = SETTLE_S) -> None:
        """Let the reader catch up, so notifications in flight land before we look."""
        await asyncio.sleep(delay)

    # -- what came back unbidden ----------------------------------------
    @property
    def notifications(self) -> tuple[Message, ...]:
        return tuple(self._notifications)

    @property
    def server_requests(self) -> tuple[Message, ...]:
        return tuple(self._server_requests)

    @property
    def closed(self) -> bool:
        return self._closed

    def notification_methods(self) -> tuple[str, ...]:
        return tuple(m.method for m in self._notifications if m.method is not None)

    # -- pumping --------------------------------------------------------
    async def _read_loop(self) -> None:
        while True:
            chunk = await self._session.read(_READ_CHUNK)
            if not chunk:
                self._stream.close()
                self._closed = True
                self._fail_pending("the target's stdout reached EOF")
                return
            for message in self._stream.feed(chunk):
                await self._route(message)

    async def _route(self, message: Message) -> None:
        route = self._dispatcher.classify(message)

        if route is Route.DELIVER and message.id is not None:
            future = self._pending.pop(message.id, None)
            if future is not None and not future.done():
                future.set_result(message)
            return

        if route is Route.RETAIN:
            self._notifications.append(message)
            return

        if route is Route.REFUSE:
            self._server_requests.append(message)
            await self._session.send(
                encode_error(
                    message.id,
                    METHOD_NOT_FOUND,
                    f"mcpscan does not implement {message.method!r} "
                    "and negotiated no capability for it",
                )
            )

    def _fail_pending(self, reason: str) -> None:
        if self._pending:
            self.anomalies.record(
                AnomalyKind.TRANSPORT_CLOSED,
                f"{reason} with {len(self._pending)} request(s) unanswered",
            )
        for request_id, future in list(self._pending.items()):
            self._dispatcher.forget(request_id)
            if not future.done():
                future.set_exception(TransportClosed(reason))
        self._pending.clear()
