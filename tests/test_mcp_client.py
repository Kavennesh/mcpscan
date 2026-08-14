"""The stdio transport and MCP client, against real servers in real containers.

Every test here launches a fixture server from ``tests/fixtures/servers/`` inside
the runner image and holds a genuine JSON-RPC conversation with it. That is the
whole point: ``test_jsonrpc.py`` and ``test_client_logic.py`` prove the decisions,
and this proves the wiring that carries them -- ``SandboxSession``'s pipes, the
reader pump, request correlation across a live process.

**These skip in CI.** CI has a Docker daemon but never runs ``make images``, so
``images_ready()`` is false there and nothing below executes. That is deliberate
and it is also why the parsing logic lives in pure modules: if a hostile-input
decision can only be reached through this file, it is unverified on every pull
request. Run ``make sandbox-test`` locally -- this file is the real gate for
step 3.

Conventions follow ``test_sandbox.py``: deferred import inside the test body, so
an ImportError is seven readable failures rather than a collection error that
hides the entire repository's suite.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager, suppress
from pathlib import Path, PurePosixPath
from typing import Any

import pytest

from tests.dockerprobe import images_ready, skip_reason

FIXTURES = Path(__file__).parent / "fixtures"

pytestmark = [
    pytest.mark.sandbox,
    pytest.mark.skipif(not images_ready(), reason=skip_reason()),
]


def _sandbox() -> Any:
    from mcpscan import sandbox

    return sandbox


def _client_mod() -> Any:
    from mcpscan import client

    return client


@asynccontextmanager
async def connect(
    fixture: str,
    *args: str,
    **limits: Any,
) -> AsyncIterator[tuple[Any, Any, Any]]:
    """Launch a fixture server and yield ``(session, transport, client)``.

    The mounted directory is ``tests/fixtures`` rather than the servers
    subdirectory so the fixtures' ``sys.path`` insert of ``/fixtures/servers``
    resolves, matching how the escape suite mounts its own tree.
    """
    sb = _sandbox()
    from mcpscan.client import MCPClient
    from mcpscan.transport import StdioTransport

    command: Sequence[str] = ["python3", f"/fixtures/servers/{fixture}", *args]

    async with sb.SandboxHandle.session(
        command,
        image=sb.Image.RUNNER,
        limits=sb.Limits(**limits),
        mounts=(sb.Mount(source=FIXTURES, target=PurePosixPath("/fixtures"), read_only=True),),
    ) as session:
        transport = StdioTransport(session)
        try:
            yield session, transport, MCPClient(transport)
        finally:
            await transport.aclose()


def kinds(transport: Any) -> set[Any]:
    return set(transport.anomalies.kinds())


# --------------------------------------------------------------------------
# 1. the happy path, and the absence of false positives
# --------------------------------------------------------------------------
async def test_a_clean_server_produces_no_anomalies() -> None:
    """The negative control. A parser that cries wolf gets its findings ignored."""
    async with connect("server_clean.py") as (_, transport, client):
        survey = await client.survey()

    assert survey.profile.protocol_version == "2025-11-25"
    assert survey.profile.decision is _client_mod().VersionDecision.MATCHED
    assert survey.profile.name == "fixture"
    assert survey.profile.instructions == "Use read_file before write_file."
    assert survey.profile.declares("tools")
    assert survey.profile.sub_capability("tools", "listChanged")

    assert [tool["name"] for tool in survey.tools] == ["read_file", "write_file", "list_dir"]
    assert [resource["name"] for resource in survey.resources] == ["README.md"]
    assert [prompt["name"] for prompt in survey.prompts] == ["code_review"]
    assert len(survey.resource_templates) == 1

    assert transport.anomalies.items == (), [a.kind for a in transport.anomalies]


async def test_the_live_server_serves_exactly_what_clean_metadata_declares() -> None:
    """The drift guard for step 4's negative control.

    ``test_negative_controls.py`` asserts that all three static rules find
    nothing in ``clean_metadata`` -- and that test runs in CI, where there is no
    container. This one runs only where there is, and proves the pure test is
    checking what the real server actually serves rather than a copy that
    drifted. Without it, the control could silently stop describing the fixture.
    """
    from mcpscan.document import MetadataDocument
    from tests.fixtures.servers import clean_metadata

    async with connect("server_clean.py") as (_, _transport, client):
        survey = await client.survey()

    served = MetadataDocument.from_survey(survey)

    assert served.instructions == clean_metadata.INSTRUCTIONS
    assert served.tools == clean_metadata.TOOLS
    assert served.resources == clean_metadata.RESOURCES
    assert served.resource_templates == clean_metadata.RESOURCE_TEMPLATES
    assert served.prompts == clean_metadata.PROMPTS


async def test_the_live_clean_server_produces_no_static_findings() -> None:
    """Belt and braces: the rules run against a genuinely served document."""
    from mcpscan.analyser import Subject, analyse
    from mcpscan.document import MetadataDocument

    async with connect("server_clean.py") as (_, _transport, client):
        survey = await client.survey()

    result = analyse(Subject(label="clean", document=MetadataDocument.from_survey(survey)))
    assert result.findings == [], [f.message for f in result.findings]


async def test_pagination_walks_every_page() -> None:
    """Three tools across two pages: the cursor loop is walked, not short-circuited."""
    async with connect("server_clean.py") as (_, transport, client):
        await client.initialize()
        tools = await client.list_tools()

    assert len(tools) == 3
    assert kinds(transport) == set()


async def test_tool_execution_errors_are_not_protocol_errors() -> None:
    async with connect("server_clean.py") as (_, _transport, client):
        await client.initialize()
        ok = await client.call_tool("read_file", {"path": "/x"})
        execution = await client.call_tool("write_file", {})
        protocol = await client.call_tool("no_such_tool", {})

    assert not ok.failed
    assert ok.text == "file contents"

    # A successful exchange whose payload describes a failure.
    assert execution.is_error and execution.protocol_error is None
    assert execution.text == "path is required"

    # The request itself was unusable.
    assert protocol.protocol_error is not None and not protocol.is_error
    assert protocol.protocol_error["code"] == -32602


async def test_resources_and_prompts_are_reachable() -> None:
    async with connect("server_clean.py") as (_, _transport, client):
        await client.initialize()
        contents = await client.read_resource("file:///project/README.md")
        prompt = await client.get_prompt("code_review", {"code": "x = 1"})

    assert contents[0]["text"] == "# Project"
    assert prompt is not None
    assert prompt["messages"][0]["role"] == "user"


async def test_the_session_exits_cleanly_when_stdin_closes() -> None:
    """Shutdown per spec: close the input stream, and the server should leave."""
    async with connect("server_clean.py") as (session, _transport, client):
        await client.initialize()

    result = session.result()
    assert result.outcome is _sandbox().Outcome.EXITED
    assert result.exit_code == 0
    assert not result.stdout_truncated


# --------------------------------------------------------------------------
# 2. stdout pollution
# --------------------------------------------------------------------------
async def test_banners_are_recorded_and_the_stream_resynchronises() -> None:
    from mcpscan.models import AnomalyKind

    async with connect("server_noise.py") as (_, transport, client):
        profile = await client.initialize()
        tools = await client.list_tools()

    assert profile.name == "fixture"
    assert [tool["name"] for tool in tools] == ["noisy"]

    junk = transport.anomalies.of_kind(AnomalyKind.NON_JSON_STDOUT)
    assert len(junk) >= 4, [a.detail for a in junk]
    assert any(b"npm WARN" in (a.raw or b"") for a in junk)
    assert any(b"progress:" in (a.raw or b"") for a in junk)


# --------------------------------------------------------------------------
# 3. the unbounded line
# --------------------------------------------------------------------------
async def test_an_unbounded_message_is_capped_not_fatal() -> None:
    """4 MiB with no newline. The per-message cap catches it and we stay alive."""
    from mcpscan.models import AnomalyKind
    from mcpscan.transport import TransportClosed, TransportTimeout

    async with connect("server_unbounded_line.py", wall_clock_s=60.0) as (
        session,
        transport,
        client,
    ):
        await client.initialize()
        with pytest.raises((TransportTimeout, TransportClosed)):
            await transport.request("tools/list", timeout=15.0)

    assert AnomalyKind.OVERSIZED_LINE in kinds(transport)
    # It really did flood: a fixture that died early would prove nothing.
    assert session.result().stdout_seen > 4 * 1024 * 1024


async def test_a_flood_past_the_sandbox_cap_kills_the_container() -> None:
    """The second, coarser bound. Independent of the transport's own cap."""
    from mcpscan.transport import TransportClosed, TransportTimeout

    async with connect(
        "server_unbounded_line.py",
        wall_clock_s=60.0,
        stdout_bytes=1024 * 1024,
    ) as (session, transport, client):
        await client.initialize()
        # However this fails is the transport's business; the assertion that
        # matters is what the *sandbox* did about it.
        with suppress(TransportTimeout, TransportClosed):
            await transport.request("tools/list", timeout=15.0)

    result = session.result()
    assert result.outcome is _sandbox().Outcome.OUTPUT_CAP
    assert result.stdout_truncated


# --------------------------------------------------------------------------
# 4. version negotiation
# --------------------------------------------------------------------------
async def test_a_downgrade_is_accepted_and_recorded() -> None:
    from mcpscan.models import AnomalyKind

    async with connect("server_bad_version.py", "2025-03-26") as (_, transport, client):
        profile = await client.initialize()
        tools = await client.list_tools()

    assert profile.protocol_version == "2025-03-26"
    assert profile.decision is _client_mod().VersionDecision.DOWNGRADE
    assert AnomalyKind.VERSION_DOWNGRADE in kinds(transport)
    assert [tool["name"] for tool in tools] == ["legacy"]


async def test_an_unspeakable_version_ends_the_scan() -> None:
    from mcpscan.client import HandshakeError
    from mcpscan.models import AnomalyKind

    async with connect("server_bad_version.py", "1999-01-01") as (_, transport, client):
        with pytest.raises(HandshakeError):
            await client.initialize()

    assert AnomalyKind.UNSUPPORTED_VERSION in kinds(transport)


# --------------------------------------------------------------------------
# 5. correlation abuse
# --------------------------------------------------------------------------
async def test_a_second_response_cannot_overwrite_the_first() -> None:
    from mcpscan.models import AnomalyKind

    async with connect("server_dup_ids.py") as (_, transport, client):
        await client.initialize()
        # Catches the unsolicited response the server volunteers after initialize.
        await transport.settle()
        tools = await client.list_tools()
        # And this one catches the duplicate. `list_tools` returns the instant
        # the *first* response resolves its future, so without a settle here the
        # block exits and aclose() cancels the reader while the overwrite is
        # still in flight -- the assertion below then fails intermittently, on
        # scheduling rather than on behaviour.
        await transport.settle()

    # The benign list is what we acted on; the overwrite was recorded, not applied.
    assert len(tools) == 1
    assert "IMPORTANT" not in tools[0]["description"]

    observed = kinds(transport)
    assert AnomalyKind.DUPLICATE_ID in observed
    assert AnomalyKind.UNSOLICITED_RESPONSE in observed


# --------------------------------------------------------------------------
# 6. pagination that never ends
# --------------------------------------------------------------------------
async def test_a_repeated_cursor_is_caught_by_loop_detection() -> None:
    from mcpscan.models import AnomalyKind

    async with connect("server_cursor_loop.py", "same", wall_clock_s=60.0) as (
        _,
        transport,
        client,
    ):
        await client.initialize()
        tools = await client.list_tools()

    assert AnomalyKind.CURSOR_LOOP in kinds(transport)
    assert AnomalyKind.PAGE_CAP not in kinds(transport)
    assert len(tools) == 2


async def test_ever_fresh_cursors_are_caught_by_the_page_cap() -> None:
    """Loop detection cannot see this one. The cap must, and must say so."""
    from mcpscan.client import MAX_PAGES
    from mcpscan.models import AnomalyKind

    async with connect("server_cursor_loop.py", "fresh", wall_clock_s=90.0) as (
        _,
        transport,
        client,
    ):
        await client.initialize()
        tools = await client.list_tools()

    assert AnomalyKind.PAGE_CAP in kinds(transport)
    assert len(tools) == MAX_PAGES


# --------------------------------------------------------------------------
# 7. silence
# --------------------------------------------------------------------------
async def test_a_server_that_never_answers_times_out_rather_than_hanging() -> None:
    from mcpscan.client import HandshakeError
    from mcpscan.models import AnomalyKind

    async with connect("server_silent.py", wall_clock_s=60.0) as (_, transport, client):
        with pytest.raises(HandshakeError):
            await client.initialize(timeout=2.0)

    assert AnomalyKind.REQUEST_TIMEOUT in kinds(transport)


# --------------------------------------------------------------------------
# 8. parser attacks
# --------------------------------------------------------------------------
async def test_deep_nesting_is_rejected_without_taking_the_client_down() -> None:
    """RecursionError, not JSONDecodeError. The depth pre-check is what saves us."""
    from mcpscan.models import AnomalyKind
    from mcpscan.transport import TransportClosed, TransportTimeout

    async with connect("server_deep_json.py", wall_clock_s=60.0) as (_, transport, client):
        await client.initialize()
        with pytest.raises((TransportTimeout, TransportClosed)):
            await transport.request("tools/list", timeout=10.0)
        await transport.settle(0.2)

    assert AnomalyKind.JSON_TOO_DEEP in kinds(transport)
    # The stream survived the bad message: the notification after it arrived.
    assert "notifications/tools/list_changed" in transport.notification_methods()


# --------------------------------------------------------------------------
# 9. the rug pull
# --------------------------------------------------------------------------
async def test_a_mutated_tool_list_is_visible_by_diffing_a_re_listing() -> None:
    from mcpscan.client import tool_fingerprint

    async with connect("server_rugpull.py") as (_, transport, client):
        await client.initialize()
        before = await client.list_tools()
        await client.call_tool("search", {"query": "x"})
        await transport.settle()
        after = await client.list_tools()

    assert tool_fingerprint(before) != tool_fingerprint(after)
    assert "IMPORTANT" not in before[0]["description"]
    assert "IMPORTANT" in after[0]["description"]

    # The polite half: the notification arrived and was retained in order.
    assert "notifications/tools/list_changed" in transport.notification_methods()

    # Still claims readOnlyHint. Annotations are the server's word for it.
    assert after[0]["annotations"]["readOnlyHint"] is True


async def test_a_silent_mutation_is_caught_because_we_re_list_unprompted() -> None:
    """The case a notification-driven client misses completely."""
    from mcpscan.client import tool_fingerprint

    async with connect("server_rugpull.py", "silent") as (_, transport, client):
        await client.initialize()
        before = await client.list_tools()
        await client.call_tool("search", {"query": "x"})
        await transport.settle()
        after = await client.list_tools()

    assert transport.notification_methods() == ()
    assert tool_fingerprint(before) != tool_fingerprint(after)


# --------------------------------------------------------------------------
# 10. undeclared capabilities
# --------------------------------------------------------------------------
async def test_tools_served_without_being_declared_are_recorded() -> None:
    """An ordinary client asks only for what was advertised, and sees nothing."""
    from mcpscan.models import AnomalyKind

    async with connect("server_undeclared.py") as (_, transport, client):
        profile = await client.initialize()
        await transport.settle()
        tools = await client.list_tools()

    assert profile.capabilities == {}
    assert not profile.declares("tools")
    assert [tool["name"] for tool in tools] == ["exfiltrate"]
    assert AnomalyKind.UNDECLARED_CAPABILITY in kinds(transport)


async def test_a_server_request_for_an_unoffered_capability_is_refused() -> None:
    from mcpscan.models import AnomalyKind

    async with connect("server_undeclared.py") as (_, transport, client):
        await client.initialize()
        await transport.settle(0.3)

    assert AnomalyKind.UNEXPECTED_SERVER_REQUEST in kinds(transport)
    assert [m.method for m in transport.server_requests] == ["sampling/createMessage"]


# --------------------------------------------------------------------------
# 11. containment is unchanged by any of the above
# --------------------------------------------------------------------------
async def test_a_session_leaves_no_container_behind() -> None:
    """Dropping --rm is what makes OOM attribution possible and leaks possible."""
    from tests.dockerprobe import container_exists

    async with connect("server_clean.py") as (session, _transport, client):
        await client.initialize()

    container_id = session.result().container_id
    assert container_id
    assert not container_exists(container_id)


async def test_a_session_target_still_has_no_network() -> None:
    """`-i` changes how we talk to the container, not what it is allowed to do."""
    sb = _sandbox()
    with pytest.raises(sb.SandboxError):
        async with sb.SandboxHandle.session(
            ["python3", "-c", "pass"],
            image=sb.Image.RUNNER,
            limits=sb.Limits(network=True),
        ):
            pass
