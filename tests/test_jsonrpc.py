"""The hostile-input contract for JSON-RPC framing.

These tests carry more weight than their subject matter suggests. CI has a Docker
daemon but never runs ``make images``, so every ``pytest.mark.sandbox`` test skips
there -- which means the suites that talk to a real container prove nothing on a
pull request. This file, and ``test_client_logic.py``, are what actually run.

So the rule for anything that decides how mcpscan reacts to a malformed, oversized
or hostile response is that it must live in a pure layer and be pinned here. If a
parsing decision can only be reached through a live container, it is untested
where it counts.

Every case below is phrased as "a server does X, and we record Y and keep going".
Nothing a target sends is allowed to raise.
"""

from __future__ import annotations

import json

import pytest

from mcpscan import jsonrpc
from mcpscan.jsonrpc import (
    MAX_LINE_BYTES,
    AnomalyLog,
    Dispatcher,
    Message,
    MessageKind,
    MessageStream,
    ProtocolError,
    Route,
    encode_error,
    encode_notification,
    encode_request,
    nesting_depth,
    text_of,
)
from mcpscan.models import RAW_SAMPLE_BYTES, AnomalyKind


def stream(**kwargs: int) -> tuple[MessageStream, AnomalyLog]:
    log = AnomalyLog()
    return MessageStream(log, **kwargs), log


def feed(payload: bytes, **kwargs: int) -> tuple[list[Message], AnomalyLog]:
    reader, log = stream(**kwargs)
    return reader.feed(payload), log


def line(payload: object) -> bytes:
    return json.dumps(payload).encode("utf-8") + b"\n"


# --------------------------------------------------------------------------
# encoding
# --------------------------------------------------------------------------
def test_requests_are_one_newline_terminated_line() -> None:
    raw = encode_request("tools/list", 1, {"cursor": "abc"})
    assert raw.endswith(b"\n")
    assert raw.count(b"\n") == 1
    assert json.loads(raw) == {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {"cursor": "abc"},
    }


def test_notifications_carry_no_id() -> None:
    assert json.loads(encode_notification("notifications/initialized")) == {
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    }


def test_params_are_omitted_rather_than_sent_as_null() -> None:
    assert "params" not in json.loads(encode_request("ping", 7))


def test_error_responses_echo_the_id_they_refuse() -> None:
    """What the transport sends back when a server reaches for a capability we
    never advertised. The id must be echoed or the server cannot correlate it."""
    assert json.loads(encode_error(4, -32601, "not implemented")) == {
        "jsonrpc": "2.0",
        "id": 4,
        "error": {"code": -32601, "message": "not implemented"},
    }


def test_newlines_in_our_own_output_are_escaped_not_emitted() -> None:
    """The framing violation we detect in others must be impossible for us to commit."""
    raw = encode_request("tools/call", 1, {"arguments": {"text": "a\nb"}})
    assert raw.count(b"\n") == 1
    assert json.loads(raw)["params"]["arguments"]["text"] == "a\nb"


@pytest.mark.parametrize(
    "hostile",
    ["a\nb", "a\r\nb", "\n" * 100, "tab\there", " line separator", "nul\x00byte"],
)
def test_no_control_character_can_break_our_framing(hostile: str) -> None:
    """Whatever goes into params, exactly one newline comes out: the terminator.

    Arguments are attacker-influenced in a scan -- we replay a server's own tool
    schemas back at it -- so this is the guard against emitting the very framing
    violation the parser is built to detect in others.
    """
    raw = encode_request("tools/call", 1, {"arguments": {"text": hostile}})
    assert raw.count(b"\n") == 1
    assert raw.endswith(b"\n")
    assert json.loads(raw)["params"]["arguments"]["text"] == hostile


def test_the_framing_guard_rejects_a_multi_line_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """ProtocolError is ours, never theirs: it fires on an mcpscan bug.

    The guard is unreachable through the public encoders -- json.dumps escapes
    every control character -- so serialisation is stubbed to prove the check
    actually fires. It is a backstop against a future `default=` hook or a
    pre-serialised payload quietly reintroducing the one framing violation this
    module exists to detect in others.
    """
    monkeypatch.setattr(jsonrpc.json, "dumps", lambda *a, **k: "line-one\nline-two")
    with pytest.raises(ProtocolError, match="newline"):
        encode_notification("notifications/initialized")


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------
def test_two_messages_in_one_chunk() -> None:
    messages, log = feed(line({"jsonrpc": "2.0", "id": 1, "result": {}}) + line(
        {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    ))
    assert [m.kind for m in messages] == [MessageKind.RESPONSE, MessageKind.NOTIFICATION]
    assert len(log) == 0


def test_a_message_split_across_chunks_is_reassembled() -> None:
    reader, log = stream()
    payload = line({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    collected: list[Message] = []
    for index in range(len(payload)):
        collected += reader.feed(payload[index : index + 1])
    assert len(collected) == 1
    assert collected[0].result == {"ok": True}
    assert len(log) == 0


def test_blank_lines_are_not_anomalies() -> None:
    messages, log = feed(b"\n\n" + line({"jsonrpc": "2.0", "id": 1, "result": 1}) + b"\n")
    assert len(messages) == 1
    assert len(log) == 0


def test_crlf_endings_are_tolerated() -> None:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "result": 1}).encode() + b"\r\n"
    messages, log = feed(payload)
    assert len(messages) == 1
    assert len(log) == 0


def test_non_json_stdout_is_recorded_and_the_stream_continues() -> None:
    """The npm-banner case: real servers pollute stdout, and we log every byte of it."""
    payload = b"npm WARN deprecated foo@1.0.0\n" + line({"jsonrpc": "2.0", "id": 1, "result": 1})
    messages, log = feed(payload)
    assert len(messages) == 1
    assert AnomalyKind.NON_JSON_STDOUT in log.kinds()
    assert log.of_kind(AnomalyKind.NON_JSON_STDOUT)[0].raw == b"npm WARN deprecated foo@1.0.0"


def test_invalid_utf8_is_recorded_not_raised() -> None:
    messages, log = feed(b"\xff\xfe not utf-8\n" + line({"jsonrpc": "2.0", "id": 1, "result": 1}))
    assert len(messages) == 1
    assert AnomalyKind.BAD_UTF8 in log.kinds()


def test_an_unbounded_line_is_capped_and_the_stream_resynchronises() -> None:
    """No length prefix means a server can write forever. This is the only bound."""
    reader, log = stream(max_line=1024)
    assert reader.feed(b"x" * 4096) == []
    assert AnomalyKind.OVERSIZED_LINE in log.kinds()

    # The tail of the overrun is discarded, and the next real message survives.
    messages = reader.feed(b"more junk\n" + line({"jsonrpc": "2.0", "id": 1, "result": 1}))
    assert len(messages) == 1
    assert messages[0].id == 1


def test_the_oversized_sample_is_bounded() -> None:
    _, log = feed(b"x" * (MAX_LINE_BYTES + 1024))
    raw = log.of_kind(AnomalyKind.OVERSIZED_LINE)[0].raw
    assert raw is not None
    assert len(raw) == RAW_SAMPLE_BYTES


def test_a_complete_but_oversized_line_is_dropped() -> None:
    reader, log = stream(max_line=64)
    assert reader.feed(b"y" * 200 + b"\n") == []
    assert AnomalyKind.OVERSIZED_LINE in log.kinds()


def test_unterminated_bytes_at_eof_are_reported() -> None:
    reader, log = stream()
    reader.feed(b'{"jsonrpc":"2.0","id":1,"result"')
    reader.close()
    assert AnomalyKind.MALFORMED_MESSAGE in log.kinds()


# --------------------------------------------------------------------------
# depth
# --------------------------------------------------------------------------
def test_nesting_depth_ignores_brackets_inside_strings() -> None:
    assert nesting_depth(b'{"a": "[[[[["}') == 1
    assert nesting_depth(b'{"a": {"b": [1]}}') == 3
    assert nesting_depth(rb'{"a": "\""}') == 1


def test_deep_nesting_is_rejected_before_parsing() -> None:
    """json.loads raises RecursionError, not JSONDecodeError -- the natural
    `except json.JSONDecodeError` misses this entirely, so depth is counted first."""
    payload = b"[" * 5000 + b"]" * 5000 + b"\n"
    messages, log = feed(payload)
    assert messages == []
    assert AnomalyKind.JSON_TOO_DEEP in log.kinds()


def test_depth_just_under_the_cap_still_parses() -> None:
    nested: object = 1
    for _ in range(30):
        nested = [nested]
    messages, log = feed(line({"jsonrpc": "2.0", "id": 1, "result": nested}))
    assert len(messages) == 1
    assert AnomalyKind.JSON_TOO_DEEP not in log.kinds()


# --------------------------------------------------------------------------
# spec violations
# --------------------------------------------------------------------------
def test_a_batch_array_is_a_spec_violation_not_a_shape_we_support() -> None:
    """Batching was removed in 2025-06-18 and stays removed in 2025-11-25."""
    messages, log = feed(line([{"jsonrpc": "2.0", "id": 1, "result": 1}]))
    assert messages == []
    assert AnomalyKind.BATCH_ARRAY in log.kinds()


def test_a_bare_scalar_is_malformed() -> None:
    messages, log = feed(b"42\n")
    assert messages == []
    assert AnomalyKind.MALFORMED_MESSAGE in log.kinds()


def test_a_wrong_jsonrpc_field_is_recorded_but_the_message_is_still_read() -> None:
    """Refusing to read it would let a server opt out of inspection for one bad field."""
    messages, log = feed(line({"jsonrpc": "1.0", "id": 1, "result": {"tools": []}}))
    assert len(messages) == 1
    assert messages[0].result == {"tools": []}
    assert AnomalyKind.MISSING_JSONRPC in log.kinds()


def test_result_and_error_together_is_recorded() -> None:
    messages, log = feed(
        line({"jsonrpc": "2.0", "id": 1, "result": {}, "error": {"code": -1, "message": "x"}})
    )
    assert len(messages) == 1
    assert AnomalyKind.RESULT_AND_ERROR in log.kinds()


def test_a_response_with_neither_result_nor_error_is_dropped() -> None:
    messages, log = feed(line({"jsonrpc": "2.0", "id": 1}))
    assert messages == []
    assert AnomalyKind.MALFORMED_MESSAGE in log.kinds()


def test_a_message_with_neither_method_nor_id_is_dropped() -> None:
    messages, log = feed(line({"jsonrpc": "2.0", "result": 1}))
    assert messages == []
    assert AnomalyKind.MALFORMED_MESSAGE in log.kinds()


@pytest.mark.parametrize("bad_id", [None, True, [1], {"a": 1}, 1.5])
def test_a_non_scalar_id_is_malformed(bad_id: object) -> None:
    messages, log = feed(line({"jsonrpc": "2.0", "id": bad_id, "result": 1}))
    assert messages == []
    assert AnomalyKind.MALFORMED_MESSAGE in log.kinds()


def test_a_non_string_method_is_malformed() -> None:
    messages, log = feed(line({"jsonrpc": "2.0", "method": 5}))
    assert messages == []
    assert AnomalyKind.MALFORMED_MESSAGE in log.kinds()


def test_an_embedded_newline_is_detected_by_rejoining_the_halves() -> None:
    """A literal newline splits one message in two, so it is invisible in either
    half alone. Rejoining and reparsing with strict=False proves the violation."""
    payload = b'{"jsonrpc":"2.0","id":1,"result":{"text":"before\nafter"}}\n'
    messages, log = feed(payload)
    assert len(messages) == 1
    assert messages[0].id == 1
    assert messages[0].result == {"text": "before\nafter"}
    assert AnomalyKind.EMBEDDED_NEWLINE in log.kinds()


def test_two_unrelated_junk_lines_are_not_mistaken_for_a_split_message() -> None:
    messages, log = feed(b"hello\nworld\n")
    assert messages == []
    assert AnomalyKind.EMBEDDED_NEWLINE not in log.kinds()
    assert len(log.of_kind(AnomalyKind.NON_JSON_STDOUT)) == 2


# --------------------------------------------------------------------------
# correlation
# --------------------------------------------------------------------------
def response(request_id: str | int) -> Message:
    return Message(kind=MessageKind.RESPONSE, id=request_id, result={})


def test_a_matched_response_is_delivered_once() -> None:
    log = AnomalyLog()
    dispatcher = Dispatcher(log)
    dispatcher.expect(1)
    assert dispatcher.classify(response(1)) is Route.DELIVER
    assert dispatcher.pending == frozenset()


def test_a_second_response_to_the_same_id_is_recorded() -> None:
    log = AnomalyLog()
    dispatcher = Dispatcher(log)
    dispatcher.expect(1)
    dispatcher.classify(response(1))
    assert dispatcher.classify(response(1)) is Route.DROP
    assert AnomalyKind.DUPLICATE_ID in log.kinds()


def test_a_response_we_never_asked_for_is_recorded() -> None:
    log = AnomalyLog()
    assert Dispatcher(log).classify(response(99)) is Route.DROP
    assert AnomalyKind.UNSOLICITED_RESPONSE in log.kinds()


def test_notifications_are_retained_never_dropped() -> None:
    """Dropping unrecognised notifications would destroy the rug-pull signal."""
    log = AnomalyLog()
    notification = Message(
        kind=MessageKind.NOTIFICATION, method="notifications/tools/list_changed"
    )
    assert Dispatcher(log).classify(notification) is Route.RETAIN
    assert len(log) == 0


def test_a_server_request_is_refused_and_recorded() -> None:
    """We advertise no client capabilities, so any server request is reaching."""
    log = AnomalyLog()
    request = Message(kind=MessageKind.REQUEST, id=1, method="sampling/createMessage")
    assert Dispatcher(log).classify(request) is Route.REFUSE
    assert AnomalyKind.UNEXPECTED_SERVER_REQUEST in log.kinds()


def test_forgotten_ids_do_not_come_back_as_unsolicited() -> None:
    log = AnomalyLog()
    dispatcher = Dispatcher(log)
    dispatcher.expect(1)
    dispatcher.forget(1)
    assert dispatcher.classify(response(1)) is Route.DROP
    assert AnomalyKind.DUPLICATE_ID in log.kinds()
    assert AnomalyKind.UNSOLICITED_RESPONSE not in log.kinds()


def test_ids_are_unique_and_monotonic() -> None:
    dispatcher = Dispatcher(AnomalyLog())
    ids = [dispatcher.next_id() for _ in range(100)]
    assert len(set(ids)) == 100
    assert ids == sorted(ids)


# --------------------------------------------------------------------------
# the log itself
# --------------------------------------------------------------------------
def test_anomaly_ordering_is_preserved_across_layers() -> None:
    """One counter for every layer -- interleaving is what makes a rug pull visible."""
    log = AnomalyLog()
    reader = MessageStream(log)
    dispatcher = Dispatcher(log)
    reader.feed(b"junk\n")
    dispatcher.classify(response(42))
    assert [item.seq for item in log] == [0, 1]
    assert [item.kind for item in log] == [
        AnomalyKind.NON_JSON_STDOUT,
        AnomalyKind.UNSOLICITED_RESPONSE,
    ]


def test_raw_samples_are_always_truncated() -> None:
    log = AnomalyLog()
    anomaly = log.record(AnomalyKind.NON_JSON_STDOUT, "x", raw=b"z" * 100_000)
    assert anomaly.raw is not None
    assert len(anomaly.raw) == RAW_SAMPLE_BYTES


def test_text_of_skips_anything_that_is_not_a_text_block() -> None:
    assert (
        text_of(
            [
                {"type": "text", "text": "one "},
                {"type": "image", "data": "..."},
                "not a block",
                {"type": "text", "text": 5},
                {"type": "text", "text": "two"},
            ]
        )
        == "one two"
    )
