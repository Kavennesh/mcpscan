"""One metadata shape for both ways of seeing a server, and the traversal over it.

A target can be met as a live server, as a source tree, or as both. The rules
should not care: MCP-001 asks "is there an invisible character in this text"
without needing to know whether the text arrived over stdio or came out of a
docstring. :class:`MetadataDocument` is where those two views collapse into one,
and :func:`walk_text` is the single traversal every metadata rule runs on.

Two things here are less obvious than they look.

**The walk yields more than the three obvious fields.** A tool's description is
the famous place to hide a payload, but it is not the only text that reaches a
model. Property descriptions nested inside ``inputSchema`` reach it identically,
and being one level down is precisely what makes them a good hiding place, so the
schema is walked recursively. Prompt argument descriptions, resource titles and
annotation titles are all in scope for the same reason.

**Source correlation is keyed on tool name, not on matching strings.** When both
views exist, the live survey is ground truth for what a model actually sees --
source can be stale, or can build a description at import time -- so the document
is the survey's, and source locations are *attached* to it by matching
``SourceTool.name`` against the survey's tool names. Fuzzy matching of description
text against string literals would be guesswork, and would fail on exactly the
servers worth scanning: the ones assembling descriptions at runtime.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from mcpscan.models import Location, Span

#: Nested schemas are walked, but a hostile server can nest forever. This is the
#: same argument as `jsonrpc.MAX_DEPTH`, applied to a structure we already parsed.
MAX_SCHEMA_DEPTH: Final = 16


def escape_token(token: str) -> str:
    """Escape one JSON Pointer reference token (RFC 6901 §3).

    ``~`` first, then ``/`` -- the other order would double-escape, turning a
    literal ``/`` into ``~01`` instead of ``~1``.
    """
    return token.replace("~", "~0").replace("/", "~1")


def pointer(*tokens: str | int) -> str:
    """Build a URI-fragment JSON pointer: ``#/tools/3/description``."""
    return "#" + "".join("/" + escape_token(str(token)) for token in tokens)


class FieldKind(StrEnum):
    """What a piece of text *is*, so a rule can vary by field rather than by guess.

    MCP-002 needs this: an imperative in `instructions` is that field doing its
    job, while the same sentence in a tool description is a server steering a
    model through documentation it was not asked to write.
    """

    INSTRUCTIONS = "instructions"
    SERVER_INFO = "server_info"
    TOOL_NAME = "tool_name"
    TOOL_TITLE = "tool_title"
    TOOL_DESCRIPTION = "tool_description"
    SCHEMA_DESCRIPTION = "schema_description"
    SCHEMA_ENUM = "schema_enum"
    ANNOTATION_TITLE = "annotation_title"
    RESOURCE_NAME = "resource_name"
    RESOURCE_TITLE = "resource_title"
    RESOURCE_DESCRIPTION = "resource_description"
    RESOURCE_URI = "resource_uri"
    PROMPT_NAME = "prompt_name"
    PROMPT_TITLE = "prompt_title"
    PROMPT_DESCRIPTION = "prompt_description"
    PROMPT_ARGUMENT = "prompt_argument"


#: Fields whose entire purpose is to address the model. An imperative here is not
#: evidence of anything; only override, secrecy and injection framing is.
MODEL_FACING_KINDS: Final = frozenset({FieldKind.INSTRUCTIONS})


@dataclass(frozen=True, slots=True)
class TextField:
    """One string a model can see, and everything needed to point at it."""

    pointer: str
    text: str
    kind: FieldKind
    location: Location | None = None

    def locate(self) -> Location:
        """The best location available, always carrying the pointer."""
        if self.location is None:
            return Location(pointer=self.pointer)
        return self.location.model_copy(update={"pointer": self.pointer})


@dataclass(frozen=True, slots=True)
class MetadataDocument:
    """Everything a server advertises, in one shape, however we came to see it."""

    instructions: str | None = None
    server_info: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    resource_templates: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    #: pointer -> where that field lives in source, when we know.
    source_locations: dict[str, Location] = field(default_factory=dict)

    @classmethod
    def from_survey(cls, survey: Any) -> MetadataDocument:
        """Build from a :class:`~mcpscan.client.ServerSurvey`."""
        profile = survey.profile
        return cls(
            instructions=profile.instructions,
            server_info=dict(profile.server_info),
            tools=list(survey.tools),
            resources=list(survey.resources),
            resource_templates=list(survey.resource_templates),
            prompts=list(survey.prompts),
        )

    @classmethod
    def from_source(cls, tools: Iterable[Any]) -> MetadataDocument:
        """Build from extracted :class:`~mcpscan.source.SourceTool` objects.

        This is the no-server path: a source tree alone is enough to scan tool
        metadata, which is what makes ``--path`` worth having.
        """
        entries: list[dict[str, Any]] = []
        locations: dict[str, Location] = {}
        for index, tool in enumerate(tools):
            entry: dict[str, Any] = {"name": tool.name}
            if tool.title is not None:
                entry["title"] = tool.title
            if tool.description is not None:
                entry["description"] = tool.description
            if tool.input_schema is not None:
                entry["inputSchema"] = tool.input_schema
            entries.append(entry)
            locations.update(_tool_locations(index, tool))
        return cls(tools=entries, source_locations=locations)

    def with_source(self, tools: Iterable[Any]) -> MetadataDocument:
        """Attach source locations to this document, matching on tool name.

        The document stays exactly as the server served it. Only locations are
        added -- if source and server disagree about a description, the server's
        is what a model receives, and that disagreement is a finding for a later
        step rather than a licence to prefer the source.
        """
        by_name = {tool.name: tool for tool in tools}
        locations = dict(self.source_locations)
        for index, entry in enumerate(self.tools):
            name = entry.get("name")
            if not isinstance(name, str):
                continue
            tool = by_name.get(name)
            if tool is not None:
                locations.update(_tool_locations(index, tool))
        return MetadataDocument(
            instructions=self.instructions,
            server_info=self.server_info,
            tools=self.tools,
            resources=self.resources,
            resource_templates=self.resource_templates,
            prompts=self.prompts,
            source_locations=locations,
        )


def _tool_locations(index: int, tool: Any) -> dict[str, Location]:
    """Map each of a source tool's known field line ranges to its pointer."""
    locations: dict[str, Location] = {}
    for field_name, (start, end) in tool.field_lines.items():
        locations[pointer("tools", index, field_name)] = Location(
            path=tool.path, start_line=start, end_line=end
        )
    return locations


def _text(value: object) -> str | None:
    """A non-empty string, or nothing. Hostile input is any JSON type at all."""
    if isinstance(value, str) and value:
        return value
    return None


def walk_text(doc: MetadataDocument) -> Iterator[TextField]:
    """Yield every string in ``doc`` that can reach a model.

    Order is stable and mirrors the document: instructions, then tools in
    listing order, then resources, templates and prompts. Stability matters
    because findings are reported in traversal order within a severity band, and
    a report that reshuffles between runs cannot be diffed.
    """
    locations = doc.source_locations

    def emit(ptr: str, value: object, kind: FieldKind) -> Iterator[TextField]:
        text = _text(value)
        if text is not None:
            yield TextField(pointer=ptr, text=text, kind=kind, location=locations.get(ptr))

    yield from emit(pointer("instructions"), doc.instructions, FieldKind.INSTRUCTIONS)

    for key in ("name", "title"):
        yield from emit(pointer("serverInfo", key), doc.server_info.get(key), FieldKind.SERVER_INFO)

    for index, tool in enumerate(doc.tools):
        yield from emit(pointer("tools", index, "name"), tool.get("name"), FieldKind.TOOL_NAME)
        yield from emit(pointer("tools", index, "title"), tool.get("title"), FieldKind.TOOL_TITLE)
        yield from emit(
            pointer("tools", index, "description"),
            tool.get("description"),
            FieldKind.TOOL_DESCRIPTION,
        )

        annotations = tool.get("annotations")
        if isinstance(annotations, dict):
            yield from emit(
                pointer("tools", index, "annotations", "title"),
                annotations.get("title"),
                FieldKind.ANNOTATION_TITLE,
            )

        for schema_key in ("inputSchema", "outputSchema"):
            schema = tool.get(schema_key)
            if isinstance(schema, dict):
                yield from _walk_schema(schema, pointer("tools", index, schema_key), locations)

    for index, resource in enumerate(doc.resources):
        yield from _walk_named("resources", index, resource, locations, RESOURCE_KINDS)
        yield from emit(
            pointer("resources", index, "uri"), resource.get("uri"), FieldKind.RESOURCE_URI
        )

    for index, template in enumerate(doc.resource_templates):
        yield from _walk_named("resourceTemplates", index, template, locations, RESOURCE_KINDS)
        yield from emit(
            pointer("resourceTemplates", index, "uriTemplate"),
            template.get("uriTemplate"),
            FieldKind.RESOURCE_URI,
        )

    for index, prompt in enumerate(doc.prompts):
        yield from _walk_named("prompts", index, prompt, locations, PROMPT_KINDS)
        arguments = prompt.get("arguments")
        if isinstance(arguments, list):
            for arg_index, argument in enumerate(arguments):
                if not isinstance(argument, dict):
                    continue
                for key in ("name", "description"):
                    ptr = pointer("prompts", index, "arguments", arg_index, key)
                    text = _text(argument.get(key))
                    if text is not None:
                        yield TextField(
                            pointer=ptr,
                            text=text,
                            kind=FieldKind.PROMPT_ARGUMENT,
                            location=locations.get(ptr),
                        )


RESOURCE_KINDS: Final = {
    "name": FieldKind.RESOURCE_NAME,
    "title": FieldKind.RESOURCE_TITLE,
    "description": FieldKind.RESOURCE_DESCRIPTION,
}

PROMPT_KINDS: Final = {
    "name": FieldKind.PROMPT_NAME,
    "title": FieldKind.PROMPT_TITLE,
    "description": FieldKind.PROMPT_DESCRIPTION,
}


def _walk_named(
    section: str,
    index: int,
    entry: Mapping[str, Any],
    locations: Mapping[str, Location],
    kinds: Mapping[str, FieldKind],
) -> Iterator[TextField]:
    for key, kind in kinds.items():
        text = _text(entry.get(key))
        if text is None:
            continue
        ptr = pointer(section, index, key)
        yield TextField(pointer=ptr, text=text, kind=kind, location=locations.get(ptr))


def _walk_schema(
    schema: Mapping[str, Any],
    prefix: str,
    locations: Mapping[str, Location],
    depth: int = 0,
) -> Iterator[TextField]:
    """Walk a JSON Schema for text a model will read.

    Descriptions nested in ``properties`` reach the model exactly as a tool
    description does, and being a level down is what makes them worth hiding in.
    ``enum`` values are included because a schema is free to enumerate strings
    that are really sentences.
    """
    if depth > MAX_SCHEMA_DEPTH:
        return

    description = _text(schema.get("description"))
    if description is not None:
        ptr = f"{prefix}/description"
        yield TextField(
            pointer=ptr,
            text=description,
            kind=FieldKind.SCHEMA_DESCRIPTION,
            location=locations.get(ptr),
        )

    title = _text(schema.get("title"))
    if title is not None:
        ptr = f"{prefix}/title"
        yield TextField(
            pointer=ptr,
            text=title,
            kind=FieldKind.SCHEMA_DESCRIPTION,
            location=locations.get(ptr),
        )

    enum = schema.get("enum")
    if isinstance(enum, list):
        for enum_index, value in enumerate(enum):
            text = _text(value)
            if text is not None:
                ptr = f"{prefix}/enum/{enum_index}"
                yield TextField(
                    pointer=ptr,
                    text=text,
                    kind=FieldKind.SCHEMA_ENUM,
                    location=locations.get(ptr),
                )

    for container in ("properties", "patternProperties", "$defs", "definitions"):
        block = schema.get(container)
        if isinstance(block, dict):
            for key, value in block.items():
                if isinstance(value, dict):
                    yield from _walk_schema(
                        value, f"{prefix}/{container}/{escape_token(str(key))}",
                        locations, depth + 1,
                    )

    for container in ("items", "additionalProperties", "not"):
        block = schema.get(container)
        if isinstance(block, dict):
            yield from _walk_schema(block, f"{prefix}/{container}", locations, depth + 1)

    for container in ("anyOf", "oneOf", "allOf", "prefixItems"):
        block = schema.get(container)
        if isinstance(block, list):
            for sub_index, value in enumerate(block):
                if isinstance(value, dict):
                    yield from _walk_schema(
                        value, f"{prefix}/{container}/{sub_index}", locations, depth + 1
                    )


# ---------------------------------------------------------------------------
# The survey artefact
#
# A live server has no file. Its findings carry a JSON pointer and nothing else,
# and a SARIF result with no `physicalLocation` is silently dropped by GitHub --
# so a scan of a server that failed nine ways would upload as a clean run. The
# fix is to give those findings a file: serialise the document the rules walked,
# and record where every value landed in it.
#
# Written here rather than in `sarif.py` on purpose. The artefact's addresses and
# the rules' addresses are the same JSON pointers, and the two only stay in
# agreement if the code that builds them sits next to `walk_text`. A serialiser
# in another module would drift the first time a field was added to the walk.
#
# Note for whoever adds a second consumer: `prober.localise` mounts the working
# directory read-only into the container, so a previous scan's artefact is
# readable by the next target. Nothing secret is in one -- canaries are redacted
# and the content is what the server itself served -- but an evasive server can
# use it to learn that it is being scanned and what was seen last time.
# ---------------------------------------------------------------------------

#: A hostile server chooses how long its descriptions are. It does not get to
#: choose how large our artefact is -- the same argument as `RAW_SAMPLE_BYTES`
#: and `EVIDENCE_CHARS`, one layer out.
MAX_ARTEFACT_VALUE_CHARS: Final = 4096

#: Deeper than `walk_text` will ever look (`MAX_SCHEMA_DEPTH`), shallow enough
#: not to exhaust the stack. The live path is already bounded by
#: `jsonrpc.MAX_DEPTH`; a source tree's `ast.literal_eval` output is not.
MAX_ARTEFACT_DEPTH: Final = 64

TRUNCATED = "…[mcpscan: truncated]"


def _escaped(text: str) -> str:
    """The characters JSON would write between the quotes.

    ``ensure_ascii=True`` throughout, and not for looks. It is what makes a lone
    surrogate -- which ``json.loads`` accepts from the wire and UTF-8 cannot
    encode -- survive as ``\\ud800`` instead of crashing the writer. It also
    makes the artefact pure ASCII, so a character, a UTF-16 code unit and a byte
    are the same thing and a SARIF column is just an offset.
    """
    return json.dumps(text, ensure_ascii=True)[1:-1]


@dataclass(frozen=True, slots=True)
class Anchor:
    """Where one value from the document landed in the serialised artefact.

    ``line`` and ``column`` are 1-based and point at the value's first character
    -- the opening quote, for a string. ``text`` is the value *before* redaction
    and truncation, because that is what a finding's :class:`~mcpscan.models.Span`
    indexes; ``exact`` and ``limit`` record whether that indexing still survives
    the trip through the writer.
    """

    line: int
    column: int
    #: The original string, when this anchor is on one. ``None`` for containers.
    text: str | None = None
    #: False when redaction rewrote the value, so offsets into ``text`` no longer
    #: line up with what was written. A line is still exact; columns are not.
    exact: bool = True
    #: How many characters were actually written, when the value was capped.
    limit: int | None = None
    #: Width of the value as written, between the quotes. Measured rather than
    #: derived, so it survives redaction and truncation -- which is what lets
    #: :meth:`whole` answer for a value :meth:`columns` cannot.
    width: int | None = None

    def columns(self, span: Span) -> tuple[int, int] | None:
        """SARIF ``startColumn``/``endColumn`` for a span within this value.

        ``None`` when the artefact cannot honestly place it: a redacted value, a
        span past the cap, or an anchor on a container rather than a string.
        Reporting the line alone is the right answer there -- an invented column
        points a reader at the wrong characters and looks authoritative doing it.
        """
        if not self.exact or self.text is None:
            return None
        if self.limit is not None and span.end > self.limit:
            return None
        if span.end > len(self.text):
            return None
        opening = self.column + 1
        return (
            opening + len(_escaped(self.text[: span.start])),
            opening + len(_escaped(self.text[: span.end])),
        )

    def whole(self) -> tuple[int, int] | None:
        """Columns spanning the entire value, for a finding with no span.

        A pattern rule matched a substring and says where. A probe did not: a
        rug pull is a statement about a whole field, and MCP-009 is a statement
        about a whole `instructions` block. Those still deserve columns -- the
        alternative is a region that starts at the line and ends nowhere, which
        renders as the whole line including the key and the punctuation.

        Measured from what was written, so unlike :meth:`columns` this survives a
        redacted or truncated value: the width is real even when the offsets a
        span would use are not.
        """
        if self.width is None:
            return None
        return (self.column + 1, self.column + 1 + self.width)


@dataclass(frozen=True, slots=True)
class SurveyArtefact:
    """A serialised :class:`MetadataDocument` and a map back into it."""

    text: str
    anchors: dict[str, Anchor]
    #: Tool name -> index, for the *unique* names only. Two tools called
    #: ``search`` are two tools; a name that does not identify one is not an
    #: identity, and a fingerprint built on it would merge them.
    tool_index: dict[str, int] = field(default_factory=dict)

    def anchor_for(self, target: str) -> Anchor:
        """The best place in the artefact for a pointer, never nothing.

        Four steps, in order. An exact hit. Then a probe pointer -- ``probes.py``
        writes ``#/_probe/rug-pull/<tool>`` when a tool has no index in the later
        listing -- resolved by name back to the tool it is about. Then the
        longest prefix that does exist, so a nested schema field lands on its
        tool rather than nowhere. Then the root.

        The chain bottoms out at line 1 rather than at ``None`` deliberately:
        ``#/_transport/7`` names an arrival order, not a place in the metadata,
        and a result that GitHub drops is a finding nobody is told about.
        """
        anchor = self.anchors.get(target)
        if anchor is not None:
            return anchor

        # Split on the first two segments only. Probe pointers interpolate the
        # tool name without RFC 6901 escaping, so a tool called `read/file`
        # arrives here as four segments and the name is everything after the
        # second.
        if target.startswith("#/_probe/"):
            parts = target.split("/", 3)
            if len(parts) == 4:
                index = self.tool_index.get(parts[3])
                if index is not None:
                    anchor = self.anchors.get(pointer("tools", index))
                    if anchor is not None:
                        return anchor

        prefix = target
        while "/" in prefix:
            prefix = prefix.rsplit("/", 1)[0]
            anchor = self.anchors.get(prefix)
            if anchor is not None:
                return anchor

        return self.anchors.get("#", Anchor(line=1, column=1))


class _Writer:
    """Appends ASCII and remembers where it is. Nothing else."""

    __slots__ = ("anchors", "column", "line", "parts")

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.line = 1
        self.column = 1
        self.anchors: dict[str, Anchor] = {}

    def raw(self, text: str) -> None:
        """Write text that contains no newline. Everything here is ASCII."""
        self.parts.append(text)
        self.column += len(text)

    def newline(self, indent: int) -> None:
        self.parts.append("\n" + "  " * indent)
        self.line += 1
        self.column = 2 * indent + 1


def _emit_string(
    writer: _Writer, value: str, ptr: str, redact: Callable[[str], str] | None
) -> None:
    shown = redact(value) if redact is not None else value
    exact = shown == value
    limit: int | None = None
    if len(shown) > MAX_ARTEFACT_VALUE_CHARS:
        limit = MAX_ARTEFACT_VALUE_CHARS
        shown = shown[:MAX_ARTEFACT_VALUE_CHARS] + TRUNCATED
    writer.anchors[ptr] = Anchor(
        line=writer.line,
        column=writer.column,
        text=value,
        exact=exact,
        limit=limit,
        width=len(_escaped(shown)),
    )
    writer.raw(json.dumps(shown, ensure_ascii=True))


def _emit(
    writer: _Writer,
    value: object,
    ptr: str,
    indent: int,
    depth: int,
    redact: Callable[[str], str] | None,
) -> None:
    if isinstance(value, str):
        _emit_string(writer, value, ptr, redact)
        return

    writer.anchors[ptr] = Anchor(line=writer.line, column=writer.column)

    if depth > MAX_ARTEFACT_DEPTH:
        writer.raw(json.dumps(TRUNCATED, ensure_ascii=True))
        return

    if isinstance(value, Mapping):
        items = list(value.items())
        if not items:
            writer.raw("{}")
            return
        writer.raw("{")
        for position, (key, sub) in enumerate(items):
            name = str(key)
            writer.newline(indent + 1)
            writer.raw(json.dumps(name, ensure_ascii=True) + ": ")
            _emit(writer, sub, f"{ptr}/{escape_token(name)}", indent + 1, depth + 1, redact)
            if position < len(items) - 1:
                writer.raw(",")
        writer.newline(indent)
        writer.raw("}")
        return

    if isinstance(value, (list, tuple)):
        entries = list(value)
        if not entries:
            writer.raw("[]")
            return
        writer.raw("[")
        for index, sub in enumerate(entries):
            writer.newline(indent + 1)
            _emit(writer, sub, f"{ptr}/{index}", indent + 1, depth + 1, redact)
            if index < len(entries) - 1:
                writer.raw(",")
        writer.newline(indent)
        writer.raw("]")
        return

    try:
        # `allow_nan=False` because `json.loads` accepts `Infinity` and `NaN` by
        # default and `json.dumps` will happily write them back out, producing a
        # file no strict parser -- including the one validating the SARIF that
        # points at it -- will read.
        writer.raw(json.dumps(value, ensure_ascii=True, allow_nan=False))
    except (ValueError, TypeError):
        writer.raw("null")


#: The artefact's top-level keys are the *pointer* tokens, not the dataclass
#: attribute names. `walk_text` emits `#/serverInfo/name` and
#: `#/resourceTemplates/0/uriTemplate`; `MetadataDocument` spells those fields
#: `server_info` and `resource_templates`. Serialise the attribute names and
#: every finding on either falls back to line 1 -- invisibly, because the
#: fallback is designed to be invisible.
_ROOT_KEYS: Final = ("instructions", "serverInfo", "tools", "resources", "resourceTemplates",
                     "prompts")


def serialise(
    doc: MetadataDocument, *, redact: Callable[[str], str] | None = None
) -> SurveyArtefact:
    """Write the document out, recording where every value went.

    Deterministic: no clock, no ordering that depends on a set, and the same
    document twice produces the same bytes. That is what makes the artefact
    diffable -- it changes when the server changes and not otherwise -- and it
    is why ``redact`` exists, since a canary token is regenerated every scan and
    would otherwise churn the file on every run.
    """
    payload: dict[str, object] = {
        "instructions": doc.instructions,
        "serverInfo": doc.server_info,
        "tools": doc.tools,
        "resources": doc.resources,
        "resourceTemplates": doc.resource_templates,
        "prompts": doc.prompts,
    }

    writer = _Writer()
    writer.anchors["#"] = Anchor(line=1, column=1)
    writer.raw("{")
    for position, key in enumerate(_ROOT_KEYS):
        writer.newline(1)
        writer.raw(json.dumps(key, ensure_ascii=True) + ": ")
        _emit(writer, payload[key], pointer(key), 1, 1, redact)
        if position < len(_ROOT_KEYS) - 1:
            writer.raw(",")
    writer.newline(0)
    writer.raw("}")

    counts: dict[str, int] = {}
    for tool in doc.tools:
        if isinstance(tool, Mapping):
            name = tool.get("name")
            if isinstance(name, str):
                counts[name] = counts.get(name, 0) + 1
    index_by_name = {
        name: index
        for index, tool in enumerate(doc.tools)
        if isinstance(tool, Mapping)
        and isinstance(name := tool.get("name"), str)
        and counts[name] == 1
    }

    return SurveyArtefact(
        text="".join(writer.parts) + "\n",
        anchors=writer.anchors,
        tool_index=index_by_name,
    )
