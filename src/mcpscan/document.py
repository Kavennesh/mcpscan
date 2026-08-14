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

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from mcpscan.models import Location

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
