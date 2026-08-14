"""The clean server's advertised metadata, as data.

Split out of ``server_clean.py`` so it can be read without running the server.
``server_clean.py`` calls ``serve()`` at module scope -- importing it would block
on stdin forever -- but step 4's rules need this metadata in a pure test that
runs in CI, where there is no container.

One definition, two readers: the fixture server serves it, and
``tests/test_clean_server_is_clean.py`` asserts all three rules find nothing in
it. A hand-copied mirror in the test would drift the first time either side
changed, and would drift silently, because the test proving them equal is
Docker-gated and skips in CI.

Deliberately no imports and no side effects, so it is safe to import from
anywhere.

**This metadata is a negative control and must stay realistic.** The `instructions`
field contains a genuine imperative, one tool is marked destructive, the schema is
nested and the prompt takes arguments -- the shapes a rule is most likely to
misfire on. Keep it that way; a control made bland to pass is not a control.
"""

from __future__ import annotations

INSTRUCTIONS = "Use read_file before write_file."

SERVER_INFO = {"name": "fixture", "title": "mcpscan fixture", "version": "0.0.1"}

TOOLS_PAGE_ONE = [
    {
        "name": "read_file",
        "title": "Read a file",
        "description": "Returns the contents of a file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to read."}
            },
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "write_file",
        "description": "Writes a file. You must provide an absolute path.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
]

TOOLS_PAGE_TWO = [
    {
        "name": "list_dir",
        "description": "Lists a directory.",
        "inputSchema": {"type": "object", "additionalProperties": False},
    }
]

TOOLS = TOOLS_PAGE_ONE + TOOLS_PAGE_TWO

RESOURCES = [
    {
        "uri": "file:///project/README.md",
        "name": "README.md",
        "title": "Project documentation",
        "mimeType": "text/markdown",
        "size": 42,
    }
]

RESOURCE_TEMPLATES = [{"uriTemplate": "file:///{path}", "name": "Project files"}]

PROMPTS = [
    {
        "name": "code_review",
        "description": "Asks for a code review.",
        "arguments": [{"name": "code", "description": "The code", "required": True}],
    }
]
