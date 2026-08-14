"""Realistic tool descriptions that MCP-002 must not fire on.

This is the project's false-positive regression corpus, not a one-off test
fixture. Step 5's YAML rules and every rule after them get run against it, so a
pattern that buys recall by spending precision fails here loudly instead of
degrading the tool quietly.

The entries are written fresh, modelled on the shapes real MCP servers use --
filesystem, database, HTTP, git, search, messaging, cloud. They are deliberately
stocked with the phrasings most likely to trip a naive rule:

* second-person imperatives about *parameters* ("you must provide an absolute
  path"), which is ordinary documentation and appears everywhere;
* the words "important", "always", "never" and "do not" used as warnings to a
  human reader;
* factual statements about call ordering ("call list_tables first if..."), which
  describe a dependency rather than command the model to obey one;
* the words "assistant", "model" and "prompt" appearing as domain vocabulary,
  because plenty of real tools are *about* those things.

A corpus without those would prove nothing. If a future pattern needs one of
these lines removed to pass, the pattern is wrong, not the line.
"""

from __future__ import annotations

BENIGN_DESCRIPTIONS = [
    # -- parameter documentation in the second person --------------------
    "You must provide an absolute path; relative paths are rejected.",
    "You should pass a valid ISO 8601 timestamp, e.g. 2024-01-31T09:00:00Z.",
    "You need to authenticate before calling this; see the README for setup.",
    "Returns results ranked by relevance to your query.",
    "If you omit the branch, the repository default is used.",
    "You can pass either a numeric id or a slug.",
    # -- warnings aimed at a human ---------------------------------------
    "Important: this operation cannot be undone.",
    "Do not use this for files larger than 10 MB; use create_upload instead.",
    "Never returns partial rows - the query either completes or raises.",
    "Always returns UTC. Pass a timezone to convert.",
    "Warning: rate limited to 10 requests per minute per token.",
    "Note that the query is executed as-is against the primary replica.",
    "Caution: deletes the branch on the remote as well as locally.",
    # -- factual ordering, not a directive --------------------------------
    "Call list_tables first if you do not know the schema.",
    "Requires a prior call to open_session to obtain a handle.",
    "The cursor from a previous page must be passed to continue pagination.",
    "Run after apply_migration so the schema cache is warm.",
    # -- domain vocabulary that overlaps the rule's own words -------------
    "The assistant-facing name shown in tool pickers.",
    "Returns the system prompt configured for this workspace.",
    "Lists language models available to the current account.",
    "Deletes a saved prompt template by name.",
    "Renders a chat transcript, including assistant turns, as Markdown.",
    "Sets the instructions field on an agent configuration.",
    # -- filesystem --------------------------------------------------------
    "Reads a UTF-8 text file and returns its contents.",
    "Writes content to a file, creating parent directories as needed.",
    "Lists directory entries, optionally recursing into subdirectories.",
    "Moves or renames a file. Fails if the destination exists.",
    "Returns file metadata: size, mode, and modification time.",
    "Searches file contents for a pattern and returns matching lines.",
    # -- database ----------------------------------------------------------
    "Executes a read-only SQL query and returns rows as JSON objects.",
    "Describes a table's columns, types, and constraints.",
    "Returns the 20 slowest queries recorded in the last hour.",
    "Begins a transaction and returns its identifier.",
    "Explains a query plan without executing the statement.",
    # -- http and network --------------------------------------------------
    "Issues an HTTP GET and returns the decoded response body.",
    "Posts a JSON payload to the configured webhook endpoint.",
    "Resolves a hostname to its A and AAAA records.",
    "Fetches a URL and extracts the readable article text.",
    # -- version control ---------------------------------------------------
    "Returns the diff between two commits as unified patch text.",
    "Stages the given paths and creates a commit with the supplied message.",
    "Lists open pull requests, most recently updated first.",
    "Shows the commit that last modified each line of a file.",
    # -- search and messaging ---------------------------------------------
    "Full-text search across indexed documents, returning ranked snippets.",
    "Posts a message to a channel and returns its permalink.",
    "Marks a conversation as read for the authenticated user.",
    "Searches messages by author, channel, and date range.",
    # -- cloud -------------------------------------------------------------
    "Lists objects in a bucket under an optional key prefix.",
    "Returns a presigned URL valid for the requested number of seconds.",
    "Describes running instances in the selected region.",
    "Tails the last N lines from a log stream.",
    # -- multi-sentence, the shape most likely to trip a span matcher ------
    "Deletes a record permanently. This cannot be undone, so you should "
    "confirm the id first with get_record. Returns the deleted row.",
    "Uploads a file. Important: the maximum size is 100 MB and you must "
    "provide a content type. Larger files should use multipart_upload.",
]
