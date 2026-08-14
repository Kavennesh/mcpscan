"""Running the rules over whatever view of a target we have.

A target can be seen as a source tree, as a live server, or as both, and not
every rule works on every view: MCP-003 needs code, MCP-001 and MCP-002 need
advertised metadata. The job here is to run what can be run and to be exact about
what could not.

That last part is the reason :class:`AnalysisResult` carries ``skipped`` and
``unparsed`` alongside the findings. "No findings" and "no analysis" look
identical in a report that only lists findings, and the difference is the whole
value of the tool -- a user who reads a clean report for a scan that never
examined anything is worse off than one who ran nothing, because now they believe
something. Both fields are printed whether or not anything was found.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcpscan.document import MetadataDocument
from mcpscan.models import Finding
from mcpscan.rules import InvisibleUnicodeRule, ModelDirectedInstructionRule, RuleSet
from mcpscan.source import SourceTool, SourceTree, extract_by_name, extract_tools, load_tree
from mcpscan.taint import UnsanitisedSinkRule

#: The three rules of step 4. Step 5 will add YAML-defined rules alongside these.
DEFAULT_RULES = RuleSet(
    metadata_rules=(InvisibleUnicodeRule(), ModelDirectedInstructionRule()),
    source_rules=(UnsanitisedSinkRule(),),
)


@dataclass(frozen=True, slots=True)
class Subject:
    """One thing to analyse, in however many views we have of it."""

    label: str
    document: MetadataDocument | None = None
    tree: SourceTree | None = None
    tools: list[SourceTool] = field(default_factory=list)

    @classmethod
    def from_path(cls, root: Path, label: str | None = None) -> Subject:
        """Build from a source tree alone -- no server, no container, no handshake."""
        tree = load_tree(root)
        tools = extract_tools(tree)
        return cls(
            label=label or str(root),
            document=MetadataDocument.from_source(tools),
            tree=tree,
            tools=tools,
        )

    @classmethod
    def from_survey(cls, survey: Any, label: str, root: Path | None = None) -> Subject:
        """Build from a live server, correlating with source when a root is given.

        The survey is the document: it is what a model actually receives. Source
        only contributes locations, and -- through :func:`extract_by_name` -- the
        set of functions worth tainting, since the survey names the tools even on
        a server whose registration pattern we do not recognise.
        """
        document = MetadataDocument.from_survey(survey)
        if root is None:
            return cls(label=label, document=document)

        tree = load_tree(root)
        names = {
            name
            for tool in survey.tools
            if isinstance(name := tool.get("name"), str)
        }
        tools = extract_tools(tree)
        known = {tool.name for tool in tools}
        tools += [tool for tool in extract_by_name(tree, names) if tool.name not in known]

        return cls(label=label, document=document.with_source(tools), tree=tree, tools=tools)


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    unparsed: list[tuple[Path, str]] = field(default_factory=list)
    ran: list[str] = field(default_factory=list)
    #: (rule id, why) -- coverage a reader must be told about.
    skipped: list[tuple[str, str]] = field(default_factory=list)

    def at_or_above(self, threshold: Any) -> list[Finding]:
        return [f for f in self.findings if f.severity.rank >= threshold.rank]


def analyse(subject: Subject, rules: RuleSet = DEFAULT_RULES) -> AnalysisResult:
    """Run every applicable rule over ``subject``."""
    findings: list[Finding] = []
    ran: list[str] = []
    skipped: list[tuple[str, str]] = []

    for rule in rules.metadata_rules:
        if subject.document is None:
            skipped.append((rule.meta.id, "no server metadata available"))
            continue
        ran.append(rule.meta.id)
        findings.extend(rule.check(subject.document))

    for source_rule in rules.source_rules:
        if subject.tree is None:
            skipped.append((source_rule.meta.id, "no source available"))
            continue
        if not subject.tools:
            skipped.append((source_rule.meta.id, "no tool definitions found in source"))
            continue
        ran.append(source_rule.meta.id)
        findings.extend(source_rule.check(subject.tree, subject.tools))

    for finding in findings:
        if not finding.subject:
            finding.subject = subject.label

    findings.sort(key=lambda f: f.sort_key)

    return AnalysisResult(
        findings=findings,
        files_scanned=subject.tree.file_count if subject.tree else 0,
        unparsed=list(subject.tree.unparsed) if subject.tree else [],
        ran=ran,
        skipped=skipped,
    )
