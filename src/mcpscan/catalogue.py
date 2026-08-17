"""Every rule that can appear in a finding, from all four of its homes.

A rule can be a YAML file in the bundled pack, a YAML file in a contributed pack
loaded with ``--rules``, or code -- MCP-003 in ``taint.py``, MCP-004/005/006 in
``anomalies.py``, MCP-007/008/009 in ``probes.py``. Nothing needed the union of
those until now, because a report only ever named the rules that *did* fire.

SARIF needs the ones that did not. ``runs[].tool.driver.rules[]`` is the tool's
declaration of what it looked for, and a driver that lists only the rules with
results turns "MCP-008 ran and found nothing" into "MCP-008 was never mentioned",
which is the same conflation ``coverage`` exists to prevent in the JSON report.

``tests/test_rule_files.py`` composes the same four sources independently, so
that neither this module nor the docs check can quietly stop covering a home.
``test_the_catalogue_agrees_with_the_docs_check`` fails if they diverge.

One consequence worth knowing before adding an import here: reaching ``probes``
reaches ``canary``, which imports ``Mount`` from ``sandbox``. So importing the
reporting layer now imports the Docker layer, where before it stopped at the rule
engine. Nothing is executed by that import and there is no cycle, but if it ever
needs undoing, the seam is ``canary``'s dependency on ``Mount`` rather than
anything in this file.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from mcpscan.anomalies import rule_metas as anomaly_rule_metas
from mcpscan.engine import RuleMeta, RuleSet
from mcpscan.probes import rule_metas as probe_rule_metas
from mcpscan.taint import UnsanitisedSinkRule


class RuleFamily(StrEnum):
    """Which view of a target a rule works on. Becomes a SARIF tag."""

    #: Advertised metadata, from a live survey or synthesised from source.
    METADATA = "metadata"
    #: The source tree.
    SOURCE = "source"
    #: What the server did on the wire.
    PROTOCOL = "protocol"
    #: What the server did when its tools were called.
    DYNAMIC = "dynamic"


@dataclass(frozen=True, slots=True)
class CatalogueEntry:
    meta: RuleMeta
    family: RuleFamily


def rule_catalogue(rules: RuleSet) -> list[CatalogueEntry]:
    """Every rule that could fire in this scan, in stable id order.

    ``rules`` rather than a hard-coded list because ``--rules`` can add packs at
    runtime: a contributed rule that fires and is not declared would produce a
    SARIF result whose ``ruleId`` names nothing in the driver, which GitHub
    rejects the whole upload for.

    The dynamic rules are unconditional. ``--static-only`` means MCP-007/008/009
    did not run, and that is what ``coverage`` and the SARIF notifications are
    for; dropping them from the driver would say they do not exist.
    """
    entries = [
        CatalogueEntry(meta=rule.meta, family=RuleFamily.METADATA)
        for rule in rules.metadata_rules
    ]
    entries += [
        CatalogueEntry(meta=rule.meta, family=RuleFamily.SOURCE) for rule in rules.source_rules
    ]
    entries += [
        CatalogueEntry(meta=meta, family=RuleFamily.PROTOCOL) for meta in anomaly_rule_metas()
    ]
    entries += [
        CatalogueEntry(meta=meta, family=RuleFamily.DYNAMIC) for meta in probe_rule_metas()
    ]

    # A RuleSet built by hand in a test may omit MCP-003; the catalogue is a
    # declaration of the tool's capability, not of one scan's configuration.
    if not any(entry.meta.id == UnsanitisedSinkRule.meta.id for entry in entries):
        entries.append(CatalogueEntry(meta=UnsanitisedSinkRule.meta, family=RuleFamily.SOURCE))

    seen: set[str] = set()
    unique: list[CatalogueEntry] = []
    for entry in sorted(entries, key=lambda e: e.meta.id):
        # SARIF requires `rules` to hold unique items, and the loader already
        # rejects a duplicate id -- but a RuleSet assembled in code has no such
        # gate, and a duplicate would fail schema validation rather than a test.
        if entry.meta.id in seen:
            continue
        seen.add(entry.meta.id)
        unique.append(entry)
    return unique
