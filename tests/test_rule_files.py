"""The CI gate on the rule pack.

Every rule that ships must carry its own positive and negative cases, must clear
the shared benign corpora, and must have a documentation page. This file is where
those become build failures rather than good intentions.

The negative half is the half that matters. A rule whose author never wrote down
what it must *not* match is a rule nobody can safely change later: the next
person to widen a pattern has nothing telling them they went too far, and the
first sign of trouble is a user quietly switching the scanner off. Hence
``tests.negative`` being required by the schema itself rather than by convention.

These checks run against **every loaded rule**, bundled or contributed, because a
third-party pack is exactly where an unvetted pattern arrives.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcpscan.anomalies import rule_metas
from mcpscan.document import FieldKind, TextField
from mcpscan.engine import DOCS_BASE_URL, LoadedRule, RuleError, RuleMeta, ScanState
from mcpscan.models import Finding
from mcpscan.ruleloader import load_builtin, load_text
from mcpscan.taint import UnsanitisedSinkRule
from tests.fixtures.descriptions.benign import BENIGN_DESCRIPTIONS
from tests.fixtures.descriptions.benign_unicode import BENIGN_UNICODE
from tests.fixtures.servers import clean_metadata
from tests.test_negative_controls import clean_document

DOCS = Path(__file__).parent.parent / "docs" / "rules"

BUNDLED = load_builtin()
BUNDLED_IDS = [item.rule.meta.id for item in BUNDLED]

#: MCP-003 is code, not YAML, but it still owes a page and a help URL.
TAINT_META = UnsanitisedSinkRule.meta


def ids(items: list[LoadedRule]) -> list[str]:
    return [item.rule.meta.id for item in items]


def check(loaded: LoadedRule, text: str, kind: FieldKind) -> list[Finding]:
    field_ = TextField(pointer="#/tools/0/description", text=text, kind=kind)
    return list(loaded.rule.check_field(field_, ScanState()))


def describe(findings: list[Finding]) -> str:
    return "\n".join(f"    {f.rule_id}/{f.metadata.get('pattern')}: {f.message}" for f in findings)


# --------------------------------------------------------------------------
# the pack loads at all
# --------------------------------------------------------------------------
def test_the_bundled_pack_loads() -> None:
    assert BUNDLED_IDS == ["MCP-001", "MCP-002"]


def test_every_pattern_compiled_at_load_time() -> None:
    """A regex that does not compile must fail the build, not the scan."""
    for loaded in BUNDLED:
        assert loaded.rule.patterns
        for pattern in loaded.rule.patterns:
            assert pattern.compiled is not None


def test_rule_ids_are_unique() -> None:
    assert len(BUNDLED_IDS) == len(set(BUNDLED_IDS))


# --------------------------------------------------------------------------
# every rule carries its own tests -- the gate
# --------------------------------------------------------------------------
@pytest.mark.parametrize("loaded", BUNDLED, ids=BUNDLED_IDS)
def test_every_rule_has_positive_and_negative_cases(loaded: LoadedRule) -> None:
    assert loaded.tests.positive, f"{loaded.rule.meta.id} has no positive cases"
    assert loaded.tests.negative, f"{loaded.rule.meta.id} has no negative cases"


def test_a_rule_without_a_negative_case_is_rejected() -> None:
    """The requirement, stated as a failing load.

    Not a style guideline enforced by review: the schema refuses the file, so a
    rule PR without a negative case cannot merge green.
    """
    yaml = """
    id: ACME-001
    title: Example
    severity: low
    remediation: Do not do that.
    patterns:
      - name: p
        regex: 'foo'
        confidence: low
        message: Found foo.
    tests:
      positive:
        - text: this has foo in it
    """
    with pytest.raises(RuleError, match="negative"):
        load_text(yaml, "<test>")


def test_a_rule_with_an_empty_negative_list_is_rejected() -> None:
    yaml = """
    id: ACME-002
    title: Example
    severity: low
    remediation: Do not do that.
    patterns:
      - name: p
        regex: 'foo'
        confidence: low
        message: Found foo.
    tests:
      positive:
        - text: this has foo in it
      negative: []
    """
    with pytest.raises(RuleError, match="negative"):
        load_text(yaml, "<test>")


@pytest.mark.parametrize("loaded", BUNDLED, ids=BUNDLED_IDS)
def test_positive_cases_fire(loaded: LoadedRule) -> None:
    for case in loaded.tests.positive:
        findings = check(loaded, case.text, case.kind)
        assert findings, (
            f"{loaded.rule.meta.id}: positive case did not fire "
            f"(kind={case.kind.value}): {case.text!r}"
        )
        if case.expect is not None:
            fired = {f.metadata["pattern"] for f in findings}
            assert case.expect in fired, (
                f"{loaded.rule.meta.id}: expected {case.expect!r}, got {sorted(fired)} "
                f"for {case.text!r}"
            )


@pytest.mark.parametrize("loaded", BUNDLED, ids=BUNDLED_IDS)
def test_negative_cases_are_silent(loaded: LoadedRule) -> None:
    for case in loaded.tests.negative:
        findings = check(loaded, case.text, case.kind)
        assert not findings, (
            f"{loaded.rule.meta.id}: negative case fired on {case.text!r} "
            f"(kind={case.kind.value})\n{describe(findings)}"
        )


def test_the_field_kind_on_a_case_is_honoured() -> None:
    """MCP-002's `instructions` exemption is only testable through this.

    The same sentence must fire as a tool description and stay silent as
    `instructions`, and a test harness that ignored the declared kind would
    quietly assert neither.
    """
    mcp002 = next(item for item in BUNDLED if item.rule.meta.id == "MCP-002")
    sentence = "Use read_file before write_file."

    assert not check(mcp002, sentence, FieldKind.INSTRUCTIONS)
    kinds = {case.kind for case in mcp002.tests.negative}
    assert FieldKind.INSTRUCTIONS in kinds, "no case exercises the exemption"


# --------------------------------------------------------------------------
# the shared corpora gate every rule, not just the ones that shipped with them
# --------------------------------------------------------------------------
@pytest.mark.parametrize("loaded", BUNDLED, ids=BUNDLED_IDS)
def test_every_rule_clears_the_benign_description_corpus(loaded: LoadedRule) -> None:
    """A contributed rule is gated by the same corpus the built-ins are.

    This is where a rule that buys recall by spending precision fails, rather
    than degrading the tool quietly in the field.
    """
    for text in BENIGN_DESCRIPTIONS:
        findings = check(loaded, text, FieldKind.TOOL_DESCRIPTION)
        assert not findings, (
            f"{loaded.rule.meta.id} fired on a benign description: {text!r}\n"
            f"{describe(findings)}"
        )


@pytest.mark.parametrize("loaded", BUNDLED, ids=BUNDLED_IDS)
def test_every_rule_clears_the_benign_unicode_corpus(loaded: LoadedRule) -> None:
    for text in BENIGN_UNICODE:
        findings = check(loaded, text, FieldKind.TOOL_DESCRIPTION)
        assert not findings, (
            f"{loaded.rule.meta.id} fired on legitimate Unicode: {text!r}\n"
            f"{describe(findings)}"
        )


@pytest.mark.parametrize("loaded", BUNDLED, ids=BUNDLED_IDS)
def test_every_rule_clears_the_clean_server(loaded: LoadedRule) -> None:
    findings = list(loaded.rule.check(clean_document(), ScanState()))
    assert not findings, (
        f"{loaded.rule.meta.id} fired on server_clean.py metadata\n{describe(findings)}"
    )


def test_the_corpora_are_actually_reaching_the_rules() -> None:
    """Guard against the three checks above passing because nothing ran."""
    assert len(BENIGN_DESCRIPTIONS) >= 40
    assert len(BENIGN_UNICODE) >= 15
    assert clean_metadata.TOOLS


# --------------------------------------------------------------------------
# documentation
# --------------------------------------------------------------------------
def all_rule_metas() -> list[RuleMeta]:
    """Every rule that can appear in a finding: YAML rules, MCP-003, the anomalies."""
    return [item.rule.meta for item in BUNDLED] + [TAINT_META] + rule_metas()


def all_rule_ids() -> set[str]:
    return {meta.id for meta in all_rule_metas()}


def test_every_rule_has_a_documentation_page() -> None:
    """Checked against the file on disk, never against the URL.

    `help_uri` is a github.com link now, and a test that fetched it would be
    asserting that a network is reachable rather than that a page was written.
    The file is the artefact; the URL is where it ends up.
    """
    missing = sorted(
        meta.id for meta in all_rule_metas() if not (DOCS / meta.doc_filename).is_file()
    )
    assert not missing, f"no docs/rules page for: {missing}"


def test_every_documentation_page_has_a_rule() -> None:
    """The other direction, so a renamed rule does not leave an orphan page."""
    pages = {path.stem for path in DOCS.glob("*.md")}
    orphans = sorted(pages - all_rule_ids())
    assert not orphans, f"docs/rules pages with no rule: {orphans}"


@pytest.mark.parametrize("loaded", BUNDLED, ids=BUNDLED_IDS)
def test_every_rule_has_remediation(loaded: LoadedRule) -> None:
    """A rule that cannot say what to do about its finding is not finished."""
    assert len(loaded.rule.meta.remediation) > 30


def test_help_uri_is_an_absolute_url() -> None:
    """A repo-relative path points at nothing for anyone who installed a wheel.

    SARIF's `helpUri` needs a real URI at step 7 regardless, so this is not
    merely cosmetic.
    """
    for meta in all_rule_metas():
        assert meta.help_uri.startswith("https://")
        assert meta.help_uri == f"{DOCS_BASE_URL}/{meta.id}.md"


def test_the_help_url_and_the_checked_file_cannot_drift() -> None:
    """The URL's last segment must be the file the check above looked for.

    Without this the two could diverge silently: the page test would keep passing
    against `docs/rules/MCP-001.md` while every published link pointed elsewhere.
    """
    for meta in all_rule_metas():
        assert meta.help_uri.rsplit("/", 1)[-1] == meta.doc_filename
        assert (DOCS / meta.doc_filename).is_file()


def test_the_docs_base_url_names_this_repository() -> None:
    assert DOCS_BASE_URL == "https://github.com/Kavennesh/mcpscan/blob/main/docs/rules"


def test_anomaly_help_anchors_exist_in_their_pages() -> None:
    """`help_uri` carries a `#kind` anchor; the heading must actually be there."""
    from mcpscan.anomalies import MAPPINGS

    for kind, mapping in MAPPINGS.items():
        page = DOCS / f"{mapping.rule.id}.md"
        anchor = kind.value.replace("_", "-")
        text = page.read_text(encoding="utf-8")
        assert f"## {anchor}" in text, f"{page.name} has no '## {anchor}' section"


# --------------------------------------------------------------------------
# schema validation
# --------------------------------------------------------------------------
def test_unknown_keys_are_rejected() -> None:
    """A typo must fail loudly rather than silently defaulting."""
    yaml = """
    id: ACME-003
    title: Example
    severity: low
    remediation: Do not do that.
    patterns:
      - name: p
        regex: 'foo'
        confidance: low
        message: Found foo.
    tests:
      positive: [{text: foo}]
      negative: [{text: bar}]
    """
    with pytest.raises(RuleError, match="confidance|extra"):
        load_text(yaml, "<test>")


def test_a_third_party_rule_cannot_claim_the_mcp_prefix() -> None:
    """A pack that could shadow MCP-001 could silently weaken it."""
    yaml = """
    id: MCP-999
    title: Impostor
    severity: low
    remediation: Do not do that.
    patterns:
      - name: p
        regex: 'foo'
        confidence: low
        message: Found foo.
    tests:
      positive: [{text: foo}]
      negative: [{text: bar}]
    """
    with pytest.raises(RuleError, match="reserved"):
        load_text(yaml, "<test>", builtin=False)


def test_a_malformed_id_is_rejected() -> None:
    yaml = """
    id: not a rule id
    title: Example
    severity: low
    remediation: Do not do that.
    patterns:
      - name: p
        regex: 'foo'
        confidence: low
        message: Found foo.
    tests:
      positive: [{text: foo}]
      negative: [{text: bar}]
    """
    with pytest.raises(RuleError, match="valid rule id"):
        load_text(yaml, "<test>")


def test_an_uncompilable_regex_is_rejected_at_load() -> None:
    yaml = """
    id: ACME-004
    title: Example
    severity: low
    remediation: Do not do that.
    patterns:
      - name: p
        regex: '(unclosed'
        confidence: low
        message: Broken.
    tests:
      positive: [{text: foo}]
      negative: [{text: bar}]
    """
    with pytest.raises(RuleError, match="does not compile"):
        load_text(yaml, "<test>")


def test_an_unknown_hook_is_rejected() -> None:
    """YAML may reference a hook; it can never define one."""
    yaml = """
    id: ACME-005
    title: Example
    severity: low
    remediation: Do not do that.
    reporter: exec_arbitrary_python
    patterns:
      - name: p
        regex: 'foo'
        confidence: low
        message: Found foo.
    tests:
      positive: [{text: foo}]
      negative: [{text: bar}]
    """
    with pytest.raises(RuleError, match="unknown reporter"):
        load_text(yaml, "<test>")


def test_a_positive_case_naming_an_unknown_pattern_is_rejected() -> None:
    yaml = """
    id: ACME-006
    title: Example
    severity: low
    remediation: Do not do that.
    patterns:
      - name: p
        regex: 'foo'
        confidence: low
        message: Found foo.
    tests:
      positive: [{text: foo, expect: typo}]
      negative: [{text: bar}]
    """
    with pytest.raises(RuleError, match="does not define"):
        load_text(yaml, "<test>")


def test_yaml_cannot_construct_python_objects() -> None:
    """safe_load only: a rule file is data, and data does not get to call things."""
    yaml = "!!python/object/apply:os.system ['echo pwned']\n"
    with pytest.raises(RuleError):
        load_text(yaml, "<test>")
