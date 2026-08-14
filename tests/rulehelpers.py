"""Reaching a bundled rule by id, for tests that predate the YAML engine.

Step 4's rule suites were written against `InvisibleUnicodeRule()` and
`ModelDirectedInstructionRule()` as classes. Those classes are gone -- both rules
are now YAML loaded through the same path a contributed rule takes -- but the
assertions they made are the migration's own regression test and must survive
unchanged in substance. This is the one-line adapter that lets them.
"""

from __future__ import annotations

from functools import lru_cache

from mcpscan.engine import PatternRule
from mcpscan.ruleloader import load_builtin


@lru_cache(maxsize=1)
def _bundled() -> dict[str, PatternRule]:
    return {loaded.rule.meta.id: loaded.rule for loaded in load_builtin()}


def rule(rule_id: str) -> PatternRule:
    """The bundled rule with this id, or a failure naming what is available."""
    rules = _bundled()
    if rule_id not in rules:
        raise AssertionError(f"no bundled rule {rule_id!r}; have {sorted(rules)}")
    return rules[rule_id]
