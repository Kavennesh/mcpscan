# Vendored schemas

## `sarif-schema-2.1.0.json`

The official OASIS JSON Schema for SARIF 2.1.0, used by `tests/test_sarif.py` to
validate everything `mcpscan.sarif` emits.

| | |
| --- | --- |
| Source | <https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json> |
| Canonical `id` | `https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json` |
| Retrieved | 2026-08-17 |
| sha256 | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |
| JSON Schema draft | draft-04 (so `jsonschema.Draft4Validator`, not the default) |

Vendored rather than fetched. A test that downloaded it would be asserting that
a network is reachable rather than that our output is valid -- the same argument
`test_rule_files.py` makes for checking `docs/rules/` on disk instead of
resolving `help_uri`. It also means the gate keeps working in an offline build,
which is the kind of build a security scanner is most likely to run in.

`test_sarif.py::test_the_vendored_schema_is_the_official_one` checks the `id`
above, so a truncated download or a swapped file fails loudly instead of
silently validating against nothing.

To refresh: re-download from the source URL, update the sha256 and the retrieval
date here, and re-run `make check`.
