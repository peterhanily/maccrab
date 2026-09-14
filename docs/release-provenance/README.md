# Historical resource measurement provenance

`resource-baseline-recorder-v1.py.txt` is the complete recorder used for the accepted v1.21.5 reference measurement. It is retained as data and is never imported or executed. Its SHA-256 is `6871807f08e6477db7525c4f78ae522d3b4296095e2a5560b6a500792ed7f33d`; the accepted public baseline remains byte-identical at SHA-256 `bac5749cb83ca5eab33a8e86338dbae93c0b801fb8661aa05583f20f863aab49`.

When the current recorder differs, `scripts/resource-baseline-provenance.py` permits this one baseline only after checking the exact archive, document and workload executors. It compares the byte-identical transitive source dependencies of resource capture and validation, including native process identity, sampling, statistics, shared helpers, constants, class definitions and decorators. Imports, CLI dispatch and original top-level ordering remain fixed. New import-time side effects, interpreter namespace changes and effectful defaults are refused.

The only normalization replaces the exact new compatibility-check call with the exact historical recorder-hash refusal. Unrelated runtime-drain function bodies and inert declarations may change; reference measurement behavior may not. A changed measurement dependency requires new reference evidence or a separately reviewed protocol change. The helper is bound by the release-critical executor inventory, and its controls run in clean CI.

This proof preserves historical measurement provenance. It does not qualify a newer installed candidate or turn the failed GA3 runtime capture into a pass.
