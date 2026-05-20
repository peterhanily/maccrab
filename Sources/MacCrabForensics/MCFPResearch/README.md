# MacCrabForensics/MCFPResearch

Research-grade. Plan §6.4 R2 prep.

MCFP R2 = cross-Mac stability + uniqueness + imposter experiment. This directory holds the tooling to RUN the experiment; the experiment itself requires a second physical Mac that the chat-agent can't supply directly.

## Files

- `CorpusCollector.swift` — walks a directory tree, fingerprints every Mach-O via MCFPStatic, writes one JSON line per binary.
- `CorpusDiff.swift` — compares two corpus files, computes per-component stability percentages.
- `ImposterHarness.swift` — builds an unsigned binary at the same path as a known-good system process (in a sandbox dir); fingerprints both; expects divergence in cs + ent components.

## What's expected of the operator

1. Run `maccrabctl mcfp corpus collect` on Mac A → `corpus-A.jsonl`.
2. Run the same on Mac B → `corpus-B.jsonl`.
3. Run `maccrabctl mcfp corpus diff corpus-A.jsonl corpus-B.jsonl` → per-component stability report.
4. Run `maccrabctl mcfp imposter` → expected divergence report.
5. Compare against plan §6.4 R2 ship criteria (≥95% same-binary stability, ≥80% different-family separation).

Pass / fail decision → `docs/mcfp-research/R2.md` outcome section.
