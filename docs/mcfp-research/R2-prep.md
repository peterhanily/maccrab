# MCFP R2 Prep

**Status:** prep underway. Execution requires Mac #2; operator runs separately.

Plan §6.4 R2 — cross-Mac stability validation. The first MCFP shipping artifact is conditional on R2 passing:

- **R2 pass criteria:** at least three of available components show ≥95% same-binary stability across Macs AND ≥80% different-family separation within a family.
- **Imposter test:** unsigned binary at the same path as a known-good system process (in sandbox) produces divergence in cs + ent components.

If R2 passes → ship `com.maccrab.fingerprinter.mcfp` + `com.maccrab.enricher.process-fingerprint` (currently deferred per plan §7 v1.15).

If R2 fails → failure write-up; posture Analyzer continues to ship without the `posture.fingerprint_drift` finding.

## Prep tooling

Built in `Sources/MacCrabForensics/MCFPResearch/`:

| File | Purpose |
|---|---|
| `CorpusCollector.swift` | Walks a directory tree, fingerprints each Mach-O via MCFPStatic. Output: one JSONL row per binary with `(path, sha256_of_file, mcfp1_canonical, arch_token, lc, cs, ent)`. |
| `CorpusDiff.swift` | Compares two corpus files; computes per-component stability percentages for binaries present in both. |
| `ImposterHarness.swift` | Builds an unsigned binary at a known path; fingerprints it; reports divergence vs the known-good fingerprint. |

CLI integration (when wired):

```bash
# Mac A:
maccrabctl mcfp corpus collect --target /Applications \
  --output ~/maccrab-research/corpus-mac-a.jsonl

# Mac B (separate hardware):
maccrabctl mcfp corpus collect --target /Applications \
  --output ~/maccrab-research/corpus-mac-b.jsonl

# Either Mac:
maccrabctl mcfp corpus diff \
  corpus-mac-a.jsonl corpus-mac-b.jsonl

# Imposter:
maccrabctl mcfp imposter --target /usr/bin/true
```

## Execution recipe (operator runs)

1. Apple-signed targets: `/Applications`, `/System/Applications`, `/usr/bin`, `/usr/libexec`. Expect ~500-2000 binaries per Mac.
2. Developer-ID targets: `/Applications/<third-party.app>` set. Expect same-team binaries across both Macs.
3. Run collector on each Mac with identical target list.
4. Transfer both corpus files to one Mac for diff.
5. Diff output reports per-component % stability + flags binaries that diverged.
6. Imposter harness produces expected-divergence report.

## Pass/fail recording

Final answer lives in this file's "Outcome" section (TBD — populated after Mac #2 runs).

```
## Outcome (DRAFT — replace with measured data)

Date measured: <YYYY-MM-DD>
Mac A: <hardware + macOS version>
Mac B: <hardware + macOS version>

Corpus size: <N binaries>
Same-binary cs stability:  <%>
Same-binary lc stability:  <%>
Same-binary ent stability: <%>
Same-binary arch stability: <%>

Different-family cs separation:  <%>
Different-family ent separation: <%>

Imposter cs divergence: <%>
Imposter ent divergence: <%>

R2 verdict: PASS | FAIL
```

If PASS: queue the conditional MCFP plugin + paired enricher for a future ship.
If FAIL: write the failure analysis; posture Analyzer continues without `posture.fingerprint_drift`.
