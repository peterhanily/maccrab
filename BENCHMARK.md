# Detection Benchmarking

MacCrab's README is honest that detection quality is **documented coverage, not an
executed benchmark**, and that most rules are still experimental. This document is
how we close that gap with real numbers — specifically the **false-positive rate**,
which is the single most important quality signal for a local detector you run on
your own machine.

> **Status:** the harness (`make benchmark-fp` / `scripts/fp-rate-benchmark.sh`)
> ships now. Aggregated multi-machine baselines (`docs/FP_BASELINES_*.md`) are
> published as volunteer data comes in — see
> [docs/CONTRIBUTING_FP_DATA.md](docs/CONTRIBUTING_FP_DATA.md).

## What we measure

- **False positive (FP):** an alert raised on a machine doing only benign work
  (no malicious activity).
- **Per-rule FP rate:** `alerts(rule) / measurement-days`, i.e. how often a given
  rule fires per day on a normal machine. Stratified by severity.

We do **not** claim a true-positive / detection-efficacy benchmark here — that
needs a labeled attack corpus and is tracked separately. FP rate is what an
operator feels day to day, and it is measurable with volunteer machines now.

## Method

1. **Detection-only.** Run MacCrab normally, but do **not** arm any response
   actions (the default — kill/quarantine/block are opt-in and confirmation-gated,
   so a stock install is already detection-only). The point is to measure what
   *fires*, with zero risk to the host.
2. **Window.** Use the machine for your ordinary work for a measurement window
   (4 weeks is a good default — long enough to capture weekly cadences like
   backups, OS updates, CI runs).
3. **Sample.** Run `make benchmark-fp` (or `scripts/fp-rate-benchmark.sh --days 28`).
   It reads the alert store and computes per-rule alerts/day.
4. **Stratify.** Record macOS version + CPU arch (coarse metadata) so rates can be
   compared across machine classes. The harness emits a privacy-safe JSON
   (`rule_id` + `count` + `per_day` only — never event contents, paths, or
   hostnames).

```bash
make benchmark-fp                       # last 28 days, JSON in ./
scripts/fp-rate-benchmark.sh --days 14  # custom window
```

## Interpreting the numbers

Rough targets for a "trustworthy on a dev workstation" rule (these are goals, not
guarantees — they're what we tune toward):

| Severity | Target FP rate |
|----------|----------------|
| critical / high | **< ~1 / month** per rule |
| medium | < ~5 / month per rule |
| low / informational | < ~10 / month per rule |

A rule that exceeds its target on multiple independent benign machines is a tuning
bug, not a detection — it gets recalibrated (lower severity, a must-fire/allow
gate, or a tighter predicate). The v1.19.x false-positive work (down-weighting
routine developer-tooling activity) came directly from this kind of measurement.

## Release gate

Before a GA, a maintainer collects this baseline on ≥3 benign machines and compares
per-rule rates to the prior release; any rule that regresses materially without a
root-cause explanation blocks the release or is documented in the changelog. See
[RELEASE_PROCESS.md](RELEASE_PROCESS.md).
