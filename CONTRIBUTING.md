# Contributing to MacCrab

Thank you for your interest in contributing to MacCrab. This guide covers how to submit detection rules and code changes.

---

## Table of Contents

- [Detection Rules](#detection-rules)
- [Code Changes](#code-changes)
- [Code Style](#code-style)
- [Testing](#testing)
- [License Agreement](#license-agreement)

---

## Detection Rules

Rule contributions are one of the most valuable ways to improve MacCrab. New rules expand detection coverage and help the entire community.

### Submitting a Rule

1. **Fork the repository** and create a branch named `rule/<short-description>` (e.g., `rule/detect-osascript-clipboard-access`).

2. **Create the rule file** in the appropriate `Rules/<tactic>/` directory. Use snake_case filenames (e.g., `osascript_clipboard_access.yml`).

3. **Follow the quality checklist** (see below).

4. **Compile and test** the rule to verify it parses correctly:
   ```bash
   python3 Compiler/compile_rules.py --input-dir Rules/ \
       --output-dir /tmp/maccrab_test_rules/
   ```
   Confirm your rule appears in the compiler output with `OK` status.

5. **Open a pull request** with the rule file and a brief description of what the rule detects, why it matters, and how you tested it.

### Rule Quality Checklist

Before submitting, verify that your rule meets all of the following criteria:

- [ ] **Title**: Clear, concise, and descriptive (e.g., "Shell Spawned by Browser Process", not "Bad Process Detection")
- [ ] **ID**: Unique UUID v4 (`python3 -c "import uuid; print(uuid.uuid4())"`)
- [ ] **Status**: Set to `experimental` for new rules (maintainers promote to `stable` per the [Rule Promotion Criteria](#rule-promotion-criteria-experimental--stable) below)
- [ ] **Description**: Explains what is detected and why it is suspicious or malicious
- [ ] **Author**: Your name or handle, or `MacCrab Community` if you prefer anonymity
- [ ] **Date**: Creation date in `YYYY/MM/DD` format
- [ ] **References**: At least one reference URL (MITRE ATT&CK technique page, blog post, or threat report)
- [ ] **Tags**: Includes MITRE ATT&CK tactic tag (e.g., `attack.execution`) and technique tag (e.g., `attack.t1059.004`)
- [ ] **Logsource**: Has `product: macos` and an appropriate `category` (`process_creation`, `file_event`, `network_connection`, `tcc_event`, etc.)
- [ ] **Detection logic**: Uses correct Sigma field names and modifiers; condition string is valid
- [ ] **False positives**: Documents at least one known false positive scenario, or explicitly states "No known false positives" if none are expected
- [ ] **Level**: Appropriate severity (`informational`, `low`, `medium`, `high`, `critical`)
- [ ] **Compiles successfully**: The rule compiler processes the file without errors
- [ ] **No duplicate**: The rule does not duplicate an existing rule's detection logic

### Sequence Rule Additional Criteria

For temporal sequence rules (`type: sequence`), also verify:

- [ ] **Window**: Time window is reasonable for the attack chain (not too short to miss, not too long to generate noise)
- [ ] **Correlation**: Process correlation type is appropriate (`process.lineage`, `process.same`, `file.path`, `network.endpoint`, or `none`)
- [ ] **Steps**: Each step has a unique `id`, valid logsource, and working detection logic
- [ ] **Trigger**: Trigger condition correctly references step IDs
- [ ] **Ordered**: The `ordered` flag accurately reflects whether step order matters

### Rule Promotion Criteria (experimental → stable)

New rules land as `status: experimental` and ship **disabled by default** — since v1.21.4 the daemon defaults to the `stable` rule profile. Maintainers promote a rule to `stable` when it meets **all** of the following bar. The bar is deliberately quantitative so promotion is checkable rather than a judgment call; run `scripts/check-promotion.sh <rule-id>` to evaluate a rule against it (advisory — it reads the local benchmark and telemetry data described below).

1. **False-positive soak.** The rule has run enabled on the reference machine for **at least 14 days** (28 recommended — the default window of `scripts/fp-rate-benchmark.sh`) at **≤ 0.5 alerts/day** in that benchmark's per-rule output. Rationale: the machine-wide release gate is < 30 HIGH/CRITICAL alerts/day (`scripts/measure-fp-baseline.sh`), and ~480 rules share that budget — a single rule sustaining more than ~0.5/day on a benign machine is an outsized noise contributor. A rule absent from the benchmark JSON emitted zero *alerts* in the window. Since v1.21.6 that alone no longer passes the criterion: the benchmark reads `alerts.db`, which is **post-NoiseFilter**, so zero alerts is consistent with three very different states. `check-promotion.sh` disambiguates them against `rule_telemetry.json` (pre-filter counters): zero alerts **and** zero telemetry `fireCount` passes (genuinely quiet); zero alerts with `fireCount > 0` **fails** (every match was suppressed downstream, so the rule's false-positive rate was never actually measured); and no telemetry entry at all **fails** (the rule was never evaluated — a dark logsource with no live collector, or it simply was not enabled for the window). Enable the rule for the whole soak, e.g. under `rule_profile: "all"`.

2. **Demonstrated true positive.** The rule has a working trigger: a fixture in `scripts/detection-test.sh` (or `scripts/campaign-test.sh`), or a rule test under `Tests/` that feeds a synthetic event through the engine and asserts the rule fires. "It should match" is not evidence; a red-team fixture or unit test is.

3. **Eval latency within budget.** The rule is not flagged by the engine's > 50 ms eval-budget guard: it does not appear in `rule_telemetry.json`'s `autoDisabledRuleIds`, and its sampled p95 execution time is under 50 ms. A rule the daemon has logged as `Slow rule:` or runtime-auto-disabled cannot be promoted until the predicate is fixed.

4. **Quality checklist still holds.** The checklist above (filters, documented false-positive scenarios, references, correct field names) is re-verified at promotion time, not just at submission.

Sequence rules (`Rules/sequences/`) and graph rules (`Rules/graph/`) follow the **same bar** for criteria 1, 2, and 4 — since v1.21.5 they are profile-gated exactly like single-event rules (experimental sequence/graph rules do not run under the default profile). Criterion 3 is the exception: the `> 50 ms` eval-budget guard, `rule_telemetry.json`, and runtime auto-disable are single-event-engine machinery only, so `scripts/check-promotion.sh` reports eval-latency **UNKNOWN** (overall **INCOMPLETE**) for sequence/graph rules. Assess their evaluation cost by other means — a sequence's specificity comes from its multi-step structure, and the 7 graph rules are curated by hand — until per-rule exec-time profiling is wired into `SequenceEngine`/`GraphRuleEvaluator`.

---

## Code Changes

### Setup

```bash
git clone https://github.com/peterhanily/maccrab.git
cd maccrab
swift build
swift test
```

### Submitting Code

1. **Fork the repository** and create a branch named `feature/<short-description>` or `fix/<short-description>`.

2. **Make your changes** in small, focused commits. Each commit should represent a single logical change.

3. **Add or update tests** for any new or modified functionality.

4. **Run the test suite** to confirm nothing is broken:
   ```bash
   swift test
   ```

5. **Open a pull request** with a description of what changed and why. Reference any related issues.

### What We Look For in Code PRs

- **Correctness**: Does the code do what it claims? Are edge cases handled?
- **Concurrency safety**: MacCrab uses Swift's structured concurrency model. New types that hold mutable state should be `actor`s or use `Sendable`-conforming value types. Avoid locks and dispatch queues in new code.
- **Performance**: The detection pipeline processes thousands of events per second. Avoid unnecessary allocations, string copies, and blocking I/O in the hot path.
- **API design**: Public APIs should be minimal, well-named, and documented with doc comments.
- **Test coverage**: New detection logic and enrichment features should have unit tests.

---

## Code Style

MacCrab follows standard Swift conventions with a few project-specific guidelines:

### General

- Use Swift's structured concurrency (`async/await`, `actor`, `AsyncStream`) for all concurrent code
- Prefer value types (`struct`, `enum`) over reference types (`class`) unless reference semantics are required
- Use `Sendable` conformance for all types that cross concurrency boundaries
- Mark classes that must be `Sendable` but cannot be verified by the compiler as `@unchecked Sendable` with a comment explaining why
- Use `os.log` (`Logger`) for all logging in library code -- never `print()`
- No force unwraps (`!`) in library code

### Naming

- Types: `UpperCamelCase` (e.g., `RuleEngine`, `ProcessLineage`)
- Functions and properties: `lowerCamelCase` (e.g., `evaluateRule`, `ruleCount`)
- Constants: `lowerCamelCase` (e.g., `maxAncestorDepth`)
- Enum cases: `lowerCamelCase` (e.g., `processCreation`, `allOf`)
- File names match the primary type they contain (e.g., `RuleEngine.swift`)

### Organization

- Use `// MARK: -` sections to organize code within files
- Group related functionality: Properties, Initialization, Public API, Private Implementation
- Keep files focused on a single type or closely related types
- Place extensions in the same file as the type they extend, unless the extension is large enough to warrant its own file

### Documentation

- All `public` types, methods, and properties must have doc comments (`///`)
- Use code examples in doc comments for non-obvious APIs
- Document preconditions, postconditions, and thrown errors

### Error Handling

- Define domain-specific error types as `enum` conforming to `Error`
- Prefer throwing errors over returning optionals for operations that can fail in meaningful ways
- Conform error types to `CustomStringConvertible` or `LocalizedError` for user-facing messages

---

## Testing

### Running Tests

```bash
# Run all tests
swift test

# Run a specific test suite
swift test --filter MacCrabCoreTests.RuleEngineTests

# Run a specific test function. These are Swift Testing tests, so function
# names have NO `test` prefix — this one is `func containsModifier()`.
swift test --filter MacCrabCoreTests.RuleEngineTests/containsModifier
```

`--filter` is a regex over test IDs and **exits 0 when it matches nothing**, so
a typo'd filter looks like a clean green run. Check the reported executed-test
count before believing a filtered run passed.

### Test Expectations

- **Rule engine tests**: Every new predicate modifier or condition type needs unit tests with positive and negative cases
- **Collector tests**: Mock the underlying system API (ES framework, SQLite, etc.) and verify event normalization
- **Enrichment tests**: Test with synthetic process trees and verify ancestry chain reconstruction
- **Sequence engine tests**: Test with ordered event sequences, out-of-order sequences, expired windows, and partial matches
- **Integration tests**: End-to-end tests that feed synthetic events through the full pipeline and verify alert output

### Test Data

Place test fixtures (sample rules, event JSON, etc.) in `Tests/MacCrabCoreTests/Fixtures/`. Do not use real system events or paths that contain usernames or sensitive information.

---

## License Agreement

By contributing to MacCrab, you agree that:

- **Code contributions** (anything outside the `Rules/` directory) are licensed under the [Apache License 2.0](LICENSE)
- **Detection rule contributions** (anything inside the `Rules/` directory) are licensed under the [Detection Rule License 1.1 (DRL 1.1)](https://github.com/SigmaHQ/Detection-Rule-License)

You represent that you have the right to license your contributions under these terms and that your contributions do not infringe on any third-party rights.

---

## Questions?

If you are unsure whether a rule or code change would be welcome, open an issue to discuss it before investing time in a pull request. We are happy to provide guidance on rule writing, detection strategy, and codebase architecture.
