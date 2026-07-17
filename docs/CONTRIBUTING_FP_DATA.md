# Contributing False-Positive Data to MacCrab

MacCrab relies on real-world false-positive baselines to be credible as a security tool. Today, we publish rule coverage (486 rules — ~87 enabled by default under the stable profile, the rest experimental), but FP rates remain unmeasured at scale — only a reference-machine number exists. This document explains why that matters, what data we collect, how to participate, and how results are published.

## 1. Why We Need FP Data

A detection rule is only useful if its false-positive rate is known and acceptable. A rule that fires thousands of times per day on clean machines is noise, regardless of its true-positive accuracy. MacCrab's detection library includes **486 rules** (~87 enabled by default under the stable profile, the rest experimental), but production FP rates are blank:

- **Reference machine FP rate:** We measure this in CI on a clean macOS VM using `scripts/false-positive-test.sh`, validating against a curated list of 100+ Apple system processes. This gives us a *lower bound* under artificial conditions.
- **Real-world FP rate:** Unknown. A developer machine with build tools (esbuild, node, Chrome, Xcode) produces different alert volumes than a non-developer endpoint. A machine running AI tools produces different patterns still. We need data from diverse real machines to publish per-rule FP baselines.

Publishing "false-positive rate: unknown" damages adoption. You can't recommend a rule to a SOC if you don't know how often it fires on a clean machine. Our goal: gather enough data to publish **per-rule FP rates** (e.g., "maccrab.persistence.launch-agent: 0.2 alerts/day on reference hardware" or "maccrab.ai-guard.credential-access: 1.8 alerts/day on active developer machine").

## 2. What Data Is Collected and What Is NOT

You run MacCrab normally in a **detection-only** posture (do not arm any response actions — a stock install is already detection-only), and the harness then reads your local alert store and aggregates it. What it collects:

### Data Collected (aggregated)

- **Rule ID** (`maccrab.process-creation.reverse-shell`, etc.), the **count** of alerts per rule over the window, and the derived **alerts/day** (`per_day`)
- **Window length** (in days) and the **total alert count** over that window
- **Coarse machine metadata only:**
  - macOS version (e.g., `14.6` / `15.1`)
  - CPU architecture (`arm64`, `x86_64`)

You may also self-report an endpoint category (`developer`, `non-developer`, `ci`, `research`) in your submission text — that is a note you add to the GitHub issue, not a field the harness emits.

### Data NOT Collected

- **Event contents:** No process names, paths, arguments, environment variables, or network details are transmitted
- **Hostnames or computer names:** Not collected
- **User names or UIDs**
- **Full process lineage or causal graph data**
- **File paths or file hashes**
- **Network traffic or DNS queries**

In short: **only per-rule alert counts + coarse host metadata.** The harness runs entirely on your machine; all aggregation happens locally before export.

### How the Harness Works

The FP benchmark harness (`scripts/fp-rate-benchmark.sh`, run via `make benchmark-fp`) is a small read-only script that:
- Reads your local alert store (`alerts.db`) over a measurement window (default: the last 28 days)
- Groups alerts by rule ID and computes per-rule counts and alerts/day
- Writes a privacy-safe JSON summary (rule IDs + counts + coarse host metadata only — never event contents, paths, or hostnames)

It does **not** stop or restart the daemon, install any special mode, or read raw events — it simply aggregates the alerts MacCrab already recorded during normal detection-only operation. "Detection-only" here just means you don't arm any response actions during the measurement window; a stock install is already detection-only (see [BENCHMARK.md](../BENCHMARK.md)).

## 3. How to Participate

### Minimal Setup

1. **Install or build MacCrab and run it normally** in a detection-only posture (do not arm any response actions — a stock install is already detection-only):
   ```bash
   # Option A: Homebrew
   brew install --cask peterhanily/maccrab/maccrab
   
   # Option B: Source build
   git clone https://github.com/peterhanily/maccrab && cd maccrab && make dev
   ```

2. **Use your machine normally** for a measurement window (2–8 weeks; longer is better):
   - Run your typical workload (development, browsing, messaging, AI tools, etc.)
   - Do NOT artificially trigger suspicious activity (that contaminates baselines)
   - MacCrab records alerts to its local store as it normally would; nothing is exported yet

3. **Run the benchmark harness** when you're ready to submit:
   ```bash
   make benchmark-fp
   ```
   or, to control the window and output path:
   ```bash
   ./scripts/fp-rate-benchmark.sh --days 28 --output maccrab_fp_data.json
   ```
   
   The harness reads your local `alerts.db`, prints a per-rule alerts/day table, and writes a privacy-safe JSON summary (rule IDs + counts + coarse host metadata only). It does not stop or restart the daemon.

   The JSON looks like:
   ```json
   {
     "schema": "maccrab.fp_benchmark.v1",
     "window_days": 28,
     "total_alerts": 41,
     "machine": { "macos": "15.1", "arch": "arm64" },
     "rules": [
       { "rule_id": "maccrab.ai-guard.credential-access", "count": 18, "per_day": 0.643 },
       { "rule_id": "maccrab.persistence.launch-agent", "count": 2, "per_day": 0.071 }
     ]
   }
   ```

4. **Review and submit via GitHub issue:**
   - Open a new issue at https://github.com/peterhanily/maccrab/issues
   - Attach your generated JSON file
   - Optionally: describe your machine (type of work, tools, ambient noise you expect) and a self-reported category (`developer` / `non-developer` / `ci` / `research`)

### Questions?

- See [BENCHMARK.md](../BENCHMARK.md) for detailed harness usage, data interpretation, and troubleshooting
- Post a [GitHub Discussion](https://github.com/peterhanily/maccrab/discussions) if the harness fails or you have privacy questions

---

## 4. Privacy Terms

### During Collection

- **Your machine, your data.** The harness runs entirely locally, reading only your existing alert store. Nothing leaves your machine until you explicitly submit the generated JSON.
- **No network requests.** The FP harness does not phone home, check for updates, or contact threat intel feeds (even if you have them enabled in your main daemon config).
- **No profiling.** The summary does not record *what* you were doing, *which* processes were involved, or *which* files were accessed — only how many alerts each rule generated.
- **Stop anytime.** The harness is a short-lived, read-only script; simply don't run it, or delete the generated JSON before submitting. It writes nothing back to MacCrab's databases.

### After Submission

- **Published data is anonymized.** When we aggregate submissions into public FP baselines, submissions are:
  - Grouped by OS version + architecture + self-reported category (e.g., "Sequoia 15.1 + arm64 + developer")
  - Median-aggregated per rule (to eliminate outliers)
  - Published as a table in [docs/FP_BASELINES_v1.md](docs/FP_BASELINES_v1.md) (file naming: one per release)
  - Example row: `maccrab.persistence.launch-agent | 0.1–0.4 alerts/day | Sonoma 14.6 arm64 (N=42 submissions) | stable`
- **Individual submissions are not published.** Raw submissions are archived privately and are not made public.
- **You can opt out.** Before submission, you can review the JSON and delete the entire file. Submissions are voluntary.
- **Aggregate data is permanent.** Published FP baseline tables are versioned and are part of the release history (immutable — typos are corrected in a subsequent release, not the published number).

### Your Privacy Rights

- **Contributor names are not recorded** — submissions are anonymous by default. If you want your name or organization listed as a contributor, add a comment in the issue saying so.
- **No reidentification.** We commit to not attempting to reidentify contributors from the OS version + architecture + category tuple.
- **Data deletion.** Request deletion of your submission by opening an issue marked [data-deletion-request](https://github.com/peterhanily/maccrab/issues?q=label%3Adata-deletion-request) — we will not publish aggregates based on that data going forward.

---

## 5. How Aggregated Results Get Published

### Collection Phase

Submissions accumulate in [GitHub Issues](https://github.com/peterhanily/maccrab/issues) with the `fp-data-submission` label.

### Aggregation (per release)

After each major release (or once we have N=50+ submissions), the maintainer:

1. Downloads all anonymized JSON payloads
2. Groups by: `(macos, arch, self-reported category)`
3. For each group, computes per-rule **median alert count** over the collection window (to reduce outlier noise)
4. Normalizes to **alerts/day** (e.g., 18 alerts over a 28-day window = 0.64 alerts/day)
5. Publishes a table in [docs/FP_BASELINES_v1.20.md](docs/FP_BASELINES_v1.20.md) (example; versioned per release)

### Published Format

A sample baseline table:

| Rule | Median Rate (alerts/day) | Stable/Experimental | Hardware | OS | Notes |
|------|-------------------------|---------------------|----------|----|----|
| `maccrab.persistence.launch-agent` | 0.0–0.1 | Stable | MacBook + iMac (arm64/x86) | Sonoma–Sequoia | Few FPs on non-dev machines; slightly higher on developer boxes with frequent tool updates. |
| `maccrab.ai-guard.credential-access` | 0.5–2.0 | Stable | All | Sonoma+ | Rate depends heavily on AI tool activity (Claude Code, Cursor, etc.). Non-developers: 0.1–0.3/day. |
| `maccrab.defense-evasion.quarantine-bypass` | 0.0 | Experimental | All | All | No submissions triggered this yet — rule is too conservative or noise floor is genuinely zero. |

**Interpretation notes** published alongside:
- Which endpoint categories had the most data (e.g., "42 developer submissions, 12 non-developer, 3 CI")
- Per-category breakdowns for rules with high category-to-category variance
- Caveats (e.g., "baseline built on macOS 14.6–15.1; older/newer OS versions may differ")
- Link to submission data: which GitHub issues contributed to this release's baseline

### Feedback Loop

Once a rule's FP rate is published:
- If it's too high (>10 alerts/day on clean machines), the rule is marked experimental and scheduled for tuning
- Tune-ups happen in the next development cycle; re-testing on the same machines verifies the delta
- The revised baseline is published in the next release

---

## 6. FAQ

**Q: How long should I run the harness?**
A: Longer is always better. We recommend at least 2 weeks (minimum: one full week of patterns). Four weeks covers enough variance in your routine to be representative. Eight weeks is excellent.

**Q: Can I interrupt the benchmark? Will I lose data?**
A: There is nothing to interrupt. The harness reads accumulated alerts from `alerts.db` after the fact, so you run it once, whenever you're ready to submit. Your alert history is simply whatever MacCrab recorded during normal operation.

**Q: I run specialized tools (security scanners, CI/CD, fuzzing). Will that contaminate my baseline?**
A: Yes — specialized tools will inflate your FP rate. But that's honest data. A developer using fuzzing tools *should* see higher alert rates than one who doesn't. When you submit, note your workload in the issue comment. When we aggregate, we group by self-reported category (developer vs. non-developer, CI, research, etc.), so specialized users naturally cluster together.

**Q: Can I run the benchmark on multiple machines and submit combined data?**
A: No. Submit one JSON per machine (one per GitHub issue). The macOS version + architecture (plus your self-reported category) lets us group comparable machines. Merging data from different machines makes grouping impossible.

**Q: What if MacCrab's daemon was down for part of my measurement window?**
A: The harness is a read-only script that runs after the fact, so there is no long-running benchmark to crash. If the daemon was down for a stretch, those hours simply weren't observed — note it in your submission if you know about it. Partial coverage is still useful data.

**Q: Does the benchmark harness require Full Disk Access?**
A: The harness itself only needs read access to `alerts.db`. FDA matters for MacCrab's *normal* detection during your measurement window: some rules require FDA to see their triggering events, so if MacCrab didn't have FDA, those rules can't have fired and won't appear in your baseline.

**Q: What if I have a personal suppressions.json?**
A: The benchmark reads whatever alerts MacCrab actually recorded, which already reflect your suppressions. If you suppressed noisy rules because your workflow legitimately triggers them, those alerts weren't stored, so they won't appear. That's correct — your baseline should reflect your actual environment.

**Q: Can I submit partial data (e.g., only data for a week)?**
A: Yes. Pass a shorter window (`--days 7`) or just run the harness whenever you like. A 1-week submission is useful and welcome.

**Q: Who has access to submitted data?**
A: Raw JSON submissions are archived privately by the maintainer and are not shared publicly. Only anonymized aggregates appear in published baselines.

**Q: Does the benchmark harness send telemetry to MacCrab?**
A: No. There is no phone-home mechanism and no backend. The harness is fully offline. The only network access is optional threat-intel feeds (if you enabled them in your daemon config), and you control those in settings.

---

## 7. Credits and Contact

Thank you for helping make MacCrab safer for everyone.

- **Questions?** Post in [GitHub Discussions](https://github.com/peterhanily/maccrab/discussions/categories/false-positive-data)
- **Issues?** Open a [GitHub Issue](https://github.com/peterhanily/maccrab/issues) with the `fp-data` label
- **Contact:** maccrab@peterhanily.com

---

## Appendix: Data Schema

The exact JSON the harness emits (`scripts/fp-rate-benchmark.sh`):

```json
{
  "schema": "maccrab.fp_benchmark.v1",
  "window_days": "integer (measurement window, in days)",
  "total_alerts": "integer (all alerts in the window)",
  "machine": {
    "macos": "string (e.g., '15.1')",
    "arch": "string (arm64 | x86_64)"
  },
  "rules": [
    {
      "rule_id": "string (e.g., 'maccrab.persistence.launch-agent')",
      "count": "integer (alerts for this rule in the window)",
      "per_day": "number (count / window_days)"
    }
  ]
}
```

That is the complete schema — rule IDs, counts, and coarse host metadata only. No timestamps, event contents, paths, hostnames, hardware model, or per-hour timeline are collected. Any self-reported endpoint category is text you add to the GitHub issue, not a field in this file.

---

**Document version:** 1.1 (MacCrab v1.21.4)  
**Last updated:** 2026-07-17  
**Maintainer:** github.com/peterhanily
