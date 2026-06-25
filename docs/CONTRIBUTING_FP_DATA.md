# Contributing False-Positive Data to MacCrab

MacCrab relies on real-world false-positive baselines to be credible as a security tool. Today, we publish rule coverage (83+ stable rules, 400+ experimental), but FP rates remain unmeasured at scale — only a reference-machine number exists. This document explains why that matters, what data we collect, how to participate, and how results are published.

## 1. Why We Need FP Data

A detection rule is only useful if its false-positive rate is known and acceptable. A rule that fires thousands of times per day on clean machines is noise, regardless of its true-positive accuracy. MacCrab's detection library includes **483 rules** (90 marked stable, the rest experimental), but production FP rates are blank:

- **Reference machine FP rate:** We measure this in CI on a clean macOS VM using `scripts/false-positive-test.sh`, validating against a curated list of 100+ Apple system processes. This gives us a *lower bound* under artificial conditions.
- **Real-world FP rate:** Unknown. A developer machine with build tools (esbuild, node, Chrome, Xcode) produces different alert volumes than a non-developer endpoint. A machine running AI tools produces different patterns still. We need data from diverse real machines to publish per-rule FP baselines.

Publishing "false-positive rate: unknown" damages adoption. You can't recommend a rule to a SOC if you don't know how often it fires on a clean machine. Our goal: gather enough data to publish **per-rule FP rates** (e.g., "maccrab.persistence.launch-agent: 0.2 alerts/day on reference hardware" or "maccrab.ai-guard.credential-access: 1.8 alerts/day on active developer machine").

## 2. What Data Is Collected and What Is NOT

MacCrab's FP benchmark harness runs in **detection-only mode**, a privacy-preserving configuration where:

### Data Collected (aggregated)

- **Rule ID** (`maccrab.process-creation.reverse-shell`, etc.) and count of alerts per rule
- **Timestamp** (to bucketing into hour/day/week windows for rate calculations)
- **Coarse machine metadata only:**
  - macOS version (e.g., `14.6` / `15.1`)
  - Architecture (`arm64`, `x86_64`)
  - Hardware model (`MacBookPro18,1` – identifies hardware family, not a specific machine)
  - Optional: self-reported endpoint category (`developer`, `non-developer`, `ci`, `research` — volunteer chooses)

### Data NOT Collected

- **Event contents:** No process names, paths, arguments, environment variables, or network details are transmitted
- **Hostnames or computer names:** Not collected
- **User names or UIDs**
- **Full process lineage or causal graph data**
- **File paths or file hashes**
- **Network traffic or DNS queries**

In short: **only per-rule alert counts + coarse host metadata.** The harness runs entirely on your machine; all aggregation happens locally before export.

### Detection-Only Benchmark Mode (Planned)

The FP benchmark harness (`scripts/fp-rate-benchmark.sh` / `make benchmark-fp`, planned for this release) runs MacCrab with **detection-only mode** enabled, a daemon configuration that:
- Compiles and evaluates all rules against your event stream
- Records rule firings in per-rule counters
- Discards raw events immediately after evaluation
- Exports only aggregated counts (per-rule alerts, hour-by-hour, no event details)

This is technically distinct from the daemon's normal operation, which stores full event + alert detail for investigation. Detection-only mode is designed specifically for safe FP data contribution.

## 3. How to Participate

### Minimal Setup (< 1 hour)

1. **Install or build MacCrab** (if not already running):
   ```bash
   # Option A: Homebrew
   brew install --cask peterhanily/maccrab/maccrab
   
   # Option B: Source build
   git clone https://github.com/peterhanily/maccrab && cd maccrab && make dev
   ```

2. **Start the FP benchmark harness** (forthcoming in this release):
   ```bash
   make benchmark-fp
   ```
   or
   ```bash
   ./scripts/fp-rate-benchmark.sh
   ```
   
   The harness will:
   - Stop your running daemon
   - Start a fresh daemon in detection-only mode
   - Begin recording per-rule alert counts
   - Print setup confirmation with expected duration

3. **Use your machine normally** for 4–8 weeks (longer is better):
   - Run your typical workload (development, browsing, messaging, AI tools, etc.)
   - Do NOT artificially trigger suspicious activity (that contaminates baselines)
   - The daemon runs in the background, detecting nothing about what you do

4. **Export results** (when you're ready to submit):
   ```bash
   maccrabctl benchmark export > maccrab_fp_data.json
   ```
   
   This produces a JSON file containing:
   ```json
   {
     "harness_version": "1.20.0",
     "submitted_at": "2026-06-26T14:32:00Z",
     "collection_duration_hours": 1008,
     "machine_metadata": {
       "os_version": "15.1",
       "architecture": "arm64",
       "hardware_model": "MacBookPro18,1",
       "endpoint_category": "developer"  // optional
     },
     "per_rule_counts": {
       "maccrab.persistence.launch-agent": 2,
       "maccrab.process-creation.reverse-shell": 0,
       "maccrab.ai-guard.credential-access": 18,
       ...
     }
   }
   ```

5. **Submit via GitHub issue:**
   - Open a new issue at https://github.com/peterhanily/maccrab/issues
   - Use the **"False-Positive Data Submission"** template (auto-provided)
   - Attach your `maccrab_fp_data.json` file
   - Optionally: describe your machine (type of work, tools, ambient noise you expect)

### Questions?

- See [docs/BENCHMARK.md](docs/BENCHMARK.md) for detailed harness usage, data interpretation, and troubleshooting
- Post a [GitHub Discussion](https://github.com/peterhanily/maccrab/discussions) if the harness fails or you have privacy questions

---

## 4. Privacy Terms

### During Collection

- **Your machine, your data.** Detection-only mode runs entirely locally. Nothing leaves your machine until you explicitly export and submit.
- **No network requests.** The FP harness does not phone home, check for updates, or contact threat intel feeds (even if you have them enabled in your main daemon config).
- **No profiling.** MacCrab does not record *what* you were doing, *which* processes were involved, or *which* files were accessed — only how many alerts each rule generated.
- **Stop anytime.** Kill the benchmark with `make stop` or `pkill maccrabd`. The harness does not persist state outside of the local SQLite database.

### After Submission

- **Published data is anonymized.** When we aggregate submissions into public FP baselines, submissions are:
  - Grouped by hardware model + OS version + endpoint category (e.g., "MacBookPro18,1 + Sonoma 14.6 + developer")
  - Median-aggregated per rule (to eliminate outliers)
  - Published as a table in [docs/FP_BASELINES_v1.md](docs/FP_BASELINES_v1.md) (file naming: one per release)
  - Example row: `maccrab.persistence.launch-agent | 0.1–0.4 alerts/day | Sonoma 14.6 arm64 (N=42 submissions) | stable`
- **Individual submissions are not published.** Raw submissions are archived privately and are not made public.
- **You can opt out.** Before submission, you can review the JSON and delete the entire file. Submissions are voluntary.
- **Aggregate data is permanent.** Published FP baseline tables are versioned and are part of the release history (immutable — typos are corrected in a subsequent release, not the published number).

### Your Privacy Rights

- **Contributor names are not recorded** — submissions are anonymous by default. If you want your name or organization listed as a contributor, add a comment in the issue saying so.
- **No reidentification.** We commit to not attempting to reidentify contributors from the hardware model + OS + category tuple.
- **Data deletion.** Request deletion of your submission by opening an issue marked [data-deletion-request](https://github.com/peterhanily/maccrab/issues?q=label%3Adata-deletion-request) — we will not publish aggregates based on that data going forward.

---

## 5. How Aggregated Results Get Published

### Collection Phase

Submissions accumulate in [GitHub Issues](https://github.com/peterhanily/maccrab/issues) with the `fp-data-submission` label.

### Aggregation (per release)

After each major release (or once we have N=50+ submissions), the maintainer:

1. Downloads all anonymized JSON payloads
2. Groups by: `(hardware_model, os_version, endpoint_category)`
3. For each group, computes per-rule **median alert count** over the collection window (to reduce outlier noise)
4. Normalizes to **alerts/day** (e.g., 18 alerts over 1008 hours = 0.43 alerts/day)
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
A: No. Alert counts are persisted hourly to a local SQLite table. You can stop and resume the harness (e.g., `make stop`, then later `make benchmark-fp` again). The counter continues from where it left off.

**Q: I run specialized tools (security scanners, CI/CD, fuzzing). Will that contaminate my baseline?**
A: Yes — specialized tools will inflate your FP rate. But that's honest data. A developer using fuzzing tools *should* see higher alert rates than one who doesn't. When you submit, note your workload in the issue comment. When we aggregate, we group by self-reported category (developer vs. non-developer, CI, research, etc.), so specialized users naturally cluster together.

**Q: Can I run the benchmark on multiple machines and submit combined data?**
A: No. Submit one JSON per machine (one per GitHub issue). The hardware_model + OS metadata lets us group identical machines. Merging data from different machines makes grouping impossible.

**Q: What if the harness crashes or the daemon dies mid-benchmark?**
A: The harness includes a watchdog. If the daemon crashes, the watchdog restarts it automatically and logs the event. You'll see a note in the export JSON (`crash_restarts: 3`). Submit it anyway — crash frequency is useful data too.

**Q: Does the benchmark harness require Full Disk Access?**
A: Yes, same as the main daemon. The harness stops the running daemon and starts a new one, so if your main daemon had FDA, the benchmark will use it. If not, detection coverage will be lower (some rules require FDA to see their triggering events).

**Q: What if I have a personal suppressions.json?**
A: The benchmark harness preserves your suppressions and uses them. If you've suppressed noisy rules because your workflow legitimately triggers them, the harness respects those suppressions. That's correct — your baseline should reflect your actual environment.

**Q: Can I submit partial data (e.g., only data for a week)?**
A: Yes. The harness exports however many hours of collection have accumulated. A 1-week submission is useful and welcome.

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

The exported JSON schema (human-readable, not Zod/TypeScript yet):

```json
{
  "harness_version": "string (semver)",
  "schema_version": 1,
  "submitted_at": "ISO8601 timestamp",
  "collection_start_time": "ISO8601 timestamp",
  "collection_end_time": "ISO8601 timestamp",
  "collection_duration_hours": "number",
  "machine_metadata": {
    "os_version": "string (e.g., '15.1')",
    "os_build": "string (e.g., '25C5062g')",
    "architecture": "string (arm64 | x86_64 | ppc64le)",
    "hardware_model": "string (e.g., 'MacBookPro18,1')",
    "hardware_cores": "integer",
    "endpoint_category": "string? (developer | non-developer | ci | research | custom)"
  },
  "harness_config": {
    "detection_only_mode_enabled": "boolean",
    "threat_intel_enabled": "boolean",
    "baseline_anomaly_enabled": "boolean"
  },
  "operational_notes": {
    "crashes": "integer (daemon restarts due to crash)",
    "manual_interrupts": "integer (user-initiated stops)",
    "warnings": ["string array of anomalies detected"]
  },
  "per_rule_counts": {
    "rule_id_1": "integer (total alerts)",
    "rule_id_2": "integer",
    ...
  },
  "per_hour_timeline": [
    {
      "hour_start": "ISO8601",
      "rule_id_1": "integer",
      "rule_id_2": "integer",
      ...
    },
    ...
  ]
}
```

---

**Document version:** 1.0 (MacCrab v1.20.0)  
**Last updated:** 2026-06-26  
**Maintainer:** github.com/peterhanily
