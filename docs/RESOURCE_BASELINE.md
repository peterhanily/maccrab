# Reference resource measurements

[`RELEASE_RESOURCE_BASELINE.json`](RELEASE_RESOURCE_BASELINE.json) contains the
accepted published-v1.21.5 reference measured on September 14, 2026: 31 samples
over 900 seconds on the qualification Mac. The three limits are 9 MiB/s average
engine writes, 164 MiB/s maximum sampled write window, and 19% background GUI p95
CPU (percent of one core).

The engineering allowance is 25% above each measured reference statistic,
rounded upward to whole MiB/s or CPU percentage points. It was selected before
measurements of the next candidate. One reference epoch cannot estimate
run-to-run variation or a false-failure probability. The document retains the
raw samples, including the workload-bracketing write spike, and the written
acceptance rationale. These limits govern the resource comparison; full
installed qualification remains separately required.

The committed record is an explicitly labelled publication derivative. It uses
`reference-user` and `/REFERENCE_SOURCE` in three account/path fields; these are
aliases, not the command or source path captured on the reference host. Its
`publication_redaction` metadata identifies the exact fields and pins the
unchanged private capture, accepted record and acceptance decision by SHA-256.
Measurements, workload output, executor hashes, acceptance and limits are
unchanged. Both records pass the same production baseline validator.

## Capture

For a new baseline, provision the published v1.21.5 app and system extension on
the chosen qualification Mac. An isolated reference profile permits using the
same Mac while preserving its operational profile separately; restore that
profile before candidate qualification. Older software must never open stores
created by a newer format. Keep the GUI running in the background and allow the
engine at least 250 seconds of uptime. Enable the loopback OTLP receiver used by
the fixed workload. Use this same machine, macOS build, power source and workload
when subsequently qualifying the candidate. The recorder checks the running
images against independently verified published executable hashes and
architecture-specific CodeDirectory hashes.

From the source checkout, run the resource recorder with the actual running
engine PID and a fresh output path:

```sh
sudo /usr/bin/python3 -I scripts/candidate-qualification.py record-resource-baseline \
  --source-root "$PWD" --engine-pid ENGINE_PID --output /private/tmp/maccrab-reference.json
```

The command measures native process counters without depending on v1.22
heartbeat fields. It captures 31 observations at 30-second offsets across a
900-second epoch and runs the fixed 3,000-iteration workload at minute five.
Workload completion is timed independently of sampling. The recorder retains
raw samples, running process identities, signing checks, host details, complete
workload output, and hashes of both workload executors. It refuses a candidate
engine, a changed process, a failed workload, or changed executor bytes.

The result is **measured-awaiting-acceptance**, with no approved limits. Capture
does not install software, choose budgets, or authorize a release.

## Review and freeze

Review the capture and choose all three limits with a written product rationale:

| JSON limit | Statistic and unit |
|---|---|
| `engine_average_write_bytes_per_second` | Cumulative native disk-write delta divided by actual captured epoch seconds. |
| `engine_max_window_write_bytes_per_second` | Maximum write rate across each captured interval and every sample-aligned span of at most 60 seconds. |
| `gui_p95_percent` | Nearest-rank p95 of the 31 background GUI `ps pcpu` snapshots, in percent of one core. |

The window statistic is not a continuous sliding-window measurement. GUI
snapshots are the `ps pcpu` statistic, not instantaneous interval CPU deltas.
The baseline and candidate enforce these same definitions.

Preserve the raw evidence. Set `status` to `accepted`, supply the three positive
finite values in `limits`, and record `acceptance.reviewer`,
`acceptance.accepted_at` (an ISO-8601 timestamp), and `acceptance.rationale`.
Copy the reviewed document to `docs/RELEASE_RESOURCE_BASELINE.json` and include
it in the source commit **before building the next candidate**. Budget choices
must be justified independently of that candidate's results; no automatic
after-the-fact margin is applied. The live validator recomputes measurements,
checks the capture protocol and reference identities, and requires the receipt
bytes to exist in the candidate's own source commit. An untracked or later
receipt cannot qualify an already-built candidate.

The recorder is resource evidence only. Its successful fixed workload does not
prove the last release's event persistence or detection fidelity. Candidate
qualification still requires the separate liveness, conservation, search,
containment, and detection checks.

## Published reference provenance

The reference is [the published v1.21.5 release](https://github.com/peterhanily/maccrab/releases/tag/v1.21.5),
GitHub asset `489442361`, published on 2026-07-25:
`MacCrab-v1.21.5.dmg`, 94,026,166 bytes, SHA-256
`9eb6f49389af910e9d1bad14b26d2510aebd2ed2e874bbd2f464f36b664c529b`.
Independent download and strict/deep signature inspection on 2026-09-12 verified
both universal images as v1.21.5, build 1.21.5.1018, Developer ID Peter Hanily,
team `79S425CW99`. The verifier pins their executable and architecture CDHashes.
The `release.json` committed in the v1.21.5 tag predates publication and has a
different DMG checksum; it is not the published-asset pin.
