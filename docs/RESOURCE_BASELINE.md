# Reference resource measurements

[`RELEASE_RESOURCE_BASELINE.json`](RELEASE_RESOURCE_BASELINE.json) is the public
resource policy for the accepted published-v1.21.5 reference. It contains only
published image identities, fixed workload and statistic definitions, the three
measured summaries and limits, and commitments to the private accepted evidence.
It contains no machine fingerprint, installed path, process ID, capture time,
raw sample, workload transcript or operator identity.

The limits remain 9 MiB/s average engine writes, 164 MiB/s maximum sampled write
window, and 19% background GUI p95 CPU (percent of one core). The engineering
allowance is 25% above each measured reference statistic, rounded upward to whole
MiB/s or CPU percentage points. It was selected before the candidate comparison.
One epoch cannot estimate run-to-run variation or a false-failure probability.
The complete raw samples, including the workload-bracketing write spike, and the
written acceptance decision remain private and unchanged.

A build preflight can validate the committed public policy without access to
private host data. Installed recording and final release verification additionally
require the exact private evidence and recompute its measurements. A public
policy alone cannot qualify a host or candidate.

## Capture

For a new baseline, provision the published v1.21.5 app and system extension on
the chosen qualification Mac. An isolated reference profile permits using the
same Mac while preserving its operational profile separately; restore that
profile before candidate qualification. Older software must never open stores
created by a newer format. Keep the GUI running in the background and allow the
engine at least 250 seconds of uptime. Enable the loopback OTLP receiver used by
the fixed workload. Use the same machine, macOS build, power source and workload
for candidate qualification. The recorder checks native running identities
against the independently verified published images and architecture CDHashes.

Create a private output directory and run the recorder from the source checkout
with the actual running engine PID and a fresh output filename:

```sh
sudo install -d -m 700 /private/tmp/maccrab-reference-private
sudo /usr/bin/python3 -I scripts/candidate-qualification.py record-resource-baseline \
  --source-root "$PWD" --engine-pid ENGINE_PID \
  --output /private/tmp/maccrab-reference-private/capture.json
sudo chmod 600 /private/tmp/maccrab-reference-private/capture.json
```

The recorder measures native process counters without depending on v1.22
heartbeat fields. It captures 31 observations at 30-second offsets across a
900-second epoch and runs the fixed 3,000-iteration workload at minute five.
Workload completion is timed independently of sampling. The private receipt
retains raw samples, running process identities, signing checks, host details,
complete workload output and both workload executor hashes. It refuses a changed
process, candidate image, failed workload or changed executor bytes.

The result is **measured-awaiting-acceptance**, with no approved limits. Capture
does not install software, choose budgets or authorize a release.

## Review, publish the policy and retain private proof

Review the capture and choose all three limits with a written rationale:

| JSON limit | Statistic and unit |
|---|---|
| `engine_average_write_bytes_per_second` | Cumulative native disk-write delta divided by actual captured epoch seconds. |
| `engine_max_window_write_bytes_per_second` | Maximum write rate across each captured interval and every sample-aligned span of at most 60 seconds. |
| `gui_p95_percent` | Nearest-rank p95 of the 31 background GUI `ps pcpu` snapshots, in percent of one core. |

The window statistic is not a continuous sliding-window measurement. GUI
snapshots are `ps pcpu`, not instantaneous interval CPU deltas. The baseline and
candidate use these same definitions.

Preserve the raw capture. In a separate private accepted receipt, set `status`
to `accepted`, supply the three positive finite `limits`, and record the reviewer,
acceptance timestamp and rationale. Never commit that host-rich receipt. Publish
only the strictly allowlisted policy schema, its measured summaries and limits,
and SHA-256 commitments to the exact accepted bytes and canonical JSON content.
Include that policy in source before building the next candidate. Budget choices
must be justified independently of that candidate's results.

For installed qualification, place the exact accepted receipt at
`.qualification-evidence/resource-baseline/<private_evidence.sha256>.json`, where
the filename digest comes from the committed public policy. This dedicated
subdirectory must have mode 0700 and the receipt mode 0600. Both must belong to
the invoking user; root may additionally use evidence owned by the source
checkout owner. The surrounding `.qualification-evidence` directory may retain
its existing permissions. Symlinks, hardlinks, changed bytes, a wrong canonical
commitment, a different host or inconsistent public summaries are refused.

The validator binds the public policy to the candidate's exact source commit,
then applies the complete original capture checks to the private receipt:
reference identity, endpoint timing, native uptime, workload output, sample
cadence, raw-statistic recomputation and same-host configuration. The historical
recorder compatibility proof pins the public policy, private evidence commitment,
archive and unchanged resource dependency closure. Missing private evidence is
an incomplete release qualification, never an implicit pass.

The recorder is resource evidence only. Its successful workload does not prove
event persistence or detection fidelity. Candidate qualification still requires
separate liveness, conservation, search, containment and detection checks.

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
