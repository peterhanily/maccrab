# MacCrab 1.3.4 — Fix: network-convergence flood from unresolved IPs

A noisy field host was generating hundreds of
`maccrab.correlator.network-convergence` alerts per hour. Every alert
description read `N unrelated processes contacted :443 over Ns` — no
IP, just the port. Diagnosis: network events that arrived before DNS
/ flow enrichment completed carried an empty `destinationIp`, which
the correlator keyed under `":443"`, collapsing every HTTPS flow on
the host into a single artifact bucket. `syspolicyd`, Chrome Helper,
`WeatherWidget`, `mDNSResponder`, and Keynote all got lumped together
as "convergence" simply because they opened HTTPS before the IP
resolved.

## Fixed

- **Empty destination IP now ignored at ingress.**
  `CrossProcessCorrelator.shouldIgnoreNetworkDestination` rejects
  empty, whitespace-only, `0.0.0.0`, `::`, and anything without a
  `.` or `:`. This is the fix that actually stops the flood — no
  cloud-prefix list could match an absent IP.

- **Expanded `trustedCloudDomains` from 15 → 49 suffixes.** Google's
  full browser/update/media stack (`gvt1.com`, `googleusercontent.com`,
  `youtube.com`, `doubleclick.net`, `googlevideo.com`, …) plus
  Microsoft, Mozilla, Apple CDN, and Slack/Discord/Zoom. Helps the
  domain-keyed path when DNS *is* attached.

- **New trusted-helpers gate.** `allEventsAreTrustedHelpers` reuses
  `NoiseFilter.trustedBrowserPrefixes` so cross-bundle fan-out
  (Chrome Helper + Slack Helper + Code Helper all to one destination)
  is suppressed. The existing bundle-identity filter couldn't see
  across bundles; this one can.

## Tests

Four new regressions in `CrossProcessCorrelatorTests` —
`emptyDestinationIPIgnored`, `chromeFamilyFanOutSuppressed`,
`unrelatedProcessesStillConverge`, `googleUpdateDomainSuppressed`.
All 7 correlator tests pass.

## Install

```bash
brew install --cask peterhanily/maccrab/maccrab
```

Or download `MacCrab-v1.3.4.dmg` below, open, drag to `/Applications`,
and click **Enable Protection** on the Overview tab.

## Upgrading from 1.3.x

No migration needed. Sysext re-activates automatically on first
launch; your SQLite DB, rules, and suppressions carry over.
