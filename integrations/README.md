# MacCrab Integrations

Drop-in configuration for the SIEMs and posture-audit tools that
complement MacCrab's real-time detection.

| Integration | Transport | Install effort | README |
|-------------|-----------|----------------|--------|
| [Wazuh](wazuh/)     | File-tail (agent reads NDJSON)  | 3 files, 10 min | [wazuh/README.md](wazuh/README.md) |
| [Elastic](elastic/) | HTTP Bulk API                   | Template + saved objects | [elastic/README.md](elastic/README.md) |
| [osquery](osquery/) | Pack reference                  | 1 config entry  | [osquery/README.md](osquery/README.md) |

## Which to pick

- **Wazuh** — best fit when a Wazuh manager already runs in your org.
  Zero new network config; MacCrab writes NDJSON, the agent tails it.
- **Elastic** — best fit for SOC teams that query their own stack.
  Direct Bulk API; index template ensures correct field types; starter
  Kibana dashboard importable.
- **osquery** — complementary, not a transport. Use alongside either
  SIEM to get periodic posture snapshots (listening ports, unsigned
  LaunchAgents, DYLD-injected processes) that cross-reference MacCrab
  alerts.

All integrations respect MacCrab's opt-in posture — nothing leaves the
host until you add the appropriate `outputs:` entry to
`daemon_config.json`.

## OCSF 1.3 as the wire format

MacCrab emits [OCSF 1.3 Security Findings](https://schema.ocsf.io/1.3.0/classes/security_finding)
by default. Every integration here expects that format. If a downstream
tool requires a different schema (ECS, CEF, etc.) it's one line to
switch in `daemon_config.json` — see the root `CLAUDE.md` for the full
format list.

## Roadmap — deferred in v2.0

- **osquery producer extension**: expose `maccrab_alerts`,
  `maccrab_events`, `maccrab_campaigns` as queryable virtual tables so
  analysts can JOIN MacCrab findings with osquery snapshots inline.
- **Wazuh API push (`WazuhOutput`)**: direct POST to Wazuh Manager
  `/events` instead of file-tail. Needed for agent-less hosts.
- **SentinelOne, CrowdStrike bridges**: the existing
  `SecurityToolIntegrations` can read their logs; outbound streaming
  is a separate phase.
