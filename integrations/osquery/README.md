# osquery integration

12 macOS posture queries that complement MacCrab's real-time detection
with periodic point-in-time snapshots. The pack is platform-specific
(`darwin`) and uses only built-in osquery tables — no extensions
required.

## What's here

- `packs/maccrab.conf` — the osquery pack. 12 queries covering
  listening ports, unsigned launch agents, kexts, startup items,
  DYLD/LD injection, package installs, browser extensions, setuid
  binaries, login items, Bonjour services, non-default routes, and
  quarantined executables.

## Install

### Reference from osquery.conf

```json
{
  "packs": {
    "maccrab": "/path/to/integrations/osquery/packs/maccrab.conf"
  }
}
```

Then restart the daemon:

```sh
sudo launchctl kickstart -k system/io.osquery.agent
```

### Ad-hoc with osqueryi

```sh
osqueryi --pack integrations/osquery/packs/maccrab.conf
```

## Query cadence

Most queries run hourly; `kernel_extensions` daily; `processes_with_env_dyld`
every 10 min (injection is high-signal).

## Pairs with

Each query complements a MacCrab detection:

| osquery snapshot               | MacCrab real-time             |
|--------------------------------|-------------------------------|
| `unsigned_launch_agents`       | `PersistenceGuard`, rule `adhoc_signed_launchagent_write` |
| `processes_with_env_dyld`      | rule `dyld_insert_libraries_env` (needs `MACCRAB_CAPTURE_ENV=1`) |
| `quarantined_executables`      | Gatekeeper / quarantine enrichment |
| `kernel_extensions`            | `RootkitDetector` |
| `browser_extensions_detail`    | `BrowserExtensionMonitor` |
| `setuid_outside_system`        | Privilege escalation rules in `Rules/privilege_escalation/` |

## Future: bidirectional bridge

A follow-up ships an **osquery extension** that exposes MacCrab's own
tables (`maccrab_alerts`, `maccrab_events`, `maccrab_campaigns`) so
analysts can JOIN MacCrab findings with osquery snapshots in one
`osqueryi` session. Tracked in the roadmap as Phase 8.1 producer path.
