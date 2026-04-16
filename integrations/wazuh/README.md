# Wazuh integration

MacCrab alerts flow into Wazuh via a shared NDJSON file that the Wazuh
agent tails. No daemon-to-manager TCP link is required — the OS
filesystem is the transport, which makes this work across strict network
boundaries and air-gapped deployments.

## Pieces

- `decoders/0600-maccrab_decoders.xml` — Wazuh decoder that recognizes
  MacCrab's OCSF-formatted NDJSON.
- `rules/0600-maccrab_rules.xml` — 10 rules mapping MacCrab severities
  and MITRE tactics to Wazuh levels 1–14.
- Your `daemon_config.json` — a FileOutput entry so MacCrab writes the
  NDJSON the agent tails.

## Install

### 1. MacCrab daemon

Add a FileOutput to `daemon_config.json`:

```json
{
  "outputs": [
    {
      "type": "file",
      "path": "/var/log/maccrab/alerts.jsonl",
      "format": "ocsf",
      "maxMb": 100,
      "maxArchives": 10
    }
  ]
}
```

Restart maccrabd. Alerts start appearing as one JSON object per line.

### 2. Wazuh agent

Add a `<localfile>` block to `/var/ossec/etc/ossec.conf` on the macOS
host running the MacCrab daemon:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/maccrab/alerts.jsonl</location>
</localfile>
```

Restart the agent:

```sh
sudo /Library/Ossec/bin/wazuh-control restart
```

### 3. Wazuh manager

Copy the decoder and rules into the manager and restart:

```sh
scp integrations/wazuh/decoders/0600-maccrab_decoders.xml \
    manager:/var/ossec/etc/decoders/

scp integrations/wazuh/rules/0600-maccrab_rules.xml \
    manager:/var/ossec/etc/rules/

ssh manager 'systemctl restart wazuh-manager'
```

## Verify

On the manager:

```sh
sudo /var/ossec/bin/wazuh-logtest -v
```

Paste a sample MacCrab NDJSON line. Expect decoder `maccrab-json` to
fire with a rule id in the 100200 range.

## Rule ID range

`100200–100299` is reserved for MacCrab rules. If your Wazuh install
uses that range already, adjust the `id` attributes in the rules file
before installing.

## What gets indexed

Every alert becomes a Wazuh event with the original OCSF document
preserved under the `data.` prefix — all of `metadata`, `finding`,
`attacks`, `severity`, `suggestedActions`, etc. are searchable in
Kibana / the Wazuh UI.

## Severity mapping

| MacCrab       | Wazuh level |
|---------------|-------------|
| Informational | 1           |
| Low           | 3           |
| Medium        | 7           |
| High          | 10          |
| Critical      | 12          |
| Honeyfile trip| 14          |
| Campaign      | 13          |
