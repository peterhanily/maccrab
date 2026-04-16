# Elasticsearch + Kibana integration

MacCrab alerts stream into Elastic via the Bulk API using the
`StreamOutput` kind `elastic_bulk`. The index template here gives each
OCSF field a correct type; the Kibana saved-objects bundle gives you a
starter index pattern and dashboard to build from.

## Pieces

- `index-template.json` — field mappings for `maccrab-alerts*` indices.
- `kibana-objects.ndjson` — minimal Kibana saved objects (index pattern
  + starter dashboard). Intentionally small — extend via Kibana and
  re-export.

## Install

### 1. MacCrab daemon

Add a StreamOutput to `daemon_config.json`:

```json
{
  "outputs": [
    {
      "type": "elastic_bulk",
      "url": "https://es.example.com/_bulk",
      "tokenEnv": "ES_AUTH_HEADER",
      "indexName": "maccrab-alerts",
      "retryCount": 2,
      "timeoutSeconds": 10
    }
  ]
}
```

`ES_AUTH_HEADER` should be the full `Authorization` header value, e.g.
`"ApiKey <base64>"` or `"Basic <base64>"`. Keep it in an env var, not
the config file.

### 2. Index template

Apply the mapping before the first document lands:

```sh
curl -H "Authorization: $ES_AUTH_HEADER" \
     -H 'Content-Type: application/json' \
     -X PUT 'https://es.example.com/_index_template/maccrab-alerts' \
     -d @integrations/elastic/index-template.json
```

### 3. Kibana objects

Import via the Kibana UI: **Stack Management → Saved Objects → Import
→ choose `kibana-objects.ndjson`**.

Or via API:

```sh
curl -H "kbn-xsrf: true" \
     -H "Authorization: $ES_AUTH_HEADER" \
     -X POST 'https://kibana.example.com/api/saved_objects/_import?overwrite=true' \
     --form file=@integrations/elastic/kibana-objects.ndjson
```

You should see the **MacCrab — Severity Overview** dashboard in Kibana.

## Notes

- MacCrab writes OCSF 1.3 Security Findings. Elastic Security's built-in
  OCSF support recognizes them natively — no ECS transformation is
  required.
- Time field: `time` is epoch millis. The index pattern is configured
  for this.
- The starter dashboard is intentionally minimal (just a filter on
  `class_uid:2004`). Build visualizations on top — severity breakdown,
  MITRE heatmap, top offenders by `actor.process.name` — and export
  back to NDJSON to share with your team.

## Alternate: Elastic Agent ingest

If you prefer the Elastic Agent path over direct Bulk posts, point
MacCrab's FileOutput at a path the agent's `log` integration watches.
No changes needed on the MacCrab side; follow Elastic's custom
integration docs for the log layout.
