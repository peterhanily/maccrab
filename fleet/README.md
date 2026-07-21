# MacCrab Fleet Collector

**Status: self-hosted prototype. NOT production.**

A small FastAPI server that receives alert/IOC telemetry pushed by MacCrab
endpoints, for a single operator who wants multi-Mac visibility in one place.

## Security model (read before deploying)

- **One shared bearer key** (`MACCRAB_FLEET_KEY`) for every endpoint. There
  is no per-device identity or attestation — any keyholder can claim any
  `hostId` (hostIds are self-reported pseudonyms).
- **No tenant isolation, no RBAC.** Every authenticated caller sees all data.
- **Trusted network only.** Treat the key as shared among all machines; a
  single compromised endpoint can pollute or read the whole dataset.

## Deployment

- Binds `127.0.0.1` by default (`--host` to override — an explicit choice).
- For anything non-local, put TLS in front via a reverse proxy (nginx/Caddy).
  MacCrab endpoints refuse `MACCRAB_FLEET_URL` over plaintext `http://`
  unless the host is loopback.

## Data flow: OUTBOUND-ONLY

Endpoints **push** sanitized alert summaries and IOC sightings. As of
MacCrab v1.21.5, **nothing this server returns is consumed by endpoints** —
the aggregation endpoints (`/api/iocs`, `/api/incidents`,
`/api/fleet-campaigns`, `/api/dashboard`) exist for operator visibility
only. Fleet data never flows back into endpoint detection state.
