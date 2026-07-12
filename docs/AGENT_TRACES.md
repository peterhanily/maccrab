# Agent Traces

> Connects AI coding-agent activity to real macOS events. When Claude Code,
> Codex, or another agent runs a command, MacCrab correlates the local tool
> span, process lineage, and Endpoint Security event so an alert can
> answer: which agent action caused this? All correlation happens
> on-device. Prompt and tool content remain redacted unless you explicitly
> enable local capture.

Status: **stable** as of v1.9.0. Default-off (operator opts in via the
**Receive agent traces** toggle in **Intelligence → Agent Traces**, or via
the `MACCRAB_AGENT_TRACES=1 + MACCRAB_OTLP_RECEIVER=1` env pair for
headless deployments).

## What it does

MacCrab can ingest the OpenTelemetry traces that AI coding agents emit
about themselves (Claude Code, OpenAI Codex, others) and join them to the
kernel events MacCrab already observes. Two correlation paths run in
parallel:

1. **TRACEPARENT (high-confidence).** When an agent runs a Bash subprocess
   it injects a `TRACEPARENT` env var into the child's environment.
   MacCrab's Endpoint Security collector reads that env at `execve` time,
   parses the W3C trace context, and binds it to the process. Every
   subsequent kernel event from that process (and its descendants) carries
   the originating `trace_id` / `span_id`.

2. **Process lineage (medium-confidence).** When no TRACEPARENT is
   present (Cursor, Copilot CLI, an unconfigured Claude Code), MacCrab
   walks the process ancestry and tags events whose ancestor binary
   matches a known AI tool.

A third path (OTLP receiver → TraceStore) lets MacCrab ingest the agent's
self-reported tool spans on `127.0.0.1:4318`. With both halves wired,
every alert can answer:

> "This `rm -rf /var/data` came from prompt P at T₀, processed by tool
> span `claude_code.tool.execution` at T₀+260ms. Trace id = `…`."

## Trust framing

The agent's OTel self-report is **advisory**. The kernel events are
**authoritative**. Trace correlation gives you a hypothesis about intent
that MacCrab verifies against the ground truth ES delivers. If a
compromised agent lies in its spans — claims a `Read` while shelling out
— the kernel events still expose the shell. The trace is for attribution
and UX, never for trust.

## Tamper-evidence (what "tamper-evident" means here)

Two distinct records, two distinct guarantees — stated plainly so the
word "tamper-evident" isn't doing unearned work:

- **The OTel span store (`traces.db`).** Append-only, and AES-GCM
  authenticated at rest (see **Privacy → Storage contract**): a modified
  ciphertext fails the GCM tag check and surfaces a warning instead of
  decrypting to garbage. That is at-rest integrity, not a portable proof.

- **The exportable causal record (`.maccrabtrace` / `tracegraph.db`).**
  This is the "signed, replayable record" a reviewer can verify offline.
  Each materialized trace extends an **append-only continuity hash
  chain** in `tracegraph.db` (a mutated / deleted / reordered / inserted
  ledger row is detected by `verifyHashChain()`), and each exported
  bundle carries a **daemon-signed Merkle root** over its contents. An
  independent **unified-log witness** (subsystem
  `com.maccrab.tracegraph.chain`) records each signed chain head.

**Honest scope.** Tamper-**evident**, not tamper-proof:
forgery-resistant against a *non-root* attacker and verifiable by a party
holding an out-of-band pinned key (`--expect-key` / fleet pin / TOFU);
**local root is out of scope** (root can rewrite and re-sign — see
[`THREAT_MODEL.md`](THREAT_MODEL.md)); tail-truncation of the newest
ledger entries is bounded by the log witness, not the chain alone; and
the witness's cross-process/cross-run read-back is **pending on-device
verification**. Full detail: [`maccrabtrace.v1.spec.md` §6.4](maccrabtrace.v1.spec.md).

## Privacy

- **Env block: never persisted.** MacCrab scans the env block delivered
  with `ES_EVENT_TYPE_NOTIFY_EXEC` for `TRACEPARENT` (and notes the
  presence of `TRACESTATE`); the env block itself is never persisted,
  logged, or sent to LLMs. Bounded scan: ≤256 vars, ≤16 KB, whichever
  first. The parsed `TRACEPARENT` value is a 32-hex trace ID + 16-hex
  span ID with no semantic content.
- **TRACESTATE: not stored in v1.9.** Presence is recorded as a boolean
  flag; the value is opaque vendor routing context and intentionally out
  of scope.
- **OTLP receiver: loopback-only, opt-in.** When enabled it binds to
  `127.0.0.1:4318` with `requiredInterfaceType = .loopback`; every
  accepted connection's peer endpoint is verified to be loopback before
  any read.
- **Attribute sanitiser.** Span attributes pass through
  `OTLPAttributeSanitizer` before persistence. Attribute keys signalling
  secrets (`*api_key*`, `*token*`, `*secret*`, `*password*`,
  `*credential*`, `*_key`, `*_token`) have their values blanked.
  Attribute values matching vendor key shapes (`sk-ant-...`, `sk-...`,
  `AKIA...`, `AIza...`, `ghp_...`, Slack `xox[abprs]-...`, Bearer tokens)
  are redacted regardless of attribute key. Private IPv4/IPv6/Mac
  ComputerName patterns are also redacted.
- **Prompt text: opt-in only.** Claude Code redacts prompt text from its
  spans by default; setting `OTEL_LOG_USER_PROMPTS=1` enables it on
  the agent side, plus a separate MacCrab Settings toggle (PR-4) gates
  storage in `traces.db`.
- **Storage contract.** `traces.db` lives next to `events.db` with the
  same 0640 root:admin permissions. **Span attributes are sanitised
  for known secret shapes, then AES-GCM-encrypted at rest** under the
  same shared key as `events.db` / `alerts.db` (the v1.8.1
  `DatabaseEncryption` path). Tamper detection is built in: a
  modified ciphertext fails the GCM authentication tag check and
  surfaces a logged warning instead of decrypting to garbage. Legacy
  plaintext rows from earlier installs continue to read unchanged
  (the decrypt path is a passthrough when the `ENC2:` prefix is
  absent).

## Enabling

v1.9.0 ships the receiver, store machinery, and the in-dashboard
toggle. **Settings → Intelligence → Agent Traces** has a switch that
starts/stops the receiver on the running daemon via SIGHUP — no env
vars or restart required. The env-var path below is kept for CI / dev
hosts where the dashboard isn't running:

```bash
# Daemon side — set in the daemon's environment.
export MACCRAB_AGENT_TRACES=1     # turn on env-block scan + lineage tagging
export MACCRAB_OTLP_RECEIVER=1    # (PR-4 wiring; reserved env var)

# Operator's shell, for Claude Code:
export CLAUDE_CODE_ENABLE_TELEMETRY=1
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
# Optional: also enable detailed user-prompt tracing
# export ENABLE_BETA_TRACING_DETAILED=1
# export OTEL_LOG_USER_PROMPTS=1
```

The smoke-test script `scripts/test-otlp-claude-code.sh` automates the
"start the daemon, wait, then count spans" loop.

## Verifying

```bash
# After running Claude Code with the env above, count spans:
sudo sqlite3 "/Library/Application Support/MacCrab/traces.db" \
    "SELECT COUNT(*), MIN(start_ns), MAX(start_ns) FROM spans"

# Inspect recent spans:
sudo sqlite3 "/Library/Application Support/MacCrab/traces.db" \
    "SELECT span_name, agent_tool, service_name FROM spans ORDER BY start_ns DESC LIMIT 10"
```

Events that received a TRACEPARENT correlation carry the indexed columns
`agent_trace_id`, `agent_span_id`, `agent_tool`,
`machine_agent_confidence` (`traceparent` or `lineage`), and the full
`AttributionEvidence` JSON in `agent_evidence_json`.

## Architecture references

- `Sources/MacCrabCore/AIGuard/TraceExtractor.swift` — bounded env scan +
  W3C v00 parser
- `Sources/MacCrabCore/AIGuard/TraceRegistry.swift` — pid → trace-context
  actor with anti-pid-recycle identity (`audit_token.pidversion`)
- `Sources/MacCrabCore/Detection/TraceCorrelator.swift` — direct +
  lineage attribution producing `AttributionEvidence`
- `Sources/MacCrabCore/Network/OTLPReceiver.swift` — loopback-only OTLP
  receiver, decode-and-persist
- `Sources/MacCrabCore/Network/OTLPAttributeSanitizer.swift` — secret
  redaction at the wire boundary
- `Sources/MacCrabCore/Storage/TraceStore.swift` — append-only span store
  in `traces.db` (separate file from `events.db`)
- `vendor/opentelemetry-proto/` — pinned upstream proto definitions
- `scripts/regenerate-otlp-proto.sh` — regen helper (PR-3b ships a
  hand-rolled wire-format reader; the script generates SwiftProtobuf
  types when protoc is installed)
- `scripts/test-otlp-claude-code.sh` — manual integration smoke test

## Audit invariants

- **Pass 12** (`scripts/pre-release-audit.sh`): `traces.db` has exactly
  one long-lived opener.
- **Pass 13** (`scripts/pre-release-audit.sh`): only the
  `TraceExtractor`/`ESHelpers` pathway calls `es_exec_env` /
  `es_exec_env_count`. Adding another caller requires an explicit
  allowlist entry plus a code review.
- **Pass 14** (`scripts/pre-release-audit.sh`): every Sigma field
  referenced by YAML rules in `Rules/` (currently `agent_trace_id`,
  `agent_span_id`, `agent_tool`, `machine_agent_confidence`) has at
  least one Swift producer. Catches rule-fields-without-enricher
  drift before release.

## Detection rules shipped

Three confidence-aware rules in `Rules/ai_safety/` consume the
`MachineAgentConfidence` enrichment field. Status is `stable` as of v1.9.0.

| Rule | Severity | Confidence gate | What it catches |
|---|---|---|---|
| `agent_filesystem_violation_high_conf` | high | `traceparent` | Agent (TRACEPARENT-bound) creates a file under `/Library/LaunchDaemons/`, `/Library/LaunchAgents/`, or `~/.ssh/`. |
| `agent_filesystem_violation_probable` | medium | `lineage` | Same paths, attribution from process lineage only — kept lower-severity because lineage can mis-attribute. |
| `agent_traceparent_credential_access` | high | `traceparent` | Agent reads SSH/AWS/cloud SDK credentials or browser-extension wallet directories. |

Compiler passthrough additions in `Compiler/compile_rules.py`:
`AgentTraceId`, `AgentSpanId`, `AgentTool`, `MachineAgentConfidence`.
Rule authors can match these by Sigma name; the compiler emits the
underscore form (`agent_trace_id`, etc.) that `RuleEngine` reads from
`Event.enrichments`.

## Limitations

- Span data from agents that do not propagate `TRACEPARENT` falls back
  to lineage attribution (`machine_agent_confidence: lineage`) — a less
  specific signal that does not drive high-severity rules without
  corroboration (the rule pairs are split into `_high_conf` and
  `_probable` variants for this reason).
- OTLP/gRPC is not supported in v1.9. Use OTLP/HTTP+protobuf only.
- The hand-rolled minimal protobuf reader covers the OTLP traces
  surface adequately for v1.9; future deep field access (events, links,
  status) will trigger the SwiftProtobuf-generated path. See
  `scripts/regenerate-otlp-proto.sh`.

## Sanitiser coverage

The wire-boundary sanitiser (`OTLPAttributeSanitizer`) redacts secrets
before persistence. As of v1.9.0 it covers:

- **Vendor key shapes**: Anthropic, OpenAI, Google (`AIza`), AWS access
  keys, GitHub (`ghp_/gho_/ghu_/ghs_/ghr_/github_pat_`), Slack
  (`xox[abprs]-`), Stripe (`sk_live_/sk_test_/pk_live_/pk_test_/rk_*_`),
  Stripe webhook signing (`whsec_`), npm (`npm_`), Twilio (`SK<32 hex>`,
  `AC<32 hex>`), JWT (`eyJ…eyJ…sig`), Postman (`PMAK-`), SendGrid (`SG.`),
  Mailgun (`key-<32 hex>`), Discord webhook URLs, Cloudflare API tokens,
  DigitalOcean (`dop_v1_`), Heroku (`HRKU-`), Vercel (`vrcl_/vercel_`).
- **Bearer tokens**: `Bearer <token>` → `Bearer [REDACTED]`.
- **Private network markers**: IPv4 RFC 1918 / link-local; IPv6
  link-local + unique-local; macOS `<Owner>-MacBook-Pro` style
  ComputerName.
- **Entropy fallback**: any token ≥ 40 chars in base62/-/_/. with
  Shannon entropy ≥ 4.5 bits/char gets `[HIGH_ENTROPY_TOKEN]`. Catches
  unknown-vendor secrets while sparing pure-hex hashes (≤ 4.0 bits)
  and short tokens.
- **Key-name gate**: attribute keys whose lowercased segments include
  `key`, `token`, `auth`, `bearer`, `apikey` or whose substrings
  include `secret`, `password`, `passwd`, `credential` get their
  values blanked regardless of value content.
