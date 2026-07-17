# TraceGraph Graph Rule Schema — v1

**Status:** v1.10.0 (2026-05-07)
**Schema id:** `maccrab.tracegraph.graph_rule.v1`

This document specifies the on-disk format for graph-native detection
rules per §23 of the v1.10.0 TraceGraph spec.

JSON is the canonical authoring + on-disk form. The §23.1
YAML example in the v1.10.0 spec is illustrative; YAML compilation
against the same `GraphRule` Swift type lands as a follow-up alongside
the existing v1.9 rule compiler in `Compiler/`.

---

## 1. Where rules live

```
Rules/graph/<rule_id>.json
```

The daemon and CLI load every `*.json` file under this directory at
startup. Files that fail to decode are skipped with a log message —
one bad rule does not silence the rest of the graph-rule pipeline.

---

## 2. Top-level shape

```json
{
  "id": "maccrab_ai_agent_credential_network_persistence",
  "title": "AI agent + credential access + network + persistence",
  "severity": "high",
  "type": "graph",
  "nodes": { ... },
  "edges": [ ... ],
  "scope": { ... },
  "constraints": { ... },
  "attack": ["T1059", "T1555"]
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `id` | yes | Unique identifier across the rule set. Conventionally `maccrab_<lowercase_underscored>`. |
| `title` | yes | Investigator-facing one-line summary. |
| `severity` | yes | `"informational" | "low" | "medium" | "high" | "critical"`. |
| `type` | yes | Always `"graph"` for v1. |
| `nodes` | yes | Map of binding-name → `NodeSpec`. At least 1 node required. |
| `edges` | yes | Array of `EdgeSpec`. May be empty (rule matches purely on node existence). |
| `scope` | optional | Common-ancestor + max-depth constraints. |
| `constraints` | optional | Time window + min confidence. |
| `attack` | optional | MITRE ATT&CK technique IDs surfaced when the rule matches. |

---

## 3. `nodes` — `NodeSpec`

Each entry binds a name (used in `edges` references) to a typed
constraint over `TraceEntity`.

```json
{
  "type": "process",
  "where": {
    "executable_name": { "in": ["zsh", "bash", "sh"] },
    "is_apple_signed": { "equals_bool": false }
  }
}
```

### 3.1 `type`

Must equal a `TraceEntity.entity_type` value. Supported v1.10.0 types:

| `type` | Backing entity |
| --- | --- |
| `process` | `ProcessNode` |
| `file` | `FileNode` |
| `network` | `NetworkNode` |
| `ai_agent` | `AIAgentNode` |
| `persistence` | `PersistenceNode` |
| `mcp_server` | `MCPServerNode` |
| `package_script` | `PackageScriptNode` |
| `browser_download` | `BrowserDownloadNode` |
| `code_signature` | `CodeSignatureNode` |
| `user_session` | `UserSessionNode` |
| `tcc_permission` | `TCCPermissionNode` |
| `rule` | `RuleNode` |
| `alert` | `AlertNode` |

### 3.2 `where`

Map of attribute path → `WhereClause`. The clause filters which
entities of `type` may bind to this node.

Supported clause shapes:

| Clause | Semantics |
| --- | --- |
| `{ "in": ["a", "b"] }` | String value must be in the list. |
| `{ "not_in": ["a", "b"] }` | String value must NOT be in the list. |
| `{ "equals": "foo" }` | String value must equal exactly. |
| `{ "equals_bool": true }` | Boolean value must equal exactly. |

### 3.3 Attribute paths

Per entity type — the keys map to JSON-encoded attribute names from
the underlying `*Node` Codable struct.

**`process`:**
- `executable_name` — derived: last path component of `executablePath`
- `executable_path` — full path
- `is_apple_signed` — bool
- `is_notarized` — bool
- `signing_team_id`
- `signing_identifier`
- `agent_trace_id`

**`file`:**
- `file_kind` — one of `credential_file`, `launch_agent`, `launch_daemon`,
  `login_item`, `shell_profile`, `script`, `binary`, `plist`,
  `browser_download`, `package_file`, `project_file`, `unknown`
- `path`
- `sha256`

**`network`:**
- `reputation` — one of `known_good`, `private_range`, `unknown`,
  `suspicious`, `malicious`
- `destination_host`
- `destination_ip`
- `port`
- `protocol_name`

**`ai_agent`:**
- `agent_name`
- `agent_tool` (alias: `tool_name`)
- `attribution_method` — one of `direct_traceparent`,
  `mcp_protocol_observed`, `process_lineage_match`, `temporal_proximity`

**`persistence`:**
- `persistence_type` — one of `launch_agent`, `launch_daemon`,
  `login_item`, `shell_profile`, `cron`, `plist`
- `path`

---

## 4. `edges` — `EdgeSpec`

Each entry constrains an edge between two bound nodes.

```json
{ "from": "agent", "to": "proc", "relation": "associated_with_agent", "min_tier": "strong_inferred" }
```

| Field | Required | Notes |
| --- | --- | --- |
| `from` | yes | Source node binding name. |
| `to` | yes | Target node binding name. |
| `relation` | yes | One of the §9 vocabulary: `spawned`, `read`, `wrote`, `renamed`, `deleted`, `connected_to`, `created_persistence`, `loaded_code`, `signed_by`, `associated_with_agent`, `triggered_rule`, `matched_sequence`, `caused`. |
| `min_tier` | optional | One of `direct`, `strong_inferred`, `weak_inferred`. Omitted → relation default per §23.2. |

Per §23.2 default minimum tier (used when `min_tier` is omitted):

| Relation | Default `min_tier` |
| --- | --- |
| `associated_with_agent` | `strong_inferred` |
| `created_persistence` | `strong_inferred` |
| `caused` | `strong_inferred` |
| `spawned`, `read`, `wrote`, `renamed`, `deleted`, `connected_to`, `loaded_code`, `signed_by`, `triggered_rule`, `matched_sequence` | `weak_inferred` |

`temporal_only` edges **never** satisfy graph rules (§23.2). The
evaluator enforces this even when a rule sets `min_tier: temporal_only`.
A future `temporal_correlation` operator (deferred to v1.10.x) will
provide explicit opt-in for temporal patterns.

---

## 5. `scope`

```json
{ "common_ancestor": "proc", "max_depth": 4 }
```

| Field | Notes |
| --- | --- |
| `common_ancestor` | Node binding name that must exist among the bound nodes. v1.10.0 baseline: presence check only. v1.10.x will validate connectivity via spawned-edge traversal. |
| `max_depth` | Bound on the ancestor walk depth (used by future v1.10.x increment). |

---

## 6. `constraints`

```json
{ "within_seconds": 300, "min_confidence": 0.75 }
```

| Field | Notes |
| --- | --- |
| `within_seconds` | All matched edges' `last_seen` timestamps must fall within this window. |
| `min_confidence` | Every matched edge's confidence must be at or above this value. |

---

## 7. `attack`

Array of MITRE ATT&CK technique IDs (e.g. `["T1059", "T1555"]`)
surfaced on alerts when the rule matches. Validated by
`make lint-rules` against the known technique set.

---

## 8. Evaluator semantics

The `GraphRuleEvaluator` evaluates each rule against a materialized
trace's entities + edges via backtracking constraint satisfaction:

1. Order node bindings (most-restrictive first).
2. For each binding, try every `entity` of `nodeSpec.type` matching
   the `where` filters.
3. After all nodes are bound, verify every `EdgeSpec` finds an
   actual edge between the bound entities meeting the `min_tier`.
4. Verify `scope` (common ancestor present in bindings).
5. Verify `constraints` (time window + min confidence).
6. First successful match per rule is reported.

A rule yields zero or one `GraphRuleMatch` per trace.

---

## 9. Shipped rule set

Seven rules ship in `Rules/graph/` (the set has grown since the v1.10.0
baseline of five):

| File | Severity | What it catches |
| --- | --- | --- |
| `maccrab_ai_agent_credential_network_persistence.json` | high | Headline: AI-attributed shell + credential read + suspicious network + persistence creation, all sharing a common process ancestor. T1059 / T1555 / T1543.001 / T1105. |
| `maccrab_ai_agent_lethal_trifecta.json` | critical | Lethal trifecta in one agent session: sensitive-data read + untrusted content + external egress. T1059 / T1555 / T1041. |
| `maccrab_ai_agent_shell_touches_credential.json` | high | An AI agent's shell touched a credential file. T1059 / T1555. |
| `maccrab_worm_self_propagation.json` | critical | Package-manager descendant read a credential then phoned home — self-propagation signal. T1195.001 / T1555 / T1567 / T1098. |
| `maccrab_unsigned_download_executes_then_persists.json` | high | Unsigned binary from a download path creates persistence — classic dropper signal. T1543.001 / T1547. |
| `maccrab_launchagent_after_credential_access.json` | high | Same process read credentials and created persistence within 10 minutes. T1543.001 / T1555. |
| `maccrab_agent_associated_shell_writes_to_login_item.json` | high | AI-associated shell wrote to a login item / launch agent. T1543.001 / T1547. |

---

## 10. Deferred to v1.10.x

* YAML authoring form (compiles to JSON via the existing
  `Compiler/` pipeline).
* JSON Schema validator wired into `make lint-rules`.
* `temporal_correlation` operator for explicit temporal patterns.
* Full common-ancestor walk verification via spawned-edge traversal.
* Integration with `ReplayEngine`'s `RulesetReplayer` so graph rules
  participate in replay determinism.
