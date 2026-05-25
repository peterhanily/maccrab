# Forensics rebuild — Plan A + rave integration

**Date:** 2026-05-25
**Branch:** release/v1.17
**Status:** approved direction (plan A — full operator-side rebuild). Implementing rc.4 immediately.

---

## 1. What the rave team has shipped (and what it changes)

Read `~/Documents/claude_code/maccrab-site/rave/` today. Key state:

| Thing | State | Impact on my plan |
|---|---|---|
| **v4.5 reconciliation** (commit `db21e6f`) | manifest schema v1 = platform-aligned with `TierBManifest.swift`. Signing = Ed25519 (my `PluginSignatureVerifier`), not Sigstore. Bundle format = flat `<id>/{manifest.json, binary, signature, signing.key.pub}`. | **Drop dual-verifier complexity from earlier plan.** Sigstore work disappears. One signing path. |
| **Local launch rehearsal** (commit `9f48c7f`) | rave team built + Ed25519-signed a plugin against my v1.16.0-rc.21 DMG; my `PluginSignatureVerifier` accepted it; `TierBBootstrap` reported it verified. | **The chain works.** Client side and server side already meet. |
| **Signed catalog.json** | Single discovery file at `rave/catalog.json` + `.sig`. Each entry has trust_tier + signer_identity + current_version. | **I consume `catalog.json` directly, no `_index.json` invention.** |
| **Signed revocations.json** | `rave/revocations.json` + `.sig`. Empty at v0 but the format is locked. | Periodic fetch + verify, applied at every plugin run. |
| **Project signing key** | `rave/keys/catalog.pub` (Ed25519, 32 bytes raw) + fingerprint. | Bake the project public key into the MacCrab binary. Verify catalog signatures against it. |
| **2 real first-party plugins** | `com.maccrab.hosts-collector`, `com.maccrab.launch-agents-collector`. Catalog entries signed. | These are NOT test data. My earlier deep-dive misread them. The only actual dev pollution is `com.test.daemon`. |
| **🎯 KITS** | `rave/kits/com.maccrab.kit.{ir-quick, phishing-triage, supply-chain-audit, ai-agent-posture}.json` — curated bundles per operator scenario. Schema at `rave/schemas/kit.json`. | **This is the operator-facing primitive I was missing.** Drop the "reason cards" idea. Pick a kit, run a kit. |

### What a kit is

A `.maccrabkit` is a signed JSON file declaring a named operator scenario + the plugins that scenario needs:

```json
{
  "id": "com.maccrab.kit.ir-quick",
  "name": "IR Quickstart",
  "category": "incident-response",
  "description": "Triage kit for the first 60 minutes of an incident...",
  "plugins": [
    { "plugin_id": "com.maccrab.hosts-collector",        "min_version": "0.0.1", "role": "..." },
    { "plugin_id": "com.maccrab.launch-agents-collector", "min_version": "0.0.1", "role": "..." }
  ],
  "trust_tier": "first-party",
  "min_maccrab_version": "1.16.0"
}
```

Categories: `incident-response | audit | posture | triage | monitoring | compliance | research`.

This maps perfectly to what an operator wants to pick when they "Start a scan."

---

## 2. The new operator flow (built around kits)

### Forensics workspace — two tabs only

```
┌────────────────────────────────────────────────────────────┐
│ Forensics                                                  │
│                                                            │
│ [ Scans ]  [ Findings ]                                    │
└────────────────────────────────────────────────────────────┘
```

**Tab 1: Scans** — start + see past scans.
**Tab 2: Findings** — actionable feed of what scans found.

**No Plugins tab.** Plugin/kit management lives in Settings.
**No Evidence tab.** Raw evidence collapses into scan detail.

### Scans tab — empty state

```
You haven't run a scan yet.

A scan checks this Mac for signs of compromise. Pick what kind of
scan to run — each one is shaped for a specific situation.

┌──────────────────────────────────────────────────────────┐
│ 🚨  IR Quickstart                          [ Run ]       │
│     For the first 60 minutes of an incident. Captures    │
│     persistence baselines and current network state.     │
│     2 scanners · under a minute                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ 🎣  Phishing Triage                        [ Run ]       │
│     Mail metadata, Safari history, recent downloads.     │
│     1 scanner · under a minute                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ 📦  Supply Chain Audit                     [ Run ]       │
│     Inventory installed software signatures + known-     │
│     compromised package check.                          │
│     1 scanner · 2-5 minutes                             │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ 🤖  AI Agent Posture                       [ Run ]       │
│     What AI tools are installed + what they can touch.   │
│     1 scanner · under a minute                          │
└──────────────────────────────────────────────────────────┘

— or —

[ Custom scan… ]   Pick individual scanners yourself.
```

Each kit card pulls its name + description + plugin count from the kit's JSON (currently bundled with the app; later fetched from rave). The "Run" button:

1. Confirms each plugin in the kit is installed (if missing, installs from the local catalog cache).
2. Creates a new scan named "IR Quickstart — May 25 2026 13:42" (auto-named from the kit + timestamp).
3. Runs all the kit's plugins on it via the existing `PluginRunner`.
4. Shows inline progress.
5. When complete, surfaces the findings under the Findings tab + jumps the operator there.

**No modal saying "use the CLI."** No "wizard ships in rc.X." The button works.

### Scans tab — non-empty state

```
Past scans

May 25, 13:42  IR Quickstart           ✓ 3 findings
May 24, 09:15  Supply Chain Audit      ✓ 1 finding
May 23, 16:30  Phishing Triage         ✓ no findings

[ Run another scan ]
```

Click a row → scan detail (findings + raw evidence collapsed under "View raw artifacts").

### Findings tab

Merged feed across all scans:

```
Open findings

Mar 24  Unsigned launch agent installed
         Source: ~/Library/LaunchAgents/com.suspicious.helper.plist
         From scan: IR Quickstart (May 25)
         [ Investigate ]  [ Mark resolved ]

Mar 24  Hosts file modified
         /etc/hosts entry pointing api.npmjs.org → 192.168.1.50
         From scan: Supply Chain Audit (May 24)
         [ Investigate ]  [ Mark resolved ]
```

Each finding has: what we found, when, why it matters, what scan produced it. Filter by severity / scan / scanner. One-click export (single finding → JSON, all → bundle).

### Settings → Forensics

The home for everything an operator only rarely touches:

- **Scanners installed** — list of plugins MacCrab currently has. Each row: name + what it does + remove. "Browse catalog" button opens the rave store sheet (rc.7).
- **Kits installed** — list of kit definitions MacCrab currently has. "Browse kits" opens a similar sheet.
- **Trusted publishers** — Ed25519 keys MacCrab trusts. Add/revoke. Most operators never touch this.
- **Privacy ceiling** — default privacy class new scans allow (metadata / content / personal / credential / secret).
- **Sample data** — "MacCrab found leftover test plugins in your installation. Remove?" + button. Triggered when defensive filter hits `com.test.*` etc.

---

## 3. Vocabulary mapping — what the operator sees vs what's in code

The product-facing vocabulary is now:

| Concept | Operator-visible word | Where it lives |
|---|---|---|
| One scan run | "Scan" | Forensics → Scans tab |
| Curated bundle of plugins for a scenario | "Kit" | Forensics → Scans (cards), Settings → Forensics (mgmt) |
| Single plugin | "Scanner" | Settings → Forensics → Scanners installed |
| What a scan found | "Finding" | Forensics → Findings tab |
| Raw artifact a scanner produced | "Evidence" | Inside scan detail (collapsed by default) |
| Where new scanners come from | "Catalog" | Settings → Forensics → Browse catalog |
| Publisher key trust | "Trusted publishers" | Settings → Forensics → Trusted publishers |
| Plugin's signing chain | (hidden) | n/a — operator never sees |

Words **deleted from operator surfaces**:
- Tier A / Tier B
- Manifest
- Bundle
- Artifact (replaced with "Evidence")
- Case (replaced with "Scan")
- Plugin (replaced with "Scanner" or "Kit" depending on context)
- Tier-anything

---

## 4. Internal renames (so the leaks stop)

Mechanical refactor in rc.5. Operator-invisible but it fixes the "Tier B everywhere" issue at the root.

| Old | New |
|---|---|
| `Sources/MacCrabForensics/TierB/` directory | `Sources/MacCrabForensics/Plugins/External/` |
| `TierBBootstrap` | `PluginCatalog` |
| `TierBManifest` | (collide with existing `PluginManifest` — keep, since rave schema v1 is platform-aligned) |
| `TierBRegistry` | `ExternalPluginRegistry` |
| `TierBSubprocessLoader` (research) | `SubprocessPluginRuntime` |
| `~/Library/Application Support/MacCrab/plugins/tier-b/` | `~/Library/Application Support/MacCrab/plugins/` |
| `tierb.list_plugins` (MCP) | `forensics.list_plugins` (with `tierb.*` alias through v1.18) |
| `tierb.verify` (MCP) | `forensics.verify_plugins` (alias) |
| `os.log` subsystem `com.maccrab.forensics`, category `TierBBootstrap` | category `PluginCatalog` |

One-time migration on first launch of rc.5: if `plugins/tier-b/` exists, move it to `plugins/` and log the migration. Idempotent.

---

## 5. RC sequence (rebuild path)

| RC | Ship | Why |
|---|---|---|
| **rc.4 (next)** | (a) **Test-data filter** — hide `com.test.*` / `com.research.*` / `*-smoke` / .json files in plugins dir from all operator surfaces. (b) **Hide disabled buttons everywhere** — better to omit than tease. (c) **Real "Run a scan" with kit cards** — 4 bundled kits, button works inline, no modal-stub. (d) **Plugins tab + Evidence tab DELETED from workspace** — content moves: plugin mgmt → Settings; evidence → scan detail. (e) **Scan detail view** — name, findings list, "view raw evidence" collapse. | Get the dashboard out of the embarrassing state. Operators can actually do a scan. |
| **rc.5** | Internal `TierB*` rename per §4. On-disk dir migration. MCP `tierb.*` → `forensics.*` aliases. No operator-visible change. | Stop the structural Tier B leak at the source. |
| **rc.6** | (a) **Findings tab** — merged feed, severity filter, mark-resolved, single-finding export. (b) **Settings → Forensics** subsection (scanners, kits, trusted publishers, privacy ceiling, sample data). (c) **Bundled kits** — 4 kit JSON files shipped inside the app at `MacCrab.app/Contents/Resources/kits/`. | Findings is the operator's actual goal. Settings is where management lives. |
| **rc.7** | **Live rave catalog integration** when the server is publicly serving. `fetch(maccrab.com/rave/catalog.json)` + verify signature against bundled `catalog.pub`. Browse + install flow in Settings → Forensics → Browse catalog. Browse kits sheet. | The store goes live in coordination with the parallel rave session. |
| **GA** | Polish, locale snap, "What's new in v1.17" callout, ship. | |

### Coordination with the rave session

- The rave team is on `~/Documents/claude_code/maccrab-site/` separately.
- They control: the catalog content, the signing process, the static-site deployment, vetting policy.
- I control: the client (this codebase) that consumes the catalog + kits + verifies signatures.
- **Shared contract**: `rave/schemas/{manifest, catalog-entry, kit, revocation}.json`. I build against those exactly.
- The rave repo's `rave/keys/catalog.pub` becomes the bundled project key in MacCrab.app. Update mechanism: project key rotation requires a MacCrab app update.

### What I drop from earlier plans

- **Sigstore client** — gone. Rave's v4.5 reconciliation eliminated the need.
- **Compliance preset reason cards** — replaced with kits. Whoever wants a compliance scan publishes a `com.acme.kit.compliance-cis` kit.
- **Plugin author scaffold CLI** — defer. Authors use `rave/tools/maccrab-rave-sign` for now.
- **What's new callout** — keeps; small and high-value.
- **Three-tab plan** (Scans + Plugins + Evidence) — replaced with two (Scans + Findings).

---

## 6. What ships in rc.4 (concretely, today)

Implementing now. No more "wait for sign-off, ship more patches" — going straight to the rebuild.

1. **Delete `V2ForensicsPluginsTabView` + `V2ForensicsEvidenceView`** from the workspace dispatch. Forensics workspace has Scans + Findings only.
2. **Rewrite `V2ForensicsScansView`**:
   - Empty state shows 4 kit cards + Custom button.
   - Each card pulls from a bundled `kits/*.json` file (4 kit files copy from `maccrab-site/rave/kits/` into `Sources/MacCrabApp/Resources/kits/`).
   - "Run" wires to a new `KitRunner` that runs the kit's plugins via `PluginRunner` on a new case + jumps to scan detail.
   - Non-empty state lists past scans with timestamps + finding counts.
   - **No modal-pretending-to-be-a-wizard.**
3. **Build `V2ForensicsScanDetailView`** — accessed by clicking a scan row.
4. **Build `V2ForensicsFindingsView`** (placeholder body for rc.4; full rc.6).
5. **Test-data filter** — `OperatorVisibilityFilter` utility that hides:
   - Cases whose name matches `*-smoke` or starts with `Tier B `
   - Plugin ids matching `com.test.*` / `com.research.*` / `*-fixture`
   - `.json` files inside the plugins dir (they're not plugins; they're metadata)
   Filter applied at every dashboard load.
6. **Hide every disabled button** — "Browse store →", "Export bundle", etc. Don't show them in rc.4 if they don't work.
7. **Bundle the 4 kit JSON files** as app resources.

---

## 7. Ask

This is implementation, not approval. Starting now. Will check in only if I hit a structural problem.

Next message back to operator: "rc.4 shipped, kits + scan-run works inline, here's the DMG."
