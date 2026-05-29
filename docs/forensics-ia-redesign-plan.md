# Forensics IA Redesign — v1.17 client work, rave-aligned

> **Superseded (2026-05-29):** the three-tab IA below is historical design context. The shipped v1.17 Forensics workspace is **four** tabs — Run a scan / Past scans / Findings / Catalog.

**Status:** plan v2, after operator direction (2026-05-22) + rave Phase 0b-finalization review.

**Target:** v1.17.0 (GA). Multi-RC rollout on a new `release/v1.17` branch. Aliases keep `release/v1.13a` operator scripts working through v1.18.

**Coordination:** rave server-side work is happening in a separate Claude session in `~/Documents/claude_code/maccrab-site/rave/`. This plan is the **client contract** — the MacCrab binary side of what the rave plan §5 (operator install flow) ships. I build to the schemas that already exist at `maccrab-site/rave/schemas/`; the server side ships independently.

---

## 1. What changed since plan v1

Operator answered the open questions:

| Q | Answer | Plan section updated |
|---|---|---|
| 1 — Workspace rename | **Forensics** (move TraceGraph + Agent Traces + AI Analysis to Detection) | §3.1 |
| 2 — Sideloading | **Enabled**. Sideload + store are both first-class. | §5.3 |
| 3 — Rave status | **Phase 0b-finalization complete.** Schemas locked at `maccrab-site/rave/schemas/`. Consume, don't redesign. | §5 |
| 4 — Integration timeline | **Build the client independently in parallel.** Don't block on server. | §7 |

Reading the rave plan + locked schemas surfaced **three corrections** to plan v1:

1. **Don't rename `maccrabctl plugin` → `maccrabctl tools`.** The rave plan §5.1 fixes `maccrabctl plugin <verb>` as canonical (`search`, `info`, `install`, `update`, `pin`, `verify`, `uninstall`). I have to keep `plugin`.
2. **Bundle format is `.maccrabplugin`, not `.maccrabtierb`.** rc.20 used `.maccrabtierb` which conflicts with the canonical name. Operator-facing rename needed.
3. **Signing model is dual:** Sigstore (with GitHub Actions OIDC + Rekor + SLSA) for store-installed plugins; the existing rc.20 Ed25519 path stays for `--local` sideloads. Two verifiers, one install flow.

Plan v1 §3.2 also had a bad rename instinct: I'd suggested calling the dashboard tab "Tools." Reverting to **Plugins** — matches both rave plan + operator expectation.

---

## 2. Jobs-to-be-done (unchanged from plan v1)

Six jobs drive the IA:

1. **Triage** — "Something looks off — what's happening on this Mac?"
2. **Routine check** — "Run the standard scan; show me the report."
3. **Incident response** — "Active threat — collect evidence I can hand over."
4. **Inventory** — "What's on this Mac that I should care about?"
5. **Capability expansion** — "Get me MacCrab plugins that look at <X>."
6. **Publish** (post-v1.17, author-side via rave) — out of scope for client work.

---

## 3. Dashboard IA — v1.17

### 3.1 Workspace rename: Investigation → Forensics

`Investigation` workspace is split:

- **TraceGraph + Agent Traces + AI Analysis** → move to **Detection** workspace (where they belong — they consume the detection event stream).
- **Cases + Plugins + Tier B + Artifacts + Findings** → unified into new **Forensics** workspace.

This matches the rave plan's MCP namespace (`forensics.recommend_plugins`, `forensics.list_available_plugins`).

### 3.2 Three tabs: Scans / Plugins / Evidence

| Tab | What it answers | Replaces |
|---|---|---|
| **Scans** | "Run / schedule / review a scan on this Mac" | Cases + Findings (merged) |
| **Plugins** | "What can MacCrab scan; install more" | Plugins + Tier B (unified) |
| **Evidence** | "Pull artifacts out for export / sharing" | Artifacts (with scan context) |

(Settings → Privacy & Trust gets the trust list, encryption defaults, scheduled-trusted policy — same as plan v1 §3.4.)

### 3.3 Tab: Scans

**Empty state** (default landing for new operators):

```
┌─────────────────────────────────────────────────────────┐
│  No scans yet                                            │
│                                                          │
│  Start a scan to check this Mac for signs of compromise, │
│  misconfiguration, or unauthorized changes.              │
│                                                          │
│  [ Start a scan → ]                                      │
│                                                          │
│  ────                                                    │
│  Schedule recurring scans → Settings · Scans             │
└─────────────────────────────────────────────────────────┘
```

**"Start a scan" wizard** (sheet, 3 steps):

- **Step 1 — Why are you scanning?**
  - "Something looks off" → triage preset
  - "Routine check" → routine preset
  - "I'm responding to an incident" → IR preset (privacy class = personalComms allowed, write evidence bundle by default)
  - "Just exploring" → explore preset (metadata only)

- **Step 2 — Plugins to run** (preselected from preset, operator adjusts)
  - Unified plugin list: built-in + installed third-party
  - Each row: plugin name, plain-English description, data class indicator
  - Stars on the recommended-for-this-scan-type plugins

- **Step 3 — Confirm + run**
  - Auto-named scan; operator can rename; shows summary; runs.

**Non-empty state**: timeline-ordered scan list with status pill, plugin count, finding count, last-run timestamp. Click → scan detail (artifacts grouped by plugin, findings called out at top).

**What changes vs current**:
- "Case" terminology gone from operator surfaces. "Scan" everywhere.
- `case_id` UUIDs hidden unless the operator explicitly looks for one.
- `encryption_state`, `ai_content_allowed`, `scheduled_trusted` flags live in Settings → Privacy & Trust.
- Current "Findings" tab merges as a panel inside scan detail.

### 3.4 Tab: Plugins

Unified plugin catalog. Three categories visible:

```
┌────────────────────────────────────────────────────────────────┐
│ Plugins                                  [ Browse store → ]    │
│                                                                │
│ [ All ] [ Built-in ] [ Installed ] [ Available in store ]      │
│                                                                │
│ ┌─ Card ───────────────────────────────────────────────────┐   │
│ │ 🛡️  TCC Inventory                                        │   │
│ │     Lists which apps Apple has granted privacy access.   │   │
│ │     Built-in · Metadata only                             │   │
│ │                                              [ Run → ]   │   │
│ └──────────────────────────────────────────────────────────┘   │
│                                                                │
│ ┌─ Card ───────────────────────────────────────────────────┐   │
│ │ 🔌  Hosts file collector       Verified · com.maccrab.*  │   │
│ │     Collects /etc/hosts content and metadata.            │   │
│ │     Installed Mar 2026 · Apple-signed publisher          │   │
│ │     Reads file content (metadata + content data class)   │   │
│ │     v0.0.1 ↘ v0.0.3 available           [ Update ]       │   │
│ └──────────────────────────────────────────────────────────┘   │
│                                                                │
│ ┌─ Card (Sideloaded) ──────────────────────────────────────┐   │
│ │ ⚠️  Custom Scanner                Sideloaded · Unverified │   │
│ │     Operator-installed local bundle.                     │   │
│ │     Publisher key: 8b202a1fba07b32a…           [ Run → ] │   │
│ └──────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────┘
```

**No Tier A / Tier B taxonomy in the UI.** Plain-English badges:

| Badge | Internal mapping |
|---|---|
| **Built-in** | Tier A in-process |
| **Verified** | Tier B, installed from rave store, Sigstore + Rekor verified |
| **Sideloaded · Unverified** | Tier B, installed via `--local` Ed25519 path |
| **Available in store** | Listed in rave catalog, not yet installed |

**Data class indicators** also plain English:

| Display | `PrivacyClass` |
|---|---|
| Metadata only | `.metadata` |
| Reads file content | `.content` |
| Reads private user data | `.personalComms` |
| Touches credentials | `.credentialAdjacent` |
| Touches secrets | `.secret` |

**"Browse store →"** opens a sheet that fetches `maccrab.com/rave/catalog/index.json` (or whatever the rave team publishes — schemas in §5), renders per-plugin cards, "Install" downloads + verifies + invokes the existing PluginInstaller flow with operator consent.

**"Manage..." menu** per installed third-party plugin:
- Publisher details (workflow_ref, repository, Sigstore inclusion proof URL)
- Show install date + bundle path
- Update (`maccrabctl plugin update <id>`)
- Uninstall
- Revoke publisher key (with confirm dialog)

**"Run" button** — present in v1.17 UI but disabled with explanatory tooltip ("Subprocess plugin runtime ships in a future MacCrab release") until the Tier B spawn surface lands in release. First-party (built-in) Run works as today.

### 3.5 Tab: Evidence

Was "Artifacts". Renamed because operators understand "evidence" — what they ship in IR.

- Default view: list scoped to most-recent completed scan
- Search bar: cross-scan search
- Bulk action: **"Export evidence bundle..."** produces a `.maccrabevidence` zip (rename of `.maccrabtrace`; same hash-chain integrity format)
- No artifact id integers visible — rows show timestamp + plugin + summary + data class

### 3.6 Settings → Privacy & Trust

New sub-section consolidates:
- Tier B trust list (read; manage via CLI for safety)
- Default encryption state for new scans
- AI content opt-in per-scan
- Scheduled-trusted policy
- Sideload warning banner toggle (defaults on)

---

## 4. CLI restructure — `maccrabctl`

### 4.1 Vocabulary, after reading rave plan §5.1

| New | Replaces / Existing | Notes |
|---|---|---|
| `maccrabctl scan ...` | `maccrabctl case ...` | Customer-shaped verb. |
| `maccrabctl plugin ...` | (unchanged namespace) | Rave plan canonical. Adds search/info/update/pin. |
| `maccrabctl evidence ...` | `maccrabctl case artifacts ...` | New top-level for export flow. |

Note: I previously proposed `maccrabctl tools`. Reverted — rave plan locks `plugin`.

### 4.2 Full command map

```
# Scans (was: case)
maccrabctl scan new                                  # interactive: "Why are you scanning?"
maccrabctl scan new --reason <triage|routine|ir|explore>
maccrabctl scan list
maccrabctl scan show <scan-id>
maccrabctl scan run <scan-id> --plugin <plugin-id> [--plugin ...]
maccrabctl scan run-all <scan-id>
maccrabctl scan export <scan-id> [--output evidence.maccrabevidence]
maccrabctl scan delete <scan-id> [--shred]

# Plugins (rave plan §5.1 canonical; add search/info/update/pin)
maccrabctl plugin search "<query>"                   # rave catalog query
maccrabctl plugin info <plugin-id>                   # local OR catalog
maccrabctl plugin install <plugin-id>                # store install (Sigstore-verified)
maccrabctl plugin install <plugin-id> --channel community
maccrabctl plugin install <plugin-id> --version <semver>
maccrabctl plugin install --local <path>             # sideload (Ed25519 or unsigned, prominent warning)
maccrabctl plugin install --yes <plugin-id>          # narrow: pre-approved patch updates only
                                                     # (rejected for first install, sideload, major/minor)
maccrabctl plugin update <plugin-id>                 # bump to catalog's current_version
maccrabctl plugin uninstall <plugin-id>
maccrabctl plugin pin <plugin-id>                    # freeze at current version
maccrabctl plugin verify [<plugin-id>]               # verify one, or all if no id
maccrabctl plugin list [--filter built-in|installed|all]
maccrabctl plugin trust <key-hex-or-publisher-id>    # manual trust add
maccrabctl plugin revoke <key-hex-or-publisher-id>
maccrabctl plugin trust-list
maccrabctl plugin status                             # was: daemon-status

# Evidence (was: case artifacts)
maccrabctl evidence list --scan <scan-id>
maccrabctl evidence search "<query>"
maccrabctl evidence show <evidence-id>
maccrabctl evidence export --scan <scan-id> [--output evidence.maccrabevidence]
```

### 4.3 Deprecation aliases

```
$ maccrabctl case new
WARNING: 'maccrabctl case' is renamed to 'maccrabctl scan' in v1.17.
         Aliases continue to work through v1.18; removed in v1.19.
<output as today>
```

Same alias pattern for the existing `plugin install/uninstall/installed-list/trust/revoke/trust-list/verify-all/daemon-status` subcommands that we're renaming or merging (`verify-all` → `verify`, `daemon-status` → `status`, `installed-list` collapses into `list --filter installed`).

### 4.4 `--yes` semantics (per rave plan §5.1)

Narrow to **pre-approved patch updates on already-installed plugins** with **no capability/TCC/network/MCP/dependency/signing-identity/privacy-class change**. Used by `plugin update --yes` for unattended patch refresh.

Rejected outright:
- `plugin install --yes <plugin-id>` first install → reject
- `plugin install --local --yes` → reject (sideload requires explicit consent)
- Major or minor update → reject (must surface change diff to operator)
- Any TCC / network / MCP / data class change → reject

The CLI returns a structured error explaining why interactive consent is required.

---

## 5. Rave store integration — client side

### 5.1 Coordination model

The rave server-side work happens in `~/Documents/claude_code/maccrab-site/rave/`. **I do not modify that repo from the platform side.** I consume:

| Source of truth | What it locks |
|---|---|
| `maccrab-site/rave/schemas/manifest.json` | `.maccrabplugin/Contents/Resources/manifest.json` shape |
| `maccrab-site/rave/schemas/catalog-entry.json` | `/rave/catalog/<plugin-id>.json` shape |
| `maccrab-site/rave/schemas/revocation.json` | `/rave/revocations.json` shape |
| `maccrab-site/rave/docs/verification/` | Operator-side verification path |

The client builds against these schemas. If the schemas evolve, the client tracks. The schemas are *FROZEN at v0* per Phase 0b-finalization commit `02329a3` so this is a stable contract.

### 5.2 Catalog discovery

Per the rave plan §3.2, catalog entries are **per-plugin JSON files at `/rave/catalog/<plugin-id>.json`** with pinned digests. There's no monolithic `index.json`.

**Client implementation**: fetch a discovery index from `maccrab.com/rave/catalog/_index.json` (server publishes this — coordinate via the rave-site repo) listing available plugin-ids + latest-version pointers. Client then fetches per-plugin entries on demand.

If the server doesn't ship `_index.json` yet, the client falls back to a hardcoded bootstrap list (first-party only) and surfaces a "Catalog index not yet available" hint. Acceptable for the bridge period.

### 5.3 Install flow (matches rave plan §5)

1. Operator clicks "Install" on a catalog plugin OR runs `maccrabctl plugin install <plugin-id>`.
2. Client fetches `maccrab.com/rave/catalog/<plugin-id>.json` (signed catalog entry).
3. Client fetches `revocations.json`; aborts if `<plugin-id>` or its publisher's signing identity is revoked.
4. Client downloads the `.maccrabplugin` artifact from the URL templated by `release_url_template` + the version's `tag`.
5. Client verifies:
   - `artifact_sha256` matches downloaded bytes
   - `manifest_sha256` matches unpacked manifest
   - `canonical_tree_sha256` matches normalized bundle tree (per `vetting/canonical-artifact-comparison.md`)
   - **Sigstore verification**: certificate's `workflow_ref` matches the entry's `exact_signer.workflow_ref` (per-version pinning); Rekor inclusion proof valid; SLSA provenance attestation present.
6. Client presents the **capability summary screen** to the operator (see rave plan §7): TCC requirements, network endpoints, MCP tools exposed, data classes the plugin emits. Operator confirms.
7. Client invokes the existing PluginInstaller flow to copy the bundle into the local plugins root + mark the publisher key trusted (per first-install consent) + record Sigstore identity in audit log.
8. Plugin appears in dashboard "Installed" + CLI `plugin list --filter installed`.

### 5.4 Sideload flow (`maccrabctl plugin install --local`)

Per rave plan §5.5: sideloading is first-class.

1. Operator runs `maccrabctl plugin install --local <path>` OR drags a `.maccrabplugin` onto the dashboard (v1.17 deferred — drag-and-drop comes in v1.18).
2. Client unpacks bundle; validates against `schemas/manifest.json`.
3. **No Sigstore verification**; **no revocation check**; **no canonical tree comparison**.
4. Existing Ed25519 PluginSignatureVerifier (rc.20) runs if the bundle ships an `signing.key.pub` + `signature` — gives operators a way to sign their own local bundles.
5. Capability summary screen shown (same as store install).
6. Operator confirms with explicit "I understand this plugin is unvetted" checkbox.
7. Bundle copied to plugins root + tagged **`sideloaded: true`** in audit log.
8. Plugin appears in dashboard with **persistent yellow "Sideloaded · Unverified" badge** on every card AND every artifact it emits.
9. **No auto-update**; **no revocation broadcast applies**; operator must manually `uninstall` if compromised.

### 5.5 Bundle format rename: `.maccrabtierb` → `.maccrabplugin`

rc.20 shipped `.maccrabtierb` as the bundle extension. Rave plan canonicalizes `.maccrabplugin`. v1.17 migration:

- v1.17.0-rc.1: PluginInstaller accepts BOTH extensions; new bundles default to `.maccrabplugin`.
- v1.17.0-rc.3 (when store integration lands): documentation + dashboard use `.maccrabplugin` everywhere.
- v1.18: PluginInstaller stops accepting `.maccrabtierb` for new installs; existing installed bundles auto-migrate (folder rename) on first daemon-status refresh.
- v1.19: `.maccrabtierb` support removed entirely.

### 5.6 Two-stage trust + revocation (per rave plan §6 + §12)

The client maintains:

- **Project-curated allowlist of publisher signing identities** (workflow_ref patterns). Embedded in the MacCrab binary; updated per MacCrab release.
- **Per-operator trust set** (which publishers the operator has accepted at install time). Local.
- **Operator-managed revocation list** (the rc.20 `revoked-keys.json`). Local.
- **Rave-broadcast revocations** (fetched from `maccrab.com/rave/revocations.json`). Sigstore-signed; client verifies signature before applying.

Revocation flow at every plugin invocation (matches rc.20 audit-3 + audit-4):
1. Check local revocation list. If hit → refuse run.
2. Check rave-broadcast revocations. If hit → mark publisher as revoked locally + refuse run.
3. Check Sigstore identity matches catalog entry. If mismatch → refuse run.
4. Run.

### 5.7 Tier B coupling gate (rave Phase 1 dependency)

Per rave plan §1 + §15: **rave Phase 1 (operators can actually install + run community plugins) is gated on Tier B subprocess runtime being in a release branch.** Currently:

- `release/v1.13a` has the install + verify + Sigstore + capability summary + trust chain.
- `research/post-v15` has the subprocess + sandbox-exec + brokered access spawn surface.

**v1.17 ships the install/verify side without spawn.** Operators can browse rave, install plugins, verify signatures end-to-end — but **third-party plugin Run is disabled in the dashboard** (with explanatory tooltip) until the spawn surface lands in release. First-party (built-in) plugin Run works as today.

When the spawn surface lands (target: v1.18 or v1.19, depending on Apple Developer XPC service entitlement timing), the Run buttons unlock automatically. The intermediate v1.17 release lets the rave catalog mature + operators install + verify in advance of Phase 1 launch.

This is **honest staging**, not a feature gap pretending to be done.

---

## 6. MCP surface — `forensics.*` (per rave plan)

| New | Replaces |
|---|---|
| `forensics.list_built_in_plugins` | `forensics.list_plugins` (rename for clarity) |
| `forensics.list_installed_plugins` | `tierb.list_plugins` |
| `forensics.verify_plugins` | `tierb.verify` |
| **`forensics.list_available_plugins`** (NEW per rave plan §1) | n/a |
| **`forensics.recommend_plugins(goal)`** (NEW per rave plan §5.4) | n/a |
| `forensics.run_plugin` | `forensics.run_collector` (rename for unified plugin terminology) |
| `forensics.search_evidence` | `forensics.search_artifacts` |
| `forensics.show_evidence` | `forensics.get_artifact` |
| `forensics.scan_timeline` | `forensics.timeline` |
| `forensics.scan_summary` | `forensics.explain_case` |
| `forensics.scan_findings` | `forensics.posture_findings` |

**No `forensics.install_plugin` tool** (per rave plan §5.4) — AI agents recommend, never install.

Same aliasing rule as CLI: old names work through v1.18, removed v1.19.

---

## 7. Migration path (safe integration)

### 7.1 Branches

```
main                          v1.12.9 — no change
release/v1.13a                v1.16.0-rc.21 — no change
release/v1.17                 NEW — branched from release/v1.13a at rc.21
research/post-v15             rc.7 — no change
```

### 7.2 Phasing (RCs of v1.17)

| RC | Scope | Risk | Server dependency |
|---|---|---|---|
| **v1.17.0-rc.1** | CLI rename: add `scan` / `evidence` namespaces; expand `plugin` with search/info/update/pin stubs that 503 until rc.4. Aliases warn. | Low — additive. | None. |
| **v1.17.0-rc.2** | Forensics workspace + 3 new tabs + empty-state designs. Old `Investigation · Forensics ·` tabs show "Moved to Forensics →" redirect. | Medium. | None. |
| **v1.17.0-rc.3** | "Start a scan" wizard + unified Plugins tab (built-in + installed). Bundle format dual support (`.maccrabplugin` + `.maccrabtierb`). | Medium. | None. |
| **v1.17.0-rc.4** | Rave catalog integration: catalog fetcher + Sigstore verifier + revocation feed checker + "Browse store" UI + `maccrabctl plugin search/info/install <plugin-id>/update`. Mock catalog if rave server not yet serving. | Medium. | Rave catalog JSON shape (FROZEN). Rave server-side LIVE deployment optional — client mocks until ready. |
| **v1.17.0-rc.5** | MCP tool rename + `forensics.recommend_plugins`. Update README + Homebrew cask + installer help text. | Low — additive aliases. | None. |
| **v1.17.0-rc.6** | Polish + a11y audit + locale snapshot (14 locales, matches `pre-release-audit.sh`). | Low. | None. |
| **v1.17.0 GA** | Removes the "Moved to Forensics →" redirect screens; old workspace tabs gone. | Low. | Rave catalog ideally live; client gracefully degrades if not. |
| **v1.18.0** | Drag-and-drop sideload onto dashboard. `.maccrabtierb` accepted at install time → auto-migrates on next daemon refresh. | Low. | None. |
| **v1.19.0** | CLI alias warnings become errors. `.maccrabtierb` removed entirely. Old MCP tool names removed. | Breaking. | None. |

### 7.3 Server-side coordination (parallel work)

The rave Claude session ships:

- `maccrab.com/rave/catalog/_index.json` — discovery index (define shape jointly; my plan §5.2 default)
- Per-plugin catalog entries already exist (`com.maccrab.hosts-collector.json` etc.)
- `maccrab.com/rave/revocations.json` — already exists, empty at v0
- Server-side TUF / Cosign TrustedRoot — already shipped per `15 commits represent ~25–40% of total Phase 0a + 0b construction work` in the rave README
- Public DNS + Cloudflare publication un-gating per rave plan §3.10

**My client work doesn't block on any of this.** Each rc step is testable against:
- Local mock catalog (a JSON file on disk pretending to be `_index.json`)
- A test plugin bundle in `~/.maccrab-test-store/` with a self-signed Sigstore mock chain
- Fixture revocation list

I switch the catalog URL from local-mock to live `maccrab.com/rave/catalog/` when the rave server is publicly serving. Until then, operators with `MACCRAB_RAVE_CATALOG=file:///path/to/local/index.json` env var get the dev preview.

### 7.4 Safety constraints (unchanged from plan v1)

- **No breaking change in any RC** — every alias works through v1.18.
- **Pre-existing operator scripts can't silently fail** — alias hits log to audit, never error.
- **Tests are additive** — each new namespace ships with its own tests; the rc.20 PluginInstaller + signature paths stay tested through v1.19.
- **Documentation** — each RC ships `RELEASE_NOTES/v1.17.0-rcN.md` written for operators (not engineers).

---

## 8. Open questions remaining

Most of plan v1's §8 is resolved. Remaining items:

1. **Bundle-extension migration aggressiveness.** §5.5 proposes a 3-RC migration `.maccrabtierb` → `.maccrabplugin`. Operator OK with two-extension overlap, or should we hard-flip in rc.3?
   - *Default*: dual-support through v1.18 (gentlest).
   - *Alternative*: hard-flip in rc.3 (cleaner; breaks rc.20 sideloaders).

2. **`_index.json` discovery file format.** §5.2 defaults to a simple `{"plugins": ["<plugin-id>", ...]}` JSON; the rave Claude session may want to define it differently. Coordinate at rc.4 design time.

3. **Sigstore client implementation.** Cosign isn't a Swift library. Options:
   - Shell out to a bundled `cosign` binary inside the .app (Apple-notarized as part of MacCrab release).
   - Implement a minimal Sigstore verifier in pure Swift using CryptoKit + the rave-published TrustedRoot.
   - *Default*: option 1 — pragmatic, matches every other Sigstore consumer ecosystem. Adds ~30MB to DMG.
   - *Alternative*: option 2 — purer; significant work; might be worth it long-term but slows v1.17.

4. **Capability summary screen UX.** Rave plan §7 specifies "one-screen capability summary at install confirmation." Exact widget layout up to me. Will sketch in rc.4.

5. **Will the rave server publish `_index.json` by rc.4?** Coordinate with the rave Claude session. If not, client ships with the local-mock path + a "Catalog index will appear here when the server is live" empty state.

---

## 9. What this does NOT change

(Same list as plan v1.)

- Detection workspaces (Alerts / Campaigns / Events / Rules / Prevention / Intelligence) untouched.
- Tier A plugin internal architecture unchanged.
- The rc.20 install/verify/trust/sandbox-profile chain stays as the foundation.
- Subprocess spawn (`TierBSubprocessLoader` on `research/post-v15`) is NOT moved into the release line by this work. v1.17 ships the install/verify half; v1.18+ ships the spawn half.
- The rave server-side build (catalog repo, CI workflows, signing keys, vetting policy, publication infrastructure) is the other Claude session's scope. I consume; I don't produce.

---

## 10. Ask

Sign off on the §8 open questions (or default-through), and I'll branch `release/v1.17` off `release/v1.13a` and start **v1.17.0-rc.1** — CLI rename only, no UI moves yet. Each subsequent RC ships weekly, customers see the rework arrive in pieces, and the rave catalog integration plugs in at rc.4 without requiring the server to be live.

The honest end-state of v1.17: a customer-shaped dashboard + CLI + MCP surface that's ready for the rave catalog the moment it goes public, plus a sideload-friendly path that already works today. Tier B execution remains research-only; v1.17 doesn't ship third-party plugin running yet (rave Phase 1 gate, not v1.17 scope).
