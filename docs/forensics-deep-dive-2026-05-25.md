# Forensics deep-dive — what I actually built, and how to unfuck it

> **Superseded (2026-05-29):** historical snapshot. The shipped v1.17 Forensics workspace is the four-tab design (Run a scan / Past scans / Findings / Catalog); references to the older IA below are kept for context only.

**Date:** 2026-05-25
**Author:** me, after shipping three RCs of patches that the operator (rightly) called shit.
**Goal:** stop patching. Step back. Look at the whole delivery from a customer's perspective. Propose a real fix.

---

## 1. Honest take on the failure

I built the Forensics delivery engineering-up. Every layer — types, runtimes, registries, signing chains, manifests, CLI verbs, MCP tools — was designed against the SDK shape, not against an operator's job. Then I tried to bolt a customer-facing dashboard on top and rename a few things.

It didn't work. Three RCs of patches later:

- "Tier B" is still everywhere in the codebase, on disk, in the binary symbol table, in audit logs.
- The dashboard's "Start a scan" button shows a modal that tells the operator to **use the CLI instead** — for a flagship action.
- The Plugins tab shows **leftover test data from my own dev sessions** as if it were product content (`com.maccrab.hosts-collector`, `com.test.daemon`, plus a revocation list file rendered as a plugin).
- The Scans tab shows a `Tier B end-to-end smoke` case I created during testing as if it were a real operator scan.
- An operator has no idea where plugins come from, what each does, whether they're safe, or how to add more.

The patches I shipped (rc.2, rc.3) addressed symptoms (rename here, hide string there). They didn't address the underlying problem: **the product is built around exposing the Mac Context Plugin Platform's internals, not around what an operator needs to do.**

I should have stopped and rebuilt the operator experience from the customer's job. Instead I shipped three rounds of garbage.

---

## 2. What an operator actually needs from Forensics

Strip everything back. An operator opens MacCrab and clicks Forensics. They want to do exactly one of these:

| Job | What they expect | What rc.3 actually does |
|---|---|---|
| **"Check my Mac for problems."** | A button. Click it. Wait. See findings. | Dashboard button says "use the CLI" |
| **"What can MacCrab even check?"** | A short, plain-English list. "Privacy permissions. Launch items. Mail attachments. Code-signing anomalies." | Shows internal plugin manifests. "Standard" badges. Filter tabs. Engineering-shaped. |
| **"Show me what's wrong right now."** | A list of findings: "3 launch agents installed without your knowledge. 1 quarantined file from yesterday's download." | No findings UI. Shows raw "evidence artifacts" with content-types like "tier_b_fixture.heartbeat". |
| **"Export this for our IR person."** | One button. Get a sharable file. | Button disabled; "lands rc.3". (We're on rc.3.) |
| **"What's new I can install?"** | A store. Browse. Click. Install. | "Catalog browser is on the way" + disabled button. No usable installation flow from the dashboard. |

The Forensics workspace in rc.3 fails on every single one of these. The operator can't actually do any forensics from the dashboard. The only working surface is the CLI, and the CLI requires SDK-level vocabulary (`maccrabctl scan new --reason routine`).

---

## 3. Every "Tier B" leak that survived rc.3

I deleted the dashboard view and the dead loader. I did not delete the **structure** the rest of the product is built on.

### Code

| Layer | Tier B reference |
|---|---|
| Directory | `Sources/MacCrabForensics/TierB/` (whole subtree) |
| Types | `TierBBootstrap`, `TierBManifest`, `TierBRegistry` (all linked into the binary symbol table; visible via `strings`) |
| Comments | Both forensics workspace view files reference "Tier A / Tier B" in source comments |
| MCP tools | `tierb.list_plugins`, `tierb.verify` (operator-visible JSON when an AI agent queries the surface) |
| Old CLI aliases | `verify-all`, `daemon-status`, `installed-list` still in the binary as deprecation-warned aliases (carrying the old engineering shape) |

### On disk

| Path | Tier B reference |
|---|---|
| `~/Library/Application Support/MacCrab/plugins/tier-b/` | The whole plugin install root is `tier-b/`. Every installed plugin is under that path. |
| `~/Library/Application Support/MacCrab/plugins/tier-b/trusted-keys.json` | Trust list file. Operator-visible if they ls the dir. |
| `~/Library/Application Support/MacCrab/plugins/tier-b/revoked-keys.json` | Same. |

### Logs / audit

- Every `os.log` line from `TierBBootstrap.refresh()` writes `subsystem: "com.maccrab.forensics", category: "TierBBootstrap"`. Shows up in `Console.app`.

### Why deleting one view + one stub didn't fix it

The "Tier B" name is **the engineering-side word for "third-party plugin runtime that runs out-of-process under a sandbox."** It's structurally in the design because the design distinguishes Tier A (in-process built-in) from Tier B (out-of-process third-party). I should have given that distinction an operator-shaped name from day one. I didn't.

---

## 4. Test data pollution I shipped to operators

Worse: my own dev sessions left real data in `~/Library/Application Support/MacCrab/` that the dashboard reads at startup. Every operator who installs rc.3 sees:

- **One leftover case** — UUID `6ef13be4-…` named whatever I called it. Shows in Scans.
- **Three test plugins**: `com.maccrab.hosts-collector`, `com.maccrab.launch-agents-collector`, `com.test.daemon`. Shows in Plugins.
- **trusted-keys.json + revoked-keys.json** sitting in the same dir as the plugin folders — rendered as if they were plugins because the installer's `list()` doesn't filter `.json` files cleanly.

This isn't operator data. It's **my development residue, shipped via the install path**. From an operator's perspective the entire product looks like an incomplete demo because they can't tell mine apart from theirs — there's no "this is sample data, remove?" affordance, no "you have no scans yet, start one" empty state, no "no plugins yet, here's how to add one" entry point.

(Actually, the dashboard *does* have empty-state designs. They just never trigger because the test data is non-empty.)

---

## 5. Why the dashboard scans flow is a dead end

The "Start a scan" button in rc.3 opens a modal that says:

> The guided wizard lands in v1.17.0-rc.3 alongside the unified plugin catalog. For now, use the CLI:
> `maccrabctl scan new "my scan" --reason routine`

This is the entire scans flow. There is no other path from the dashboard to running a scan. **The flagship operator action — the literal reason this workspace exists — requires dropping to a terminal.**

This was always going to be the wizard's job. But I committed to rc.2 shipping the IA without the wizard, expecting "rc.3 wires the wizard." Then I shipped rc.3 with the bug fixes and forgot the wizard was supposed to land there too.

Even ignoring the wizard miss: the CLI command itself is engineering-shaped. `--reason routine` makes sense to a developer who read the plan; to a customer it's noise. What's a "reason"? Why does it matter? What happens if I pick wrong?

---

## 6. Plugins tab is confused

Even after the rc.3 cleanup, the operator sees:

- A "Browse store →" button **that's disabled** because the store isn't live yet.
- A "Plugins" header with no explanation of what the plugins do for them.
- A list of "Scanners" (built-in collectors) and "Analyses" (built-in analyzers).
- An "Installed" section that includes my test data.

The operator can't:
- Run a plugin from the Plugins tab (Run buttons aren't there in the new view).
- Install a plugin from the Plugins tab (store disabled; sideload only via CLI).
- Tell which plugins are running automatically vs. only when invoked.
- Tell which plugins read sensitive data vs. metadata.

So the tab is **a read-only inventory of internal capabilities that the operator can't act on.** Why is it a tab at all?

---

## 7. The root mistake: I designed for plugin authors, not for end users

Going back to the original plan: I was building "the platform that hosts plugins." That's an SDK product. SDK products expose plugins, manifests, signing chains, capability summaries. The dashboard reflects that — it has tabs for the platform's *components*.

What MacCrab needs is a **product** that *happens to be built on* a plugin platform. End users buy MacCrab to keep their Macs safe. The plugin platform is plumbing. It should be invisible to operators most of the time.

Apple does this well: macOS uses plugins for everything (LaunchAgents, XPC services, kexts, sysexts). Operators almost never see the word "plugin" outside System Settings. They see the *capability* — "Privacy & Security", "Login Items", "Extensions" — and the plumbing is hidden.

MacCrab's Forensics workspace should mirror that. Operators see capabilities; never see "plugins" except when explicitly adding one from the store. The Plugins tab as it exists today shouldn't exist at all.

---

## 8. What to actually ship — the unfuck plan

Strip the Forensics workspace to **two tabs, both job-shaped:**

### Tab 1 — "Scans"

Only thing operators do here:
- See what scans have run.
- Start a new one.

**Empty state** when no scans:

```
Forensics

You haven't run a scan yet. A scan checks this Mac for signs of
compromise — bad launch items, suspicious quarantined files,
unfamiliar privacy permissions, code-signing anomalies, and more.

[ Run a quick scan ]      [ Custom scan… ]
```

**"Run a quick scan"** kicks off the standard set (TCC + launchd + posture + codesigning + quarantine) inline. Progress bar. Findings appear when done. No modal. No "use the CLI". Operator clicks the button and a scan runs.

**"Custom scan…"** opens a sheet with:
- Name (auto-suggested: "Quick scan — May 25 2026")
- Reason cards (Triage / Routine / Incident response / Just looking) — preselects the scanner set and privacy ceiling.
- Scanner list (preselected by reason; operator can toggle).
- Encryption choice (default: encrypted).
- "Start scan" button.

**Non-empty state** (you have scans): timeline of past scans. Each row: name, time ago, finding count, status. Click → detail view with findings + evidence + export.

### Tab 2 — "Findings"

The thing operators actually want.
- A merged feed of findings across all scans.
- Filter by severity / scan / scanner.
- Each finding has: what we found, when, why it matters, what to do about it.
- One-click export (a single finding → JSON, all findings → bundle).

### Things that DON'T have their own tab

- **Plugins** — moves to **Settings → Forensics → Scanners installed**. Operator-facing only when they're managing what's installed. Default view is just "MacCrab ships with N standard scanners. You can install more from the catalog." The catalog browser ALSO lives in Settings. Once you've installed something it shows in this list, but day-to-day the operator never touches this.
- **Evidence** — collapses into the scan-detail view. "Evidence" was always "the raw artifacts a scan collected" — that belongs inside a scan, not as a peer tab.
- **Tier B / Tier A** — gone. Operators never see those words anywhere.
- **Trust list management** — moves to Settings → Forensics → Trusted publishers. Operator-facing only when adding a third-party scanner.

### Internal rename

| Old | New (operator-visible) | New (internal class names) |
|---|---|---|
| Tier A | "Standard" or just nothing (it's the default) | `BuiltInPlugin` / `BuiltInRegistry` |
| Tier B | "Third-party" or "From the catalog" | `ExternalPlugin` / `PluginCatalog` |
| `plugins/tier-b/` on disk | `plugins/` (no subdir) | same |
| `TierBBootstrap` | n/a | `PluginCatalog` |
| `TierBRegistry` | n/a | `ExternalPluginRegistry` |
| `TierBManifest` | n/a | `PluginManifest` (collide with existing Tier A `PluginManifest` — rename one) |
| `TierBSubprocessLoader` (research) | n/a | `SubprocessPluginRuntime` |
| `tierb.list_plugins` (MCP) | n/a | `forensics.list_plugins` |
| `maccrabctl plugin trust/revoke/verify-all/daemon-status/installed-list` | n/a | `maccrabctl plugin {trust, revoke, verify, status, list --installed}` — but most don't need to exist in v1; trust management can be Settings-only |

The internal rename is a big patch but it's mechanical. Naming hygiene matters because every leaked class name shows up in the binary, in audit logs, in stack traces, in `strings` output, in operator-readable Console.app log messages.

### Test data residue

Whoever installs rc.3 has my dev pollution in `~/Library/Application Support/MacCrab/`. Either:

a) Ship a one-time **"Sample data found in your plugins directory. Remove?"** modal on first launch of v1.17 GA, OR
b) Ship a `maccrabctl maintenance clean-test-data` command that operators can run, OR
c) (Best) ship MacCrab's install path with a check: if the bundle's manifest is `com.test.*` or `com.maccrab.*-test`, ignore it on load + log a hint.

(c) is best — defensive, no operator action required.

### Don't ship features that don't work yet

- "Browse store →" — hide entirely until the catalog is live and we can browse it. Don't show a disabled button.
- "Export evidence bundle" — hide until rc.4 wires it. Don't show a disabled button.
- "Start a scan" wizard — don't ship the modal that says "use the CLI." Either ship the actual wizard, or don't ship the button.

A disabled button is worse than no button. Operators feel cheated.

---

## 9. Scope of the unfuck

This is **not** a small change. Here's what it actually takes:

### v1.17.0-rc.4 (next ship) — Forensics works end-to-end from the dashboard

1. **Reset operator-side scans surface** to 2 tabs (Scans / Findings), per §8 above. Delete the Plugins tab + Evidence tab. (Their content moves: plugin mgmt → Settings; evidence → inside scan detail.)
2. **Write the actual "Run a quick scan" flow** — button calls into PluginRunner, shows progress, surfaces findings when done. No CLI required.
3. **Write a real scan-detail view** — name + findings list + raw evidence (collapsed by default) + export button.
4. **Findings tab** — pulls findings from all completed scans + presents them as actionable items.
5. **Test data filter** — on dashboard load, hide any case named `*-smoke` / plugin id matching `com.test.*` / `com.research.*` etc. Log them in Console but don't render.
6. **Hide all disabled buttons** — better to omit than to tease.

### v1.17.0-rc.5 — Internal rename (no operator-visible change)

7. **Rename `TierB*` types** across `Sources/MacCrabForensics/TierB/` and `Sources/MacCrabApp/V2/`. New names per §8 table. Internal-only refactor.
8. **Rename `~/Library/Application Support/MacCrab/plugins/tier-b/` → `plugins/`** with a one-time migration on first launch.
9. **Rename MCP tools** — `tierb.*` → `forensics.*` with the v1.18-deprecation alias pattern.
10. **Rename log categories + subsystem strings** in `os.log` calls.

### v1.17.0-rc.6 — Catalog browser (when rave site is serving)

11. **Ship the catalog browser** in Settings → Forensics → Scanners. Real browse + install flow against `maccrab.com/rave/catalog/`.
12. **Hide the "Browse store →" button from Settings → Forensics → Scanners** until the catalog is reachable. Hide, not disable.

### v1.17.0 GA

13. Polish, locale snap, "What's new" callout, ship.

### What I drop from earlier plan

- The "Plugins" and "Evidence" tabs as designed in plan v2. They don't make sense as operator-facing tabs.
- The compliance preset scans (audit-E.1). Defer — get the basic flow working before adding presets.
- The plugin author scaffold (audit-E.2). Defer to v1.18 or later; author tooling isn't operator-facing.
- The "What's new in v1.17" callout (audit-E.3). Keep — it's small and high-value.

---

## 10. The hard question

The user has now told me three times that the Forensics delivery isn't shippable. I shipped three RCs claiming it was, and each time the user pushed back on real product gaps.

**Should I keep going with rc.4 = full operator-side rebuild, or should we pause forensics entirely and ship v1.17 as a CLI-only Forensics preview?**

Option A — **Rebuild rc.4 as proposed above.** Substantial scope. ~1-2 weeks of work even at this pace. Real product after.

Option B — **Pause Forensics dashboard. Ship v1.17 with only the CLI surface from rc.1 + the internal rename from rc.5.** The dashboard's Forensics workspace gets removed entirely for v1.17 — Forensics is a developer preview that runs via CLI only. The dashboard rebuild lands in v1.18.

I'd recommend **B**. Here's why:

- The dashboard is the customer-facing surface. Shipping it half-broken is worse than not shipping it. Operators see a broken Forensics workspace in the menubar and conclude the whole product is half-finished.
- The CLI surface is the operator-power-user / developer-preview surface. It's OK for that to be engineering-shaped — the audience knows.
- A v1.18 dashboard rebuild can take the time it actually needs without RC pressure. Right now we're shipping weekly. The wizard, findings tab, scan-detail view, settings reorg all want design + iteration time. Not a 4-hour ship cycle.
- The rave site work continues in parallel. By v1.18 we have a real catalog to integrate against, instead of mocking + stubbing.
- Operators with v1.17 get: working CLI scans, working detection (the existing v1.16 surface, untouched), working everything that already shipped. They don't get: half-baked dashboard tabs that disappoint.

The reframe: **v1.17 is the CLI Forensics release. The dashboard catches up in v1.18 when there's something real to ship.**

That's a real product decision. It needs sign-off.

---

## 11. Ask

Pick one:

- **A.** Rebuild rc.4 = full operator-side rebuild per §9. Multi-week. Then keep going through rc.5 / rc.6 / GA.
- **B.** Pause dashboard. Strip the Forensics workspace from MacCrabApp for v1.17. Internal rename ships in rc.5. v1.18 brings the dashboard back built for real.
- **C.** Something else you're thinking — tell me.

Whatever the answer, I'm not writing any more code until the path is decided. Three failed RCs is enough.
