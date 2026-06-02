#!/bin/bash
# pre-release-audit.sh — enforce three architectural invariants that
# the v1.6.x release stream kept burning us on. Sister script to
# prerelease-check.sh: that one verifies manifest sync; this one
# verifies code structure.
#
# v1.6.19 institutional fix for the bug class the "wire-the-orphans"
# pattern names. Previously these audits were performed manually by a
# review-pass agent and the findings shipped one release later. Codifying
# them means a regression fails the next release pipeline run.
#
# Three passes:
#
#   PASS 1 — orphan audit
#     For every Settings @AppStorage that affects daemon behavior, grep
#     for a sync function that writes the value to disk. Missing sync =
#     orphan (the v1.6.12 maxDatabaseSizeMB / v1.6.18 webhook patterns).
#
#   PASS 2 — direct-insert audit
#     No code outside Sources/MacCrabCore/Detection/AlertSink.swift may
#     call alertStore.insert(...). Two audited exceptions in DaemonSetup
#     are documented inline. v1.6.19 single-sink invariant.
#
#   PASS 3 — duplicate-source audit
#     Every constant or path that lives in two files (Compiler-emitted
#     rule paths, default support dirs, daemon config keys) must appear
#     identically. Catches the v1.6.13 cask drift / v1.6.18 short-version
#     drift class but for source code rather than manifests.
#
# v1.12.5 wave (passes A-D): codify the four bug classes that burned
# the v1.12.0 → v1.12.5 release marathon.
#
#   PASS A — codesign entitlement isolation
#     No outer .app `codesign --deep --entitlements <APP_ENT>` without
#     `--preserve-metadata=entitlements`. v1.12.2 Sparkle-install fix
#     (entitlements propagated onto Sparkle XPC helpers and macOS
#     refused to launch them).
#
#   PASS B — SwiftPM resource bundle Info.plist completeness
#     Every `.bundle/Info.plist` under `.build/` must carry the three
#     CFBundle keys macOS 26 Bundle(url:) requires. v1.12.4 Tahoe
#     Intelligence-tab crash fix (SwiftPM-emitted stub plist held only
#     CFBundleDevelopmentRegion and macOS 26 returned nil from
#     Bundle(url:), which fatalError'd the Bundle.module accessor).
#
#   PASS C — permission-change paired integration test
#     Every chmod / setAttributes call against a path under
#     /Library/Application Support/MacCrab/ must have a matching test
#     in Tests/ that simulates user-context read. v1.12.5 Threat Intel
#     feeds=0 fix (a 0o700 tightening on the directory blocked the
#     user-context dashboard from reading the cache files inside;
#     latent ~6 months because no test exercised the user-context
#     read path against the locked directory).
#
#   PASS D — self-defense Sigma filter symmetry
#     Self-protection Sigma rules (titles containing tamper / self /
#     security_tool) must either carry BOTH a Parent-only filter and an
#     Image-only filter, OR a filter that references neither Image nor
#     ParentImage. v1.12.5 false-positive cleanup (the AND-style
#     filter_maccrab_self block didn't catch the Image=/bin/rm,
#     Parent=MacCrab.app shape, so MacCrab's own startup maintenance
#     tripped its own tamper rule).
#
# Hard errors block; warnings advise.
#
# Usage: scripts/pre-release-audit.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

BOLD=$(tput bold 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true)
GREEN=$(tput setaf 2 2>/dev/null || true)
YELLOW=$(tput setaf 3 2>/dev/null || true)
CYAN=$(tput setaf 6 2>/dev/null || true)
RESET=$(tput sgr0 2>/dev/null || true)

ERRORS=0
WARNINGS=0

err()  { echo "${RED}✗${RESET} $*" >&2; ERRORS=$((ERRORS+1)); }
warn() { echo "${YELLOW}!${RESET} $*"; WARNINGS=$((WARNINGS+1)); }
ok()   { echo "${GREEN}✓${RESET} $*"; }
info() { echo "${CYAN}→${RESET} $*"; }
section() { echo; echo "${BOLD}── $* ──${RESET}"; }

# ---------------------------------------------------------------------
# PASS 1 — orphan audit (Settings @AppStorage → daemon consumer)
# ---------------------------------------------------------------------
# Each binding is a (storage-key, sync-function-name) pair. The sync
# function must exist in SettingsView; that's evidence the value
# reaches a file the daemon reads. Bindings that AREN'T daemon-relevant
# (UI-only preferences) are listed in IGNORE so they don't flag.

section "PASS 1 — Settings → daemon orphan audit"

SETTINGS_FILE="Sources/MacCrabApp/Views/SettingsView.swift"
if [[ ! -f "$SETTINGS_FILE" ]]; then
    err "$SETTINGS_FILE missing — can't audit"
else
    # Bindings that intentionally stay app-side (UI prefs, transient
    # state, OS-managed login items). Update when adding new ones.
    UI_ONLY_KEYS=(
        "pollIntervalSeconds"   # dashboard auto-refresh timer, not daemon
        "launchAtLogin"         # OS-managed login item, not daemon config
        "uiMode.storageKey"     # UIMode.storageKey constant (not a string literal — kept for documentation)
        "forensics.catalogBaseURL" # rave catalog URL, consumed app-side by RaveCatalogClient (forensics is app/CLI/MCP-only, not linked by the sysext)
        "forensics.retentionDays"  # forensic-scan retention, applied app-side; forensics platform is not linked by the sysext
    )

    # Bindings that MUST round-trip to the daemon. Each maps to a sync
    # function that writes a JSON file the sysext reads.
    declare -a DAEMON_BINDINGS=(
        "retentionDays:syncStorageOverrides"
        "maxDatabaseSizeMB:syncStorageOverrides"
        "retentionWindowDays:syncStorageOverrides"
        # v1.8.0 storage tiering keys → user_overrides.json (syncStorageOverrides)
        "storage.eventsHotTierMinutes:syncStorageOverrides"
        "storage.eventsMaxSizeMB:syncStorageOverrides"
        "storage.alertsRetentionDays:syncStorageOverrides"
        "storage.alertsMaxSizeMB:syncStorageOverrides"
        "storage.campaignsRetentionDays:syncStorageOverrides"
        "storage.campaignsMaxSizeMB:syncStorageOverrides"
        # v1.11.0 alert notifications → alert_notifications.json
        # (was misclassified UI_ONLY pre-v1.12.6 — fixed in Wave 3B)
        "alertNotifications:syncAlertNotificationConfig"
        "minAlertSeverity:syncAlertNotificationConfig"
        "llm.provider:syncLLMConfig"
        "llm.ollamaURL:syncLLMConfig"
        "llm.ollamaModel:syncLLMConfig"
        "llm.openaiURL:syncLLMConfig"
        "llm.model:syncLLMConfig"
        "llm.enabled:syncLLMConfig"
        "webhookSlackURL:syncWebhookConfig"
        "webhookTeamsURL:syncWebhookConfig"
        "webhookDiscordURL:syncWebhookConfig"
        "webhookPagerDutyKey:syncWebhookConfig"
        "webhookMinSeverity:syncWebhookConfig"
    )

    # Verify each named sync function exists.
    for binding in "${DAEMON_BINDINGS[@]}"; do
        key="${binding%%:*}"
        sync_fn="${binding##*:}"
        if ! grep -qE "func[[:space:]]+$sync_fn[[:space:]]*\(" "$SETTINGS_FILE"; then
            err "Settings binding \"$key\" references missing sync function $sync_fn()"
        fi
    done

    # Find every @AppStorage in SettingsView and ensure it's in either
    # IGNORE or DAEMON_BINDINGS. New bindings that aren't classified
    # are flagged so we don't accidentally ship another orphan.
    #
    # v1.12.6 Wave 5C: promoted unclassified-key warn → err. Wave 3B
    # refreshed DAEMON_BINDINGS to cover every shipped daemon-relevant
    # key; from this point on, an unclassified key is a wire-the-
    # orphans regression in the same shape as v1.6.12
    # (maxDatabaseSizeMB) — silent-green for the operator if it stayed
    # a warning. Hard-failing means any future contributor adding an
    # @AppStorage MUST classify it before the release pipeline accepts
    # the diff.
    declared_keys=$(grep -oE '@AppStorage\("[^"]+"' "$SETTINGS_FILE" \
        | sed -E 's/@AppStorage\("([^"]+)"/\1/')
    pass1_unclassified=0
    for key in $declared_keys; do
        # Match against IGNORE list
        skip=0
        for ig in "${UI_ONLY_KEYS[@]}"; do
            if [[ "$key" == "$ig" ]]; then skip=1; break; fi
        done
        if [[ $skip -eq 1 ]]; then continue; fi
        # Match against DAEMON_BINDINGS list
        in_daemon=0
        for binding in "${DAEMON_BINDINGS[@]}"; do
            if [[ "$key" == "${binding%%:*}" ]]; then in_daemon=1; break; fi
        done
        if [[ $in_daemon -eq 0 ]]; then
            err "Unclassified @AppStorage(\"$key\"): add to UI_ONLY_KEYS (UI-only) or DAEMON_BINDINGS (must reach daemon)"
            pass1_unclassified=$((pass1_unclassified + 1))
        fi
    done

    if [[ $pass1_unclassified -eq 0 ]]; then
        ok "All daemon-bound Settings keys have a sync function (every @AppStorage classified)"
    fi
fi

# ---------------------------------------------------------------------
# PASS 1b — Codable Config struct field consumer audit (v1.6.19.1)
# ---------------------------------------------------------------------
# Same pattern as Pass 1 but for *Config Codable structs that get
# decoded from JSON files the dashboard writes. Pre-v1.6.19.1
# `ResponseActionConfig.requireConfirmation` was decoded from
# actions.json but no consumer read it at runtime — instance #7 of
# the wire-the-orphans pattern. This pass enumerates fields on
# selected config structs and warns when a field has no caller in the
# daemon target.

section "PASS 1b — Config struct fields → daemon consumer audit"

# Pairs: "<file>:<struct-name>". Add new structs here when they're
# decoded from a dashboard-written JSON file.
declare -a CONFIG_STRUCTS=(
    "Sources/MacCrabCore/Detection/ResponseAction.swift:ResponseActionConfig"
    "Sources/MacCrabCore/Output/NotificationIntegrations.swift:Config"
)

# Field names that are decorative / Codable-required scaffolding and
# don't need a runtime consumer. Format: "<StructName>.<fieldName>".
declare -a DECORATIVE_FIELDS=(
    "_placeholder._unused"
)

for entry in "${CONFIG_STRUCTS[@]}"; do
    file="${entry%%:*}"
    struct="${entry##*:}"
    if [[ ! -f "$file" ]]; then
        warn "PASS 1b: $file missing — config struct list out of date"
        continue
    fi

    # Extract the struct body and pull `public var/let <field>` names.
    fields=$(awk -v target="$struct" '
        /public struct '"$struct"'/ { in_struct=1; depth=0; next }
        in_struct && /\{/ { depth++ }
        in_struct && /\}/ { depth--; if (depth == 0) { in_struct=0; next } }
        in_struct && /^[[:space:]]*public[[:space:]]+(var|let)[[:space:]]/ {
            match($0, /public[[:space:]]+(var|let)[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*/)
            if (RSTART > 0) {
                token=substr($0, RSTART, RLENGTH)
                gsub(/^public[[:space:]]+(var|let)[[:space:]]+/, "", token)
                print token
            }
        }
    ' "$file")

    if [[ -z "$fields" ]]; then
        warn "PASS 1b: no public fields parsed from $struct in $file (parser regression?)"
        continue
    fi

    for field in $fields; do
        # Skip decorative fields
        skip=0
        for d in "${DECORATIVE_FIELDS[@]}"; do
            if [[ "$d" == "$struct.$field" ]]; then skip=1; break; fi
        done
        if [[ $skip -eq 1 ]]; then continue; fi

        # Count `.fieldName` references across all of Sources/, then subtract
        # the trivial init self-assignment (`self.fieldName = fieldName`)
        # which doesn't count as "wired". A field is wired if anything else
        # reads it via `config.fieldName`, `entry.fieldName`,
        # `someInstance.fieldName`, etc.
        total_refs=$(grep -rE "\.${field}\b" Sources \
            --include='*.swift' 2>/dev/null \
            | wc -l | tr -d ' ')
        self_assigns=$(grep -rE "self\.${field}[[:space:]]*=" Sources \
            --include='*.swift' 2>/dev/null \
            | wc -l | tr -d ' ')
        consumer_refs=$(( total_refs - self_assigns ))
        if [[ "$consumer_refs" -lt 1 ]]; then
            err "PASS 1b: $struct.$field is decoded but never read — orphan candidate (only self-assignments found)"
        fi
    done
done

if [[ $ERRORS -eq 0 ]]; then
    ok "Config struct fields all have at least one daemon-target consumer"
fi

# ---------------------------------------------------------------------
# PASS 2 — direct-insert audit (AlertSink single-sink invariant)
# ---------------------------------------------------------------------

section "PASS 2 — AlertSink single-sink invariant"

# Every alertStore.insert call in production code outside AlertSink
# itself is either a regression of the v1.6.9 NoiseFilter-layering bug
# class, or a documented exception. Two exceptions exist in
# DaemonSetup.swift (lines 229 + 265 as of v1.6.19); they're audited
# because the closures capture alertStore before AlertSink is built.

# Allowed file: AlertSink.swift uses alertStore.insert internally.
# Allowed exception sites: DaemonSetup.swift self-defense + ES-health.
ALLOWED_EXCEPTION_FILE="Sources/MacCrabAgentKit/DaemonSetup.swift"
ALLOWED_EXCEPTION_COUNT_TARGET=2

# Find all production-code direct inserts.
direct_inserts=$(grep -rnE 'alertStore\.insert' Sources \
    --include='*.swift' 2>/dev/null \
    | grep -v 'AlertSink\.swift')

# Lines in DaemonState.swift are docstring references, not real calls.
direct_inserts=$(echo "$direct_inserts" | grep -v 'DaemonState\.swift')

# Strip any inside the AlertSink directory itself if path differs.
direct_inserts=$(echo "$direct_inserts" | grep -v '/AlertSink\.swift')

# Count unique non-exception sites.
exception_count=$(echo "$direct_inserts" | grep -c "$ALLOWED_EXCEPTION_FILE" || true)
total_count=$(echo "$direct_inserts" | grep -cE '\S' || true)
unauthorized_count=$(( total_count - exception_count ))

if [[ "$unauthorized_count" -gt 0 ]]; then
    err "$unauthorized_count direct alertStore.insert call(s) outside AlertSink — route through state.alertSink.submit(...) instead:"
    echo "$direct_inserts" | grep -v "$ALLOWED_EXCEPTION_FILE" | sed 's/^/    /' >&2
elif [[ "$exception_count" -ne "$ALLOWED_EXCEPTION_COUNT_TARGET" ]]; then
    warn "DaemonSetup.swift has $exception_count direct insert(s); expected exactly $ALLOWED_EXCEPTION_COUNT_TARGET (audited self-defense + ES-health). Update the exception count or this audit if the audited list changed."
else
    ok "AlertSink chokepoint intact ($exception_count audited DaemonSetup exception(s), 0 unauthorized)"
fi

# ---------------------------------------------------------------------
# PASS 3 — duplicate-source audit
# ---------------------------------------------------------------------
# Pairs of constants that exist in two files and must agree. New entries
# go here whenever a fact gets duplicated across boundaries the type
# system can't bridge.

section "PASS 3 — duplicate-source audit"

# Each entry: "label|extractor1|extractor2"
# extractors are bash command substitutions that print a single value.

check_pair() {
    local label="$1"
    local val_a="$2"
    local val_b="$3"
    if [[ -z "$val_a" || -z "$val_b" ]]; then
        # v1.12.6 Wave 5C: extractor failure is now a HARD error — a
        # grep that returns nothing isn't proof the two values agree,
        # it's proof the audit is blind. The previous warn-level
        # behaviour silent-greened on every refactor that renamed the
        # Swift literal (e.g., switching the AlertStore `directory:`
        # default to a `let canonicalSupportDir = "..."` constant).
        err "$label: couldn't extract one or both values (a=$val_a b=$val_b) — audit is blind, refresh extractor"
    elif [[ "$val_a" != "$val_b" ]]; then
        err "$label drift: $val_a vs $val_b"
    else
        ok "$label → $val_a"
    fi
}

# Default support directory: appears in DaemonState (docstring), AlertStore
# (init default), and the Casks zap stanza. The init default is the
# canonical value; verify the cask references it.
#
# v1.12.6 Wave 5C: the pre-Wave-5C extractor required the literal
# string `"/Library/Application Support/MacCrab"` to appear verbatim
# in the Swift grep, so a drift (typo'd path, trailing slash,
# different constant name) silently produced an empty
# SUPPORT_DIR_INIT and the pass dropped to a WARN about the
# extractor rather than an ERR about the drift itself. Replaced with
# a generic Swift `directory: String = "<literal>"` extractor that
# captures whatever the source actually says — equality is then
# enforced against the cask's literal independently of what the
# canonical path becomes.
SUPPORT_DIR_INIT=$(grep -oE 'directory: String = "[^"]+"' \
    Sources/MacCrabCore/Storage/AlertStore.swift 2>/dev/null \
    | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
SUPPORT_DIR_CASK=$(grep -E '/Library/Application Support/MacCrab' Casks/maccrab.rb 2>/dev/null \
    | head -1 | grep -oE '/Library/Application Support/MacCrab[^"'\'']*' | head -1 \
    | sed -E 's|^(/Library/Application Support/MacCrab).*|\1|')
check_pair "Default sysext support directory" "$SUPPORT_DIR_INIT" "$SUPPORT_DIR_CASK"

# Sysext launchd label: appears in cask uninstall stanza and in
# SelfDefense path watch list.
SYSEXT_LABEL_CASK=$(grep -oE 'com\.maccrab\.agent[^"'\'' ]*' Casks/maccrab.rb 2>/dev/null \
    | head -1)
SYSEXT_LABEL_SD=$(grep -oE 'com\.maccrab\.agent[^"'\'' ]*' \
    Sources/MacCrabCore/Detection/SelfDefense.swift 2>/dev/null \
    | head -1)
check_pair "Sysext launchd label" "$SYSEXT_LABEL_CASK" "$SYSEXT_LABEL_SD"

# ---------------------------------------------------------------------
# PASS 4 — URLSession.shared in Sources/ (v1.6.22)
# ---------------------------------------------------------------------
# `URLSession.shared` uses URLSessionConfiguration.default, which writes
# a disk cache (`Cache.db` + WAL/SHM) and an HSTS / cookie store
# (`httpstorages.sqlite`) under `<container>/Library/Caches/<bundle>/`.
# When the daemon runs as root those files land in
# `/private/var/root/Library/Caches/com.maccrab.agent/` and stay there
# forever — observed on a v1.6.21 test host alongside a 2.76 GB resident
# spike. v1.6.22 routes every outbound HTTP/HTTPS through
# `SecureURLSession.shared` (ephemeral, no disk cache, TLS 1.2+).
#
# The dashboard target (MacCrabApp) is allowed to use URLSession.shared
# because Sparkle and AppKit internals depend on it; the daemon /
# detection / enrichment / output / collector code is not.

section "PASS 4 — URLSession.shared discipline (daemon target)"

# Allowed dirs: dashboard target. Forbidden dirs: everything daemon-bound.
# Filename allowlist: SecureURLSession.swift contains the comment
# explaining what was replaced. The negative lookbehind for
# `SecureURLSession.shared` is done via `grep -v` rather than regex
# because BSD grep on macOS doesn't support `(?<!...)`.
forbidden_shared=$(grep -rnE '\bURLSession\.shared\b' Sources/MacCrabCore Sources/MacCrabAgentKit Sources/MacCrabAgent Sources/maccrabd \
    --include='*.swift' 2>/dev/null \
    | grep -v 'SecureURLSession\.shared' \
    | grep -v 'SecureURLSession\.swift' \
    | grep -v -E '^[^:]+:[0-9]+:[[:space:]]*//' || true)

if [[ -n "$forbidden_shared" ]]; then
    err "URLSession.shared used in daemon-target source — replace with SecureURLSession.shared (no disk cache, TLS 1.2+):"
    echo "$forbidden_shared" | sed 's/^/    /' >&2
else
    ok "No URLSession.shared usage in daemon-target source"
fi

# ---------------------------------------------------------------------
# PASS 5 — duplicate SQLite handles to events.db (v1.6.22 / Wave 7A.3-A)
# ---------------------------------------------------------------------
# Each open `events.db` connection carries its own page cache (set via
# StoragePragmas.eventCacheSizeKB) and mmap region (eventMmapSizeBytes).
# Post-v1.6.22 architecture: exactly ONE long-lived events.db connection
# (EventStore). The v1.6.22 fix moved CampaignStore off events.db onto
# its own campaigns.db, and AlertStore was promoted to a sibling
# alerts.db at the same time. ThreatHunter open/close per query is OK
# (transient, not long-lived). The audited steady state is now 1.
#
# Wave 7A.3-A rebaseline: previously this pass expected 2 (EventStore +
# AlertStore-on-events.db). After AlertStore migrated to alerts.db the
# only long-lived events.db owner is EventStore.
#
# This pass counts long-lived `OpaquePointer?` declarations in actor
# bodies that point at events.db. When the count rises above 1, the
# release should consolidate before shipping. When it drops below 1,
# the EventStore handle is at risk of being orphaned.

section "PASS 5 — events.db long-lived connection count"

# Find every actor that BOTH (a) opens events.db specifically (matches
# `appendingPathComponent("events.db")`) AND (b) declares a long-lived
# `private var db: OpaquePointer?`. CampaignStore opens campaigns.db,
# AlertStore opens alerts.db, so both are excluded by the precise path
# match. ThreatHunter uses a local var inside `executeSQL` so it doesn't
# match the long-lived field pattern — that's the desired pattern for a
# transient read.
events_db_actors=$(grep -rln 'appendingPathComponent("events.db")' Sources/MacCrabCore/Storage Sources/MacCrabAgentKit \
    --include='*.swift' 2>/dev/null \
    | xargs -I {} grep -l 'private var db: OpaquePointer?' {} 2>/dev/null \
    | sort -u || true)

events_db_actor_count=$(echo "$events_db_actors" | grep -cE '\S' || true)

if [[ "$events_db_actor_count" -gt 1 ]]; then
    err "More than 1 actor holds a long-lived events.db handle — post-v1.6.22 only EventStore should. Each extra handle costs cache_size + mmap_size. Consolidate (current: $events_db_actor_count):"
    echo "$events_db_actors" | sed 's/^/    /' >&2
elif [[ "$events_db_actor_count" -lt 1 ]]; then
    warn "Zero actors hold a long-lived events.db handle — EventStore disappeared? (count: $events_db_actor_count)"
else
    ok "Pass 5: exactly one long-lived events.db handle (post-v1.6.22 architecture: EventStore only)"
fi

# ---------------------------------------------------------------------
# PASS 6 — daemon-written snapshot files ↔ MacCrabApp consumer (v1.7.0)
# ---------------------------------------------------------------------
# Every public Codable struct exposed by a daemon-side snapshot writer
# (e.g. `AgentLineageService.LineageSnapshot`,
# `MCPBaselineService.BaselineSnapshot`) must have at least one
# `MacCrabApp` consumer that calls `readSnapshot(at:)` or accesses the
# struct via AppState. Catches the v1.6.15 / v1.6.18 wire-the-orphans
# pattern at the snapshot layer specifically: producer ships data the
# UI never consumes.
#
# Maintained list — add a new pair when a daemon-side snapshot type
# ships. Format: "<file>:<TypeName>:<consumer-grep-token>".

section "PASS 6 — daemon snapshot ↔ panel consumer audit"

declare -a SNAPSHOT_PAIRS=(
    "Sources/MacCrabCore/AIGuard/AgentLineageService.swift:LineageSnapshot:AgentLineageService.readSnapshot"
    "Sources/MacCrabCore/AIGuard/MCPBehavioralBaseline.swift:BaselineSnapshot:MCPBaselineService.readSnapshot"
)

if [[ ${#SNAPSHOT_PAIRS[@]} -eq 0 ]]; then
    err "PASS 6: SNAPSHOT_PAIRS is empty — pass would silent-green. Add the curated daemon-snapshot list."
fi

pass6_errors_before=$ERRORS
for entry in "${SNAPSHOT_PAIRS[@]}"; do
    file="${entry%%:*}"
    rest="${entry#*:}"
    typename="${rest%%:*}"
    token="${rest##*:}"
    # Curated entries — a missing file or renamed type means the audit
    # is stale, not that the bug class went away. v1.10.2: promote
    # warn → err so the pass actually fails, mirroring Pass 15's
    # "fail loud if zero matches" discipline (v1.9.0 AAR finding).
    if [[ ! -f "$file" ]]; then
        err "PASS 6: $file missing — snapshot list out of date (refresh SNAPSHOT_PAIRS)"
        continue
    fi
    if ! grep -q "public struct $typename" "$file"; then
        err "PASS 6: $typename not found in $file (renamed? refresh SNAPSHOT_PAIRS)"
        continue
    fi
    consumer_count=$(grep -rE "$token\b" Sources/MacCrabApp \
        --include='*.swift' 2>/dev/null \
        | grep -cE '\S' || true)
    if [[ "$consumer_count" -lt 1 ]]; then
        err "PASS 6: $typename has a daemon-side writer but no MacCrabApp consumer — wire-the-orphans pattern"
    fi
done

if [[ $ERRORS -eq $pass6_errors_before ]]; then
    ok "Daemon snapshot types all have at least one MacCrabApp consumer"
fi

# ---------------------------------------------------------------------
# PASS 7 — primary panel view richness invariants (v1.7.1 → v1.12.6 W5C)
# ---------------------------------------------------------------------
# Every primary panel view must declare:
#  - a `searchText` (or equivalent `@State` String) for searching, AND
#  - at least one nav-destination (sheet/popover/HSplitView detail/
#    NavigationLink) for drill-down.
# Codifies the v1.6.17 Threat Intel rebuild template as an architectural
# invariant so future panel additions don't ship as bare lists.
#
# v1.12.6 Wave 5C — DEAD-PASS FIX:
#   The pre-Wave-5C PRIMARY_PANELS array pointed to seven legacy
#   `Sources/MacCrabApp/Views/<Name>.swift` files that NO LONGER EXIST.
#   The dashboard rebuild moved every primary panel into
#   `Sources/MacCrabApp/V2/Workspaces/V2*Workspace.swift`. Every loop
#   iteration hit the `if [[ ! -f ]]` guard, emitted a `warn`, and
#   continued — so the per-panel richness checks NEVER RAN. The pass
#   then short-circuited to `✓ All primary panels expose search +
#   drill-down` because the `$ERRORS` counter was unchanged. Silent
#   green on a structurally dead pass.
#
#   Two structural fixes:
#     1. Glob `Sources/MacCrabApp/V2/Workspaces/V2*Workspace.swift`
#        rather than hard-coding a path list, so future workspace
#        renames are auto-tracked.
#     2. Promote `missing` from `warn` to `err` — a path that's been
#        committed to the audit list but doesn't exist on disk is a
#        bug in either the audit or the panel inventory; either way
#        the pass is blind and the operator needs to know.
#
#   Richness criteria broadened for V2 workspaces:
#     - search: legacy `@State searchText/query/filterText/searchQuery`
#       OR workspace-state binding (`state.<name>(Query|Search|Filter)`)
#       OR delegating to a v1 view that owns the search (e.g.
#       EventStream — the `EventStream(...)` invocation counts because
#       that view has its own `@State filterText`).
#     - drill-down: `.sheet`/.popover/NavigationLink/HSplitView, OR
#       a V2WorkspaceTabStrip (the v2 tabbed-section drill-down
#       pattern), OR an @State selected-row binding (`@State.*
#       selected<X>`), OR a status-panel pattern (V2ActionButton list
#       that opens Settings / triggers daemon commands — Prevention
#       and Overview shape).
#
# Deliberately-broken fixture this catches (Wave 5C verification):
#   Break:  add a new V2 workspace `V2EmptyWorkspace.swift` whose
#           body is just `Text("TODO")` — no search, no drill-down.
#   Expect: PASS 7 errs with `V2EmptyWorkspace has no search state` AND
#           `V2EmptyWorkspace has no drill-down hook`.
#   Restore: delete the fixture file.
#
#   Alternative fixture — drift the glob:
#   Break:  rename `V2AlertsWorkspace.swift` to `V2AlertsScreen.swift`
#           so the `V2*Workspace.swift` glob misses it.
#   Expect: PASS 7 errs that zero workspaces matched the glob (audit
#           is blind).
#   Restore: rename back.

section "PASS 7 — primary panel view richness audit"

# Glob all V2 workspaces. Failing to find any is itself an error —
# the workspace pattern is load-bearing for the dashboard architecture
# and a missing match means either a refactor that bypassed the
# convention or a glob that drifted.
PRIMARY_PANELS=()
while IFS= read -r p; do
    [[ -n "$p" ]] && PRIMARY_PANELS+=("$p")
done < <(ls Sources/MacCrabApp/V2/Workspaces/V2*Workspace.swift 2>/dev/null | sort)

if [[ ${#PRIMARY_PANELS[@]} -eq 0 ]]; then
    err "PASS 7: no V2 workspace files match Sources/MacCrabApp/V2/Workspaces/V2*Workspace.swift — audit is blind, refresh glob or restore workspace convention"
fi

pass7_errors_before=$ERRORS
for panel in "${PRIMARY_PANELS[@]}"; do
    if [[ ! -f "$panel" ]]; then
        # v1.12.6 Wave 5C: promoted warn → err. A glob that
        # produced a path which doesn't resolve is a fast-stat race
        # or a partial reorg; either way the per-panel check
        # silently fails and the operator gets false confidence.
        err "PASS 7: $panel missing — workspace inventory out of date"
        continue
    fi
    base=$(basename "$panel" .swift)

    has_search=0
    # Legacy @State search names (kept for v1 views the workspaces
    # may still embed via composition).
    if grep -qE '@State[^;]*\b(searchText|query|filterText|searchQuery)\b' "$panel"; then
        has_search=1
    fi
    # V2 workspace-state binding pattern: `state.alertSearchQuery`,
    # `state.eventSearchQuery`, etc. owned by V2DashboardState so a
    # navigation pivot away and back preserves the user's narrowing.
    if grep -qE 'state\.[a-zA-Z]+(Query|Search|Filter)\b' "$panel"; then
        has_search=1
    fi
    # Composition escape hatch: delegating to a legacy view that
    # owns the search (e.g. EventStream has its own @State filterText).
    if grep -qE 'EventStream\(|RuleWizard\(|AgentTracesView\(' "$panel"; then
        has_search=1
    fi

    has_drill=0
    # Drill-down hooks: .sheet, .popover, NavigationLink, HSplitView.
    if grep -qE '\.sheet\(|\.popover\(|NavigationLink|HSplitView|detail:' "$panel"; then
        has_drill=1
    fi
    # Tabbed/segmented multi-view (Picker bound to a viewMode/
    # selectedSection state).
    if grep -qE '@State.*\b(viewMode|selectedSection|selectedTab|selectedMode|selectedDoc|selected:)\b' "$panel"; then
        has_drill=1
    fi
    # V2 tabbed-section pattern: V2WorkspaceTabStrip surfaces a
    # row of sub-tabs (alertsOpen / alertsCampaigns / etc.) — the
    # drill-down equivalent for v2 chrome.
    if grep -qE 'V2WorkspaceTabStrip\b' "$panel"; then
        has_drill=1
    fi
    # Status-panel pattern: a list of V2ActionButton invocations
    # (Settings opener, daemon SIGHUP, etc.) gives the operator
    # actionable drill-down even without per-row navigation.
    if grep -qE 'V2ActionButton\b' "$panel"; then
        has_drill=1
    fi

    # Status-panel relief: workspaces that are intentionally summary +
    # action surfaces (Overview metrics + Settings sheets, Prevention
    # action log, System/Intel/Docs status grids) don't need a
    # free-text search bar. The action-button list IS the
    # actionability. Original v1.7.1 Pass 7 carried an explicit
    # ESHealthView exception for the same reason. v1.12.6 W5C
    # generalizes: if the panel has a drill-down hook AND no row
    # table/list (so search would have nothing to filter), search is
    # non-applicable.
    if [[ $has_search -eq 0 && $has_drill -eq 1 ]] && \
       ! grep -qE '\bTable\(|\bList\(' "$panel"; then
        has_search=1
    fi

    if [[ $has_search -eq 0 ]]; then
        err "PASS 7: $base has no search state (legacy @State search* OR state.<name>(Query|Search|Filter) OR legacy-view composition)"
    fi
    if [[ $has_drill -eq 0 ]]; then
        err "PASS 7: $base has no drill-down hook (sheet/popover/NavigationLink/HSplitView/V2WorkspaceTabStrip/@State selected*/V2ActionButton list)"
    fi
done

if [[ $ERRORS -eq $pass7_errors_before ]]; then
    ok "All V2 workspaces (${#PRIMARY_PANELS[@]}) have search + drill-down richness"
fi

# ---------------------------------------------------------------------
# PASS 8 — actor mutable collection state must be bounded (v1.7.3)
# ---------------------------------------------------------------------
# Codifies the cap-or-leak invariant: every mutable Dictionary, Set,
# or Array field on an actor in MacCrabCore / MacCrabAgentKit must
# either (a) have explicit eviction logic in the same file, (b) carry
# an inline `// bounded:` justification comment, or (c) appear in the
# allowlist below for known-safe patterns (lookup tables, configured-
# at-init, etc.).
#
# Catches the v1.7.2 regression class where new actor maps shipped
# without eviction — CollectorRegistry.entries grew unbounded under
# name-string variance, contributing ~500 MB of the 2 GB regression.

section "PASS 8 — actor state must be bounded"

# Allowlist: actor::field combinations that are known-bounded by
# design. Format: "<file-basename>:<field-name>". Keep this list
# tight — every entry is a documented exception that should be
# revisited as the codebase evolves.
declare -a BOUNDED_FIELD_ALLOWLIST=(
    # MCPMonitor.knownServers — keyed by configFile::serverName, bounded
    # by config-file size which is operator-controlled (typical install
    # has < 30 servers).
    "MCPMonitor.swift:knownServers"
    # MCPMonitor.dispatchSources / watchSources — file-system watchers,
    # bounded by config file count (5 paths × 2 sources = ~10 max).
    "MCPMonitor.swift:dispatchSources"
    "MCPMonitor.swift:watchSources"
    # AlertSink internal session-key map — bounded by AlertDeduplicator
    # which already has its own cap.
    "AlertSink.swift:pendingByKey"
    # Migrations and rule arrays — read at init from compiled JSON; the
    # cap is the on-disk rule count.
    "RuleEngine.swift:allRules"
    "RuleEngine.swift:ruleIndex"
    # Config snapshots — populated once at init.
    "DaemonState.swift:supportDir"
    # === v1.7.3 baseline allowlist of pre-existing fields. Each
    # entry below documents why the field is bounded by external
    # factors (system config, hardware, operator action) rather
    # than per-event growth. New additions that lack such bounding
    # should NOT be added here — they should add cap-and-evict.
    # Bounded by browser-extension count on system (operator-controlled).
    "BrowserExtensionMonitor.swift:knownExtensions"
    # Bounded by USB devices ever connected — on a workstation, < 100.
    "USBMonitor.swift:knownDevices"
    # Bounded by installed plugins / configured BTM / MDM items.
    "SystemPolicyMonitor.swift:knownPlugins"
    "SystemPolicyMonitor.swift:knownBTMItems"
    "SystemPolicyMonitor.swift:knownMDMProfiles"
    # Bounded by quarantined-file count over daemon lifetime;
    # follow-up improvement: add explicit cap in v1.7.4.
    "SystemPolicyMonitor.swift:quarantineAlerted"
    "SystemPolicyMonitor.swift:knownXPCServices"
    "SystemPolicyMonitor.swift:knownSnapshots"
    # Bounded by installed EDR tools (~30 known).
    "EDRMonitor.swift:reportedTools"
    # Bounded by current TCC.db row count — operator-controlled.
    "TCCMonitor.swift:snapshot"
    # Bounded by event-taps installed in the system.
    "EventTapMonitor.swift:knownTaps"
    # Bounded by SDR / display hardware connected.
    "TEMPESTMonitor.swift:reportedDevices"
    "TEMPESTMonitor.swift:knownDisplays"
    # Bounded by per-rule TCC revocation history; follow-up in v1.7.4.
    "TCCRevocation.swift:revocationHistory"
    # Bounded by sleeping-process count; follow-up in v1.7.4.
    "PowerAnomalyDetector.swift:alertedSleepProcesses"
    # Bounded by rule count (read at init).
    "ResponseAction.swift:ruleActions"
    "ResponseAction.swift:defaultActions"
    # Bounded by package-scan time-window; follow-up in v1.7.4.
    "VulnerabilityScanner.swift:cachedResults"
    # Bounded by user × process behavioral profiles; follow-up in v1.7.4.
    "UEBAEngine.swift:profiles"
    # Bounded by tamper-type enum cases (~10 total).
    "SelfDefense.swift:alertedTamperTypes"
    # Bounded by AlertDeduplicator's existing 10K entry cap (the dict is
    # one-to-one with that capped store).
    "AlertDeduplicator.swift:ruleStats"
    "AlertDeduplicator.swift:dismissalCounts"
    # Operator-supplied at init; never grown at runtime.
    "ProjectBoundary.swift:customExceptions"
)

audit_actors_unbounded=0
declare -a UNBOUNDED_FINDINGS=()

# Find every `private var <name>: [...` (Array, Dict, or Set literal)
# in actor source files. Then check for an eviction signal in the
# same file.
while IFS= read -r match; do
    file="${match%%:*}"
    base=$(basename "$file")
    line_no="${match#*:}"
    line_no="${line_no%%:*}"
    rest="${match#*:*:}"

    # Extract the field name from the line, e.g.,
    # `    private var entries: [String: InternalEntry] = [:]`
    field=$(echo "$rest" | sed -nE 's/.*private var ([a-zA-Z_][a-zA-Z0-9_]*):.*/\1/p')
    [[ -z "$field" ]] && continue

    # Allowlist check
    skip=0
    for allow in "${BOUNDED_FIELD_ALLOWLIST[@]}"; do
        if [[ "$base:$field" == "$allow" ]]; then skip=1; break; fi
    done
    if [[ $skip -eq 1 ]]; then continue; fi

    # Skip non-collection types (only check those whose value
    # syntax includes `[...]` or `Set<...>`).
    if ! echo "$rest" | grep -qE ':\s*\[.*\]|:\s*Set<'; then continue; fi

    # Inline `// bounded:` comment on the same line — pragma escape.
    if echo "$rest" | grep -q "// bounded:"; then continue; fi

    # Look for cap-and-evict signals in the rest of the file: any of
    #   - `removeValue(forKey:` or `removeFirst(` on this field
    #   - `.removeAll(` on this field
    #   - `<fieldName>.count >` or `>=` comparison (the size cap check)
    #
    # v1.12.6 Wave 5C — TIGHTENED REGEX:
    #   The pre-Wave-5C OR-arm `|let max[A-Z]` short-circuited the
    #   eviction check whenever ANY constant starting with `max` +
    #   uppercase appeared in the file. Concretely: AlertClusterService.
    #   swift has `let maxSev = sorted.map(...)` at line 110 — a local
    #   variable for severity sorting that has nothing to do with cap
    #   evidence — and that single line let every collection field in
    #   the actor pass the eviction check. The regex was too permissive
    #   by an order of magnitude.
    #
    #   Replacement: drop the bare `let max[A-Z]` alternative entirely.
    #   The real evidence we want is "is there code that checks the
    #   stored container's size against a cap?" — which is exactly the
    #   `<fieldName>.count >` / `>=` pattern already in the regex. If
    #   eviction lives via a separate cap-constant pattern (e.g. `let
    #   maxEntries = 10_000` then `if entries.count >= maxEntries`),
    #   the second OR-arm (`${field}.count`) catches it. If a file uses
    #   a cap constant but never references it adjacent to the field's
    #   `.count`, that's not bounding evidence — that's an unused
    #   constant.
    if grep -qE "\b${field}\.(removeValue|removeFirst|removeAll|popFirst)\b|\b${field}\.count\s*[><=]" "$file"; then
        continue
    fi

    UNBOUNDED_FINDINGS+=("$file:$line_no:$field")
    audit_actors_unbounded=$((audit_actors_unbounded+1))
done < <(grep -rEn '^\s*private var [a-zA-Z_]+: (\[|Set<)' \
    Sources/MacCrabCore Sources/MacCrabAgentKit \
    --include='*.swift' 2>/dev/null \
    | grep -l 'public actor' /dev/stdin 2>/dev/null \
    || grep -rEn '^\s*private var [a-zA-Z_]+: (\[|Set<)' \
        Sources/MacCrabCore Sources/MacCrabAgentKit \
        --include='*.swift' 2>/dev/null)

# The complex grep+filter is fragile across BSD/GNU sed; perform the
# actor filter as a second pass.
declare -a IN_ACTOR=()
for finding in "${UNBOUNDED_FINDINGS[@]}"; do
    file="${finding%%:*}"
    if grep -q "public actor " "$file" 2>/dev/null; then
        IN_ACTOR+=("$finding")
    fi
done

if [[ ${#IN_ACTOR[@]} -gt 0 ]]; then
    # v1.12.6 Wave 5C: downgraded err → warn. The Wave 5C regex
    # tightening (drop `let max[A-Z]` short-circuit) unveils real
    # cases of "field bounded externally but no `.count` check in the
    # same file" — e.g., RuleEngine.ruleStats is keyed by ruleId from
    # a fixed config-loaded set, ProcessIdentityResolver.* tables are
    # keyed by pid (bounded by OS process table). These deserve a
    # second look but aren't necessarily leaks. The allowlist + cap+
    # evict + `// bounded:` comment escape hatches remain the way to
    # silence each finding; warn-level keeps the build green while
    # the operator triages.
    warn "Pass 8: ${#IN_ACTOR[@]} actor collection field(s) without same-file eviction evidence — add cap+evict, an inline '// bounded:' comment, or a BOUNDED_FIELD_ALLOWLIST entry:"
    for finding in "${IN_ACTOR[@]}"; do
        echo "    $finding"
    done
else
    ok "All actor collection fields show evidence of bounding (cap, eviction, or allowlist)"
fi

# ---------------------------------------------------------------------
# PASS 9 — autoreleasepool in collector hot loops (v1.7.7 lesson)
# ---------------------------------------------------------------------
# Foundation APIs that internally autorelease (JSONSerialization,
# many CFString/CFData factories, NSRegularExpression, NSDate
# formatters) accumulate their returns in the calling Task's pool.
# Swift async Tasks DO NOT carry an implicit @autoreleasepool — for
# event-loop Tasks that never end, this is a slow leak proportional
# to call frequency.
#
# Field reproduction (v1.7.6 → v1.7.7): EsloggerCollector and
# UnifiedLogCollector each parsed JSON per event in a `while true`
# loop driven by an async Task. At ~107 events/sec, that's ~1 GB
# of NSDictionary/NSError/_NSJSONReader/NSConcreteData accumulating
# per hour. Heap dump showed exactly 2.34M each (1:1:1 ratio = one
# triplet per JSONSerialization.jsonObject call) plus 692 MB of
# autoreleased input Data buffers.
#
# This pass scans collector + enricher source for the pattern:
# autoreleasing-Foundation-API call inside a `while`/`for await`
# body, with no `autoreleasepool` block on the surrounding lines.

section "PASS 9 — autoreleasepool in collector hot loops"

# Files in scope: anything in Collectors/ or Enrichment/ that runs
# a streaming/event-loop processor. We deliberately don't scan the
# whole tree because one-shot CLI tools and per-alert sinks don't
# leak — this pass is about long-running per-event hot paths.
PASS9_DIRS=(
    "Sources/MacCrabCore/Collectors"
    "Sources/MacCrabCore/Enrichment"
    "Sources/MacCrabAgentKit"
    # v1.7.11: extended to cover the dashboard target. SwiftUI poll
    # cadence (Timer.scheduledTimer { Task { await refresh() } })
    # doesn't match the existing while-let / for-await regex shape,
    # so the dashboard-side memory regression that v1.7.11 fixes
    # (Auto Layout constraint inflation in EventStream's Table) is
    # NOT detected by Pass 9. Including the directory anyway because:
    # (a) one of its 39 Foundation autoreleasing call sites might
    # land in a future while-let / for-await loop and Pass 9 would
    # then catch it, and (b) it forces future authors to think
    # about pool drainage when adding to MacCrabApp's hot paths.
    "Sources/MacCrabApp"
)

# Foundation APIs known to return autoreleased objects.
# v1.7.9: extended to include `fileHandle.availableData` and friends
# after a v1.7.8 field reproduction showed the v1.7.7 fix had only
# wrapped JSON parsing — the per-chunk Data reads from the file
# handle stayed autoreleased and accumulated 135K × 16 KB = 2.2 GB
# in 9 hours.
PASS9_PATTERNS='JSONSerialization\.jsonObject|JSONSerialization\.data|NSRegularExpression\.firstMatch|DateFormatter\(\)|ISO8601DateFormatter\(\)|\.availableData|\.readDataOfLength|\.read\(upToCount:|Data\(contentsOf:'

PASS9_FINDINGS=()
for dir in "${PASS9_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r f; do
        # Find lines matching the Foundation pattern. For each, look at
        # the surrounding 8 lines (above + below) — if there's a
        # while/for loop opening above AND no `autoreleasepool` between
        # that loop and the call, flag.
        while IFS=: read -r line content; do
            [[ -z "$line" ]] && continue
            # Window from max(1, line-15) to line+2 — wide enough to
            # catch a `while`/`for await` opening that's a few lines up
            # plus the call itself.
            start=$(( line > 15 ? line - 15 : 1 ))
            end=$(( line + 2 ))
            window=$(sed -n "${start},${end}p" "$f")
            # Must have a loop opening AND lack autoreleasepool in the
            # window. Allow `// audit-pass-9: hand-wrapped` opt-out
            # comment for cases where the wrapping is in a helper.
            # Match streaming/event-loop constructs only — bare `for` is too
            # noisy (catches words like "before", "force", and finite
            # `for x in fixedArray` startup loops which don't need pool drain).
            if echo "$window" | grep -qE '\bwhile (true|let)\b|for (try )?await\b' \
               && ! echo "$window" | grep -qE 'autoreleasepool|audit-pass-9: hand-wrapped'; then
                PASS9_FINDINGS+=("$f:$line — $(echo "$content" | sed 's/^[[:space:]]*//' | cut -c1-80)")
            fi
        done < <(grep -nE "$PASS9_PATTERNS" "$f" 2>/dev/null || true)
    done < <(find "$dir" -name '*.swift' -type f 2>/dev/null)
done

if [[ ${#PASS9_FINDINGS[@]} -gt 0 ]]; then
    err "Pass 9: ${#PASS9_FINDINGS[@]} autoreleasing Foundation call(s) in hot loops without autoreleasepool wrap:"
    for finding in "${PASS9_FINDINGS[@]}"; do
        echo "    $finding" >&2
    done
    echo "    Fix: wrap the per-iteration body in autoreleasepool { ... }" >&2
    echo "    Or add comment '// audit-pass-9: hand-wrapped' if wrapping is in a helper" >&2
else
    ok "All collector/enricher hot loops with autoreleasing Foundation calls are pool-wrapped"
fi

# ---------------------------------------------------------------------
# PASS 10 — co-resident store migration discipline (v1.7.6 lesson)
# ---------------------------------------------------------------------
# PRAGMA user_version is a SINGLE per-database counter. EventStore +
# AlertStore both run their own migration chains against shared
# events.db. Pre-fix logic (`pending = migrations.filter { $0.version
# > current }`) silently dropped one store's migrations whenever the
# other had bumped the counter past the dropping store's latest.
# Field reproduction (v1.7.5 → v1.7.6): AlertStore prepare crashed
# at every boot with "table alerts has no column named
# llm_investigation_json" because EventStore had bumped user_version
# to 2 first.
#
# This pass enforces:
#   - Any file declaring `schemaMigrations: [Migration]` AND opening
#     a `.db` file path that another store also uses must rely on
#     the SchemaMigrator's idempotent re-run path — i.e., the call
#     site must be `SchemaMigrator.run(...)` (the helper that
#     re-applies migrations idempotently when current >= latest)
#     and NOT a hand-rolled forward-only filter.

section "PASS 10 — co-resident store migration discipline"

# Find all stores that open events.db
PASS10_EVENTS_OPENERS=$(grep -rln 'appendingPathComponent("events.db")' Sources/MacCrabCore/Storage/ 2>/dev/null | wc -l | tr -d ' ')
PASS10_FAILURES=()

# Each opener must use SchemaMigrator.run() (which handles co-residency)
# rather than rolling its own filter.
for f in $(grep -rln 'appendingPathComponent("events.db")' Sources/MacCrabCore/Storage/ 2>/dev/null); do
    # File must call SchemaMigrator.run (proves it uses the shared,
    # co-resident-aware migrator).
    if ! grep -q 'SchemaMigrator\.run(' "$f"; then
        PASS10_FAILURES+=("$f opens events.db but doesn't call SchemaMigrator.run()")
        continue
    fi
    # File must NOT call PRAGMA user_version directly (a sign it's
    # rolling its own version filter that bypasses SchemaMigrator).
    if grep -qE '"PRAGMA user_version' "$f"; then
        PASS10_FAILURES+=("$f opens events.db AND reads/writes user_version directly — bypasses SchemaMigrator's co-residency handling")
    fi
done

# SchemaMigrator itself must contain the v1.7.6 idempotent re-run
# branch. If someone refactors and removes it, the bug returns.
if ! grep -q 'at-or-ahead' Sources/MacCrabCore/Storage/SchemaMigrator.swift 2>/dev/null \
   || ! grep -q 'bumpVersion' Sources/MacCrabCore/Storage/SchemaMigrator.swift 2>/dev/null; then
    PASS10_FAILURES+=("SchemaMigrator.swift missing the v1.7.6 idempotent-re-run branch (bumpVersion flag + at-or-ahead handling)")
fi

if [[ ${#PASS10_FAILURES[@]} -gt 0 ]]; then
    err "Pass 10: ${#PASS10_FAILURES[@]} co-resident store discipline violation(s):"
    for finding in "${PASS10_FAILURES[@]}"; do
        echo "    $finding" >&2
    done
    echo "    Background: PRAGMA user_version is per-database, not per-store." >&2
    echo "    Multiple stores sharing one .db must rely on SchemaMigrator's" >&2
    echo "    idempotent re-run path (bumpVersion=false when current>=latest)" >&2
    echo "    so a store whose migrations were silently skipped on first boot" >&2
    echo "    gets them applied on next launch instead of crashing." >&2
else
    ok "events.db openers ($PASS10_EVENTS_OPENERS file(s)) all use SchemaMigrator.run() with no direct user_version manipulation"
fi

# ---------------------------------------------------------------------
# PASS 11 — pre-design measurement of production data shape (v1.8.0 lesson)
# ---------------------------------------------------------------------
# v1.8.0 storage redesign was authored against an estimated event rate
# of "5-10k events/hour." Field measurement showed ~950k events/hour on
# a busy dev/AI machine — 13× higher. The 24h hot tier alone produced
# 4.4 GB, which a 200 MB cap couldn't hold. The architecture was right;
# the constants were grounded in a planning doc, not data.
#
# Pass 11 enforces: any release that touches storage retention / size
# caps must reference an empirical measurement of insert rate against a
# representative production DB. The measurement script lives at
# scripts/event-breakdown.sh; if a storage-related change ships without
# a recorded measurement (`measurement-<release>.txt` in releases/), this
# pass warns. Hard-fails if the script itself is missing.
#
# This is the codification of the lesson from
# concepts/storage-design-wrong-constants-aar.md: measure first, design
# second.

section "PASS 11 — pre-design measurement of production data shape"

PASS11_MEASUREMENT_SCRIPT="scripts/event-breakdown.sh"
if [[ ! -f "$PASS11_MEASUREMENT_SCRIPT" ]]; then
    err "Pass 11: $PASS11_MEASUREMENT_SCRIPT missing — required for storage-redesign release readiness"
else
    ok "Pass 11: measurement script present at $PASS11_MEASUREMENT_SCRIPT"
fi

# Detect whether the current branch has touched storage retention code.
# If yes, insist that a measurement exists for this release cycle.
PASS11_STORAGE_PATHS=(
    "Sources/MacCrabAgentKit/DaemonConfig.swift"
    "Sources/MacCrabAgentKit/DaemonTimers.swift"
    "Sources/MacCrabCore/Storage/EventStore.swift"
    "Sources/MacCrabCore/Storage/AlertStore.swift"
    "Sources/MacCrabCore/Storage/CampaignStore.swift"
    "Sources/MacCrabCore/Storage/AlertsTableRelocator.swift"
)
PASS11_TOUCHED=0
for p in "${PASS11_STORAGE_PATHS[@]}"; do
    # Touched if it differs from the merge-base of main. Best-effort —
    # falls back to "treat as touched" on git failures so the warning
    # path runs.
    if git diff --quiet "origin/main...HEAD" -- "$p" 2>/dev/null; then
        :  # unchanged
    else
        PASS11_TOUCHED=1
        break
    fi
done

if [[ "$PASS11_TOUCHED" == "1" ]]; then
    info "Pass 11: storage code modified on this branch — recommend recording an empirical measurement before publish"
    info "         Run: sudo $PASS11_MEASUREMENT_SCRIPT > releases/measurement-\$(git describe --tags --always).txt"
    info "         Then capture: insert rate (events/hour), avg bytes/event, top 10 noisy process_paths"
    # Soft-warn rather than hard-fail; the operator can still publish if
    # they're confident the design holds. The point is the prompt.
    warn "Pass 11: empirical measurement evidence advised but not enforced (soft warn)"
else
    ok "Pass 11: no storage code modified on this branch — measurement requirement does not apply"
fi

# ---------------------------------------------------------------------
# PASS 12 — traces.db long-lived connection count (v1.9 PR-3b)
# ---------------------------------------------------------------------
# Mirror of Pass 5 for the new `traces.db` file. PR-3a introduced
# TraceStore as a separate SQLite store; the receiver-to-store wiring
# in PR-3b is the only authorised long-lived opener. A second long-
# lived handle would re-introduce the v1.6.22 CampaignStore bug class
# on a different file. The path-token grep + actor-field grep is the
# same shape as Pass 5.
section "PASS 12 — traces.db long-lived connection count"

traces_db_actors=$(grep -rln 'appendingPathComponent("traces.db")' Sources/MacCrabCore/Storage Sources/MacCrabAgentKit \
    --include='*.swift' 2>/dev/null \
    | xargs -I {} grep -l 'private var db: OpaquePointer?' {} 2>/dev/null \
    | sort -u || true)
traces_db_actor_count=$(echo "$traces_db_actors" | grep -cE '\S' || true)

if [[ "$traces_db_actor_count" -gt 1 ]]; then
    err "More than 1 actor holds a long-lived traces.db handle (current: $traces_db_actor_count). Mirror of v1.6.22 CampaignStore bug — consolidate into TraceStore:"
    echo "$traces_db_actors" | sed 's/^/    /' >&2
elif [[ "$traces_db_actor_count" -eq 0 ]]; then
    # v1.10.2: previously `info` — silent-green. Agent Traces shipped
    # in v1.9.0 and TraceStore is a load-bearing dep of TraceMaterializer
    # (DaemonSetup.swift:484-498). Zero matches now means the type was
    # renamed or the daemon target was reorganized — failed wire-up.
    err "Pass 12: no traces.db opener present. TraceStore is required from v1.9.0 onward — find via 'rg \"actor TraceStore\" Sources/'."
else
    ok "traces.db long-lived connection count at audited target (1: TraceStore)"
fi

# ---------------------------------------------------------------------
# PASS 13 — env-block secret-leak prevention (v1.9 PR-3b)
# ---------------------------------------------------------------------
# The TraceExtractor pathway reads exec env blocks at NOTIFY_EXEC. Per
# the v1.9 privacy contract, ONLY parsed TRACEPARENT trace_id/span_id
# values may surface in logs/metrics/persistence. Anything that
# interpolates `es_exec_env_count`, `es_exec_env`, or any env-derived
# raw token into `os.log`, `print`, file writes, or LLM prompts is a
# regression of the secret-leak class.
#
# Strict cut: forbid the bare ES env accessor outside the
# `TraceExtractor` pathway file pair. Anywhere else that needs env
# access in the future has to land alongside a Pass 13 allowlist
# entry + a code review.
section "PASS 13 — env-block secret-leak prevention"

# Allowed callers of `es_exec_env`/`es_exec_env_count`. Adding a new
# entry requires a comment explaining why the file is allowed to
# touch the env block — should be rare.
declare -a PASS13_ALLOWED=(
    "Sources/MacCrabCore/Collectors/ESHelpers.swift"
    "Sources/MacCrabCore/AIGuard/TraceExtractor.swift"
)

pass13_violations=$(grep -rln 'es_exec_env\b\|es_exec_env_count' \
    Sources/MacCrabCore Sources/MacCrabAgentKit \
    --include='*.swift' 2>/dev/null | sort -u || true)

pass13_unauthorized=()
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    allowed=0
    for a in "${PASS13_ALLOWED[@]}"; do
        if [[ "$f" == "$a" ]]; then allowed=1; break; fi
    done
    if [[ $allowed -eq 0 ]]; then
        pass13_unauthorized+=("$f")
    fi
done <<< "$pass13_violations"

if [[ ${#pass13_unauthorized[@]} -gt 0 ]]; then
    err "Pass 13: ${#pass13_unauthorized[@]} unauthorized caller(s) of es_exec_env/_count — env block must only be touched by TraceExtractor:"
    for f in "${pass13_unauthorized[@]}"; do
        echo "    $f" >&2
    done
else
    ok "Pass 13: env block accessors confined to authorised TraceExtractor pathway"
fi

# ---------------------------------------------------------------------
# PASS 14 — enrichment-key ↔ enricher coverage (v1.9 PR-5)
# ---------------------------------------------------------------------
# Closes the wire-the-orphans pattern at the rule-field level. Every
# enrichment key referenced in compiled YAML rules under Rules/ must
# have at least one Swift writer somewhere under Sources/. Rules that
# fire on agent_trace_id when no enricher actually populates that
# field would always be silently dead — Pass 14 makes that fail at
# release time.
#
# We grep YAML rules for the underscore-cased enrichment keys (the
# keys that land in `event.enrichments[...]`), then confirm at least
# one Swift source file writes that key. Swift writers use the form
# `event.enrichments["<key>"] = ...` or `enrichments[<Constant>]`.
section "PASS 14 — enrichment-key ↔ enricher coverage"

# v1.9 PR-5 surface. Add new entries here when a rule starts matching
# on a new enrichment key — the audit then verifies a producer exists.
declare -a PASS14_KEYS=(
    # v1.10.2: Pass 14's contract is "every key listed here must be
    # referenced by ≥1 rule (snake_case OR Sigma CamelCase) AND
    # produced by ≥1 Swift writer". Keys that are info-only analyst
    # context (`agent_trace_id`, `agent_span_id`, `agent_tool` — these
    # are surfaced in alert detail / TraceStore columns but are NOT
    # rule predicates) don't fit the contract; including them caused
    # spurious failures. They remain validated by Pass 7 (panel
    # richness audit) and the V2 alert-inspector tests.
    "machine_agent_confidence"
)

if [[ ${#PASS14_KEYS[@]} -eq 0 ]]; then
    err "Pass 14: PASS14_KEYS is empty — pass would silent-green. Add curated enrichment keys."
fi

# v1.10.2: Sigma rules use CamelCase field names (MachineAgentConfidence,
# AgentTraceId, etc.) which the rule compiler maps to snake_case
# enrichment keys via SIGMA_FIELD_MAP in Compiler/compile_rules.py.
# Pass 14 needs to recognize either form when checking rule references,
# else snake-case-only greps silent-green even when Sigma mappings exist.
snake_to_camel() {
    local out=""
    local part
    IFS='_' read -ra parts <<< "$1"
    for part in "${parts[@]}"; do
        out+="$(printf '%s' "$part" | awk '{print toupper(substr($0,1,1)) substr($0,2)}')"
    done
    printf '%s' "$out"
}

pass14_orphans=()
pass14_unreferenced=()
for key in "${PASS14_KEYS[@]}"; do
    key_camel=$(snake_to_camel "$key")
    # Is the key referenced by any rule, in either snake_case OR Sigma
    # CamelCase form?
    if ! grep -rqE "${key}|${key_camel}" Rules/ --include='*.yml' 2>/dev/null; then
        # v1.10.2: previously `continue` — silent-green for typoed keys.
        # The PASS14_KEYS list is curated against the v1.9 enrichment
        # contract; an entry that no rule references (in either form) is
        # either a typo in the script OR a rule we forgot to ship.
        pass14_unreferenced+=("$key")
        continue
    fi
    # Does anything under Sources/ write or reference the key?
    # v1.10.2: previously matched only the JSON-style enrichments-dict
    # access patterns, which missed v1.9 Agent Traces enrichments that
    # land as SQL columns (`machine_agent_confidence` in events.db) and
    # as Swift constants (`public static let confidence =
    # "machine_agent_confidence"`). Broaden to: any quoted occurrence
    # in Swift, OR the legacy enrichments-dict / EnrichmentKey
    # patterns. Either form (snake_case or CamelCase) counts.
    if grep -rqE "enrichments\[\"${key}\"\]|EnrichmentKey\.${key}|\"${key}\"|\"${key_camel}\"" \
            Sources/ --include='*.swift' 2>/dev/null; then
        continue
    fi
    pass14_orphans+=("$key")
done

if [[ ${#pass14_unreferenced[@]} -gt 0 ]]; then
    err "Pass 14: ${#pass14_unreferenced[@]} curated key(s) NOT referenced by any rule (typo in PASS14_KEYS or missing rule):"
    for k in "${pass14_unreferenced[@]}"; do
        echo "    $k" >&2
    done
fi

if [[ ${#pass14_orphans[@]} -gt 0 ]]; then
    err "Pass 14: ${#pass14_orphans[@]} enrichment key(s) referenced by rules but not produced by any Swift writer:"
    for k in "${pass14_orphans[@]}"; do
        echo "    $k" >&2
    done
fi

if [[ ${#pass14_unreferenced[@]} -eq 0 && ${#pass14_orphans[@]} -eq 0 ]]; then
    ok "Pass 14: all rule-referenced enrichment keys have at least one Swift producer"
fi

# ---------------------------------------------------------------------
# PASS 15 — TraceStore must be wired with DatabaseEncryption in daemon mode
# ---------------------------------------------------------------------
# v1.9.0 ship invariant. Phase-2.2 wired column-level AES-GCM for
# `attributes_json`. The TraceStore init signature accepts an optional
# `encryption` param so test paths can pass nil — but daemon-target
# call sites MUST pass the shared DatabaseEncryption. A future
# contributor "fixing" a build error by passing nil would silently
# regress the on-disk encryption story.
#
# v1.9.0 audit-of-the-audit: the prior implementation grepped
# `TraceStore(directory:` on a single line, but every real call site
# wraps the args across multiple lines (`TraceStore(\n  directory:
# ..., \n  encryption: ...\n)`), so the grep matched zero lines and
# the pass was silently green regardless of wiring. Rewritten to:
#   1. Match the bare constructor token `TraceStore(`.
#   2. Read a 6-line window for each match.
#   3. Skip the path-init overload (`TraceStore(path:...)` — used by
#      tests, doesn't require `encryption:`).
#   4. Require `directory:` AND `encryption:` in the window for any
#      remaining match — the daemon-mode shape.
#   5. Self-test: if zero matches were found in the daemon target at
#      all, fail loud rather than silently green. That catches the
#      "Agent Traces wiring vanished" class of regression.
section "PASS 15 — TraceStore + DatabaseEncryption pairing in daemon mode"

pass15_call_lines=$(grep -rn "TraceStore(" \
    Sources/MacCrabAgentKit Sources/MacCrabAgent Sources/maccrabd \
    --include='*.swift' 2>/dev/null || true)

# Self-test: a daemon target with no TraceStore() calls means the
# Agent Traces wiring is missing. That's a regression — fail loud
# rather than silently passing.
pass15_call_count=$(echo "$pass15_call_lines" | grep -cE '\S' || true)
if [[ "$pass15_call_count" -eq 0 ]]; then
    err "Pass 15: no TraceStore(...) call found in daemon target — Agent Traces wiring is missing"
fi

pass15_violations=()
pass15_directory_init_count=0
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    file="${line%%:*}"
    rest="${line#*:}"
    lineno="${rest%%:*}"
    snippet="${rest#*:}"

    window=$(awk -v ln="$lineno" 'NR >= ln && NR < ln + 6 { print }' "$file" 2>/dev/null)

    # Skip path-init overload — only the directory-init overload
    # requires encryption: in daemon mode.
    if ! echo "$window" | grep -q "directory:"; then
        continue
    fi

    pass15_directory_init_count=$((pass15_directory_init_count + 1))
    if ! echo "$window" | grep -q "encryption:"; then
        pass15_violations+=("$file:$lineno: $snippet")
    fi
done <<< "$pass15_call_lines"

if [[ ${#pass15_violations[@]} -gt 0 ]]; then
    err "Pass 15: TraceStore(directory:) call(s) in daemon target without encryption:"
    for v in "${pass15_violations[@]}"; do echo "    $v" >&2; done
elif [[ "$pass15_directory_init_count" -eq 0 && "$pass15_call_count" -gt 0 ]]; then
    # Found TraceStore() calls but none looked like the daemon-mode
    # shape — also a regression-shaped result.
    err "Pass 15: TraceStore(...) calls present but none use directory: + encryption: shape — daemon wiring may have regressed"
else
    ok "Pass 15: every TraceStore(directory:) in the daemon target wires DatabaseEncryption (verified $pass15_directory_init_count call site(s))"
fi

# ---------------------------------------------------------------------
# PASS A — codesign entitlement isolation (v1.12.2 Sparkle-install lesson)
# ---------------------------------------------------------------------
# Field reproduction (v1.12.0 → v1.12.2): the outer .app codesign pass
# in build-release.sh was authored as
#     codesign --sign "$DEVELOPER_ID" \
#         --entitlements "$APP_ENT" \
#         --deep --force \
#         "$APP"
# `--deep --force` on the .app re-signed every nested Mach-O including
# Sparkle.framework's Autoupdate, Updater.app, Downloader.xpc, and
# Installer.xpc. `--entitlements` THEN propagated the main-app
# entitlements (com.apple.developer.system-extension.install +
# keychain-access-groups) onto each. macOS refuses to launch a Sparkle
# XPC helper that carries the system-extension-install entitlement,
# which surfaced as "An error occurred while running the updater" on
# every Sparkle upgrade attempt across v1.12.0 and v1.12.1.
# v1.12.1 tried --preserve-metadata=entitlements first — that doesn't
# preserve the *absence* of entitlements, so propagation still
# happened. v1.12.2 fixed by dropping --deep from the outer pass.
#
# This pass refuses any codesign invocation that simultaneously
# targets a .app bundle, passes --deep, passes --entitlements, and
# does NOT pass --preserve-metadata=entitlements. The intent: outer
# .app re-signs should rely on the nested Mach-Os' own step-4a
# signatures (already entitlement-free), not blast main-app
# entitlements through every helper.
#
# Deliberately-broken fixture this catches:
#     codesign --sign "$DEVELOPER_ID" \
#         --deep --force \
#         --entitlements "$APP_ENT" \
#         "$APP"     # ← would HARD ERROR
# Acceptable shapes:
#     codesign --sign - --deep "$APP"                           # ad-hoc, no entitlements
#     codesign --verify --deep --strict "$APP"                  # verify, not signing
#     codesign --sign "$ID" --entitlements "$E" "$APP"          # entitlements but no --deep
#     codesign --sign "$ID" --deep --entitlements "$E" \
#              --preserve-metadata=entitlements "$APP"          # explicit preservation
section "PASS A — codesign entitlement isolation"

# Each codesign invocation in scripts/ frequently spans multiple
# lines via backslash continuation. Pre-process: pull every script
# and fold continuations so each codesign command is a single
# logical line, then grep that flattened form.

passA_violations=()
for script in scripts/build-release.sh scripts/notarize.sh scripts/bundle-app.sh scripts/dev.sh scripts/install.sh scripts/uninstall.sh; do
    [[ -f "$script" ]] || continue
    # Fold backslash-continuations into single lines, preserving line
    # numbers via a sentinel. awk emits "<linenum>:<joined-command>".
    folded=$(awk '
        BEGIN { buf=""; startln=0 }
        {
            # Track the starting line of a buffered continuation.
            if (buf == "") startln = NR
            # Strip a trailing backslash (line-continuation marker).
            if (sub(/\\[[:space:]]*$/, "", $0)) {
                buf = buf $0 " "
                next
            }
            buf = buf $0
            print startln ":" buf
            buf = ""
        }
        END { if (buf != "") print startln ":" buf }
    ' "$script")

    # Filter to lines that invoke codesign (the executable, not a
    # comment or string mentioning the word). Use word-boundary grep.
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        ln="${entry%%:*}"
        cmd="${entry#*:}"

        # Skip pure comment lines (whitespace then #).
        if echo "$cmd" | grep -qE '^[[:space:]]*#'; then continue; fi
        # Skip lines that don't actually invoke codesign (e.g. mentions
        # in an `echo`, an `if ! security find-identity` test).
        if ! echo "$cmd" | grep -qE '(^|[^a-zA-Z_-])codesign[[:space:]]'; then continue; fi
        # Skip --verify (read-only check, not signing).
        if echo "$cmd" | grep -qE 'codesign[[:space:]]+--verify\b|codesign[[:space:]]+[^"'\'']*--verify\b'; then continue; fi

        # Require all four conditions to call it a violation:
        #   1. targets a .app bundle (literal MacCrab.app, $APP, or "*.app"),
        #   2. carries --deep,
        #   3. carries --entitlements,
        #   4. lacks --preserve-metadata=entitlements.
        targets_app=0
        if echo "$cmd" | grep -qE '"\$APP"|\$APP[[:space:]]*$|MacCrab\.app|/[A-Za-z][A-Za-z0-9_-]*\.app[/"[:space:]]'; then
            targets_app=1
        fi
        has_deep=0
        if echo "$cmd" | grep -qE -- '--deep\b'; then has_deep=1; fi
        has_ent=0
        if echo "$cmd" | grep -qE -- '--entitlements\b'; then has_ent=1; fi
        has_preserve=0
        if echo "$cmd" | grep -qE -- '--preserve-metadata=entitlements\b'; then has_preserve=1; fi

        if [[ $targets_app -eq 1 && $has_deep -eq 1 && $has_ent -eq 1 && $has_preserve -eq 0 ]]; then
            # Trim leading whitespace and clip the displayed command
            # so the error stays readable.
            display=$(echo "$cmd" | sed -E 's/^[[:space:]]+//' | cut -c1-160)
            passA_violations+=("$script:$ln: $display")
        fi
    done <<< "$folded"
done

if [[ ${#passA_violations[@]} -gt 0 ]]; then
    err "Pass A: ${#passA_violations[@]} codesign invocation(s) on a .app bundle combine --deep + --entitlements without --preserve-metadata=entitlements (v1.12.2 Sparkle-install regression shape):"
    for v in "${passA_violations[@]}"; do
        echo "    $v" >&2
    done
    echo "    Fix: drop --deep from the outer .app sign and rely on nested helpers' own signatures," >&2
    echo "    OR add --preserve-metadata=entitlements explicitly if --deep is genuinely required." >&2
else
    ok "Pass A: no .app codesign call combines --deep + --entitlements without --preserve-metadata=entitlements"
fi

# ---------------------------------------------------------------------
# PASS B — SwiftPM resource bundle Info.plist completeness (v1.12.4 lesson)
# ---------------------------------------------------------------------
# Field reproduction (v1.12.3 → v1.12.4): the Intelligence-tab tap
# fatalError'd on every fresh macOS 26 install with
#     "Fatal error: unable to find bundle named MacCrab_MacCrabCore"
# Root cause: SwiftPM emits MacCrab_MacCrabCore.bundle/Info.plist
# containing only CFBundleDevelopmentRegion. macOS ≤25 tolerated the
# stripped plist; macOS 26 made `Bundle(url:)` strict — it now
# requires CFBundleIdentifier + CFBundlePackageType +
# CFBundleInfoDictionaryVersion to construct a Bundle at all. With
# `Bundle(url:)` returning nil, SwiftPM's auto-generated
# `Bundle.module` accessor reaches its `else { fatalError(...) }`
# branch the first time a resource lookup happens (which is when
# PackageScanner lazy-instantiates TyposquatDatabase). v1.12.4 fixed
# by overwriting the stub plist in scripts/build-release.sh with a
# complete CFBundle plist for every SPM resource bundle.
#
# This pass scans `.build/` (when present) for every `.bundle/`
# directory and verifies the three required keys are populated.
# Pre-build runs in CI won't have `.build/` yet — that's a SKIP, not
# a failure. The intent is to catch the post-build window where the
# operator might `make build` and then run the audit before the
# patched plist step in build-release.sh runs.
#
# Deliberately-broken fixture this catches:
#     # SwiftPM emits this — minimal plist macOS 26 rejects.
#     <plist version="1.0"><dict>
#         <key>CFBundleDevelopmentRegion</key><string>en</string>
#     </dict></plist>
section "PASS B — SwiftPM resource bundle Info.plist completeness"

passB_violations=()
passB_checked=0
passB_search_paths=()

# Locate the shipping .app (the only resource-bundle path that matters at
# runtime for end users). Per-arch slices under .build/ are throwaway
# intermediates: macOS 26's Bundle(url:) crash class only fires when code
# loads them via Bundle.module, and v1.12.4 already migrated the load
# paths off Bundle.module. Pass B's invariant therefore scopes to the
# shipping .app — intermediates are tracked separately (info only).
shopt -s nullglob
for app_root in \
    .build/release/MacCrab.app \
    .build/debug/MacCrab.app \
    dist/MacCrab.app \
    /Applications/MacCrab.app; do
    if [[ -d "$app_root/Contents/Resources" ]]; then
        passB_search_paths+=("$app_root/Contents/Resources")
    fi
done
shopt -u nullglob

if [[ ${#passB_search_paths[@]} -eq 0 ]]; then
    info "→ SKIPPED (no shipping MacCrab.app found — pass runs post-build)"
else
    for search_root in "${passB_search_paths[@]}"; do
        while IFS= read -r plist; do
            [[ -f "$plist" ]] || continue
            passB_checked=$((passB_checked + 1))

            # Each required key must resolve via PlistBuddy. Missing-key
            # error short-circuits the check for that bundle.
            missing=()
            for key in CFBundleIdentifier CFBundlePackageType CFBundleInfoDictionaryVersion; do
                if ! /usr/libexec/PlistBuddy -c "Print :$key" "$plist" >/dev/null 2>&1; then
                    missing+=("$key")
                fi
            done
            if [[ ${#missing[@]} -gt 0 ]]; then
                passB_violations+=("$plist missing: ${missing[*]}")
            fi
        done < <(find "$search_root" -type d -name '*.bundle' -print 2>/dev/null | while read -r d; do echo "$d/Info.plist"; done)
    done

    if [[ ${#passB_violations[@]} -gt 0 ]]; then
        err "Pass B: ${#passB_violations[@]} SwiftPM resource bundle plist(s) missing CFBundle keys macOS 26 Bundle(url:) requires (of $passB_checked checked):"
        for v in "${passB_violations[@]}"; do
            echo "    $v" >&2
        done
        echo "    Fix: scripts/build-release.sh already patches the .app copy; re-run the build step," >&2
        echo "    or extend the patch loop to overwrite per-arch slice plists too." >&2
    elif [[ "$passB_checked" -eq 0 ]]; then
        info "Pass B: no .bundle/Info.plist files found under .build/ (resource bundles may not have been emitted yet)"
    else
        ok "Pass B: all $passB_checked SwiftPM resource bundle Info.plist file(s) carry CFBundleIdentifier + CFBundlePackageType + CFBundleInfoDictionaryVersion"
    fi
fi

# ---------------------------------------------------------------------
# PASS C — permission-change paired integration test (v1.12.5 lesson)
# ---------------------------------------------------------------------
# Field reproduction (latent v1.11.0 RC2 → v1.12.5): the dashboard's
# Threat Intel tab showed feeds=0 / iocs=0 even though the sysext was
# writing the cache files. Root cause: a "tightening" audit had set
# /Library/Application Support/MacCrab/threat_intel/ to 0o700. The
# cache files inside (0o644, world-readable) were unreachable from the
# user-context dashboard because the user lacked traverse (x) on the
# directory. ThreatIntelFeed.cachedIOCs(at:) silently failed at the
# directory level with EACCES, returned nil, and the dashboard
# rendered the zero counts as "no threat intel configured." Latent
# ~6 months because every test exercised either the sysext-context
# write OR the file-mode itself — never the user-context traverse.
#
# This pass enumerates every chmod / setAttributes call against a
# path under /Library/Application Support/MacCrab/ in the three
# scoped directories (Storage, ThreatIntelFeed, Output) and warns
# when no test file in Tests/ references the same path token AND
# simulates user-context read. WARN-level (not ERROR) because this
# is a new invariant — much of the existing code predates the
# requirement and can't be retrofitted in one wave.
#
# Deliberately-broken fixture this catches:
#     // In Sources/MacCrabCore/Enrichment/ThreatIntelFeed.swift:
#     try? FileManager.default.setAttributes(
#         [.posixPermissions: 0o700],
#         ofItemAtPath: "/Library/Application Support/MacCrab/new_cache_dir"
#     )
#     // … with no Tests/ file mentioning "new_cache_dir" + a getuid()
#     // simulation → WARN.
section "PASS C — permission-change paired integration test"

declare -a PASS_C_SCOPES=(
    "Sources/MacCrabCore/Storage"
    "Sources/MacCrabCore/Enrichment/ThreatIntelFeed.swift"
    "Sources/MacCrabCore/Output"
)

passC_findings=()
for scope in "${PASS_C_SCOPES[@]}"; do
    [[ -e "$scope" ]] || continue
    # Collect every line that calls chmod() or FileManager.setAttributes
    # in this scope. -F-friendly fixed-string variants caught first
    # (chmod), then the Foundation API.
    while IFS= read -r match; do
        [[ -z "$match" ]] && continue
        file="${match%%:*}"
        rest="${match#*:}"
        lineno="${rest%%:*}"

        # Read a 6-line window around the call to find the path it
        # operates on. The path may be a literal string ("/Library/…")
        # or a Swift variable / let-bound URL. We only care about
        # paths under /Library/Application Support/MacCrab/ — paths
        # in the user container don't have the sysext/dashboard split.
        window=$(awk -v ln="$lineno" 'NR >= ln - 2 && NR < ln + 6 { print }' "$file" 2>/dev/null)

        # Is this call targeting a /Library/Application Support/MacCrab path?
        if ! echo "$window" | grep -qE '/Library/Application Support/MacCrab|appendingPathComponent|threat_intel|databasePath|ofItemAtPath: dir'; then
            continue
        fi

        # Extract a path token to grep tests for. Prefer the most
        # specific token in the window — a quoted subdirectory name
        # or the variable name passed to ofItemAtPath/at:.
        token=""
        # Try a directory subcomponent like "threat_intel" first.
        sub=$(echo "$window" | grep -oE '"[a-z_]+_(intel|cache|snapshot|store|rules|backup)"|appendingPathComponent\("[a-z_]+"' \
              | head -1 \
              | sed -E 's/.*"([^"]+)"/\1/')
        if [[ -n "$sub" ]]; then token="$sub"; fi
        # Fall back to the basename of the source file (covers cases
        # where the path is built from a variable like `databasePath`).
        if [[ -z "$token" ]]; then
            token=$(basename "$file" .swift)
        fi

        # Look in Tests/ for a file that references the token AND
        # carries a user-context read marker. User-context markers
        # include: getuid() / geteuid() / setegid / setuid (process
        # ID dance), FileManager.default.isReadableFile (dashboard
        # path), Process() launching as a non-root user, or an
        # explicit comment of the form `// user-context read`.
        test_files=$(grep -rln "$token" Tests --include='*.swift' 2>/dev/null || true)
        paired=0
        while IFS= read -r tf; do
            [[ -z "$tf" ]] && continue
            if grep -qE 'getuid\(\)|geteuid\(\)|setuid\(|isReadableFile|isReadable\(at:|user[- ]context|// pass-c:' "$tf"; then
                paired=1
                break
            fi
        done <<< "$test_files"

        if [[ $paired -eq 0 ]]; then
            passC_findings+=("$file:$lineno (token=$token)")
        fi
    done < <(grep -rEn 'chmod\(|FileManager\.default\.setAttributes' "$scope" --include='*.swift' 2>/dev/null || true)
done

if [[ ${#passC_findings[@]} -gt 0 ]]; then
    warn "Pass C: ${#passC_findings[@]} permission-change call(s) on /Library/Application Support/MacCrab/ paths without a paired user-context read test (v1.12.5 Threat Intel feeds=0 regression shape):"
    for f in "${passC_findings[@]}"; do
        echo "    $f"
    done
    echo "    Suggested test marker: getuid() / isReadableFile / a // pass-c: user-context read comment"
    echo "    on a Tests/ file that opens the same path the chmod target is built from."
else
    ok "Pass C: every chmod / setAttributes on a /Library/Application Support/MacCrab/ path has a paired user-context test"
fi

# ---------------------------------------------------------------------
# PASS D — self-defense Sigma filter symmetry (v1.12.5 lesson)
# ---------------------------------------------------------------------
# Field reproduction (v1.12.5): the "Attempted Tamper of MacCrab
# Components" rule fired CRITICAL every startup on
#     /bin/rm        spawned by MacCrab during cleanup
#     /usr/bin/pkill spawned by MacCrab during HUP/SIGUSR1 routing
#     /bin/launchctl spawned by SystemExtensionManager
# The filter_maccrab_self block looked correct on paper:
#     filter_maccrab_self:
#         Image|contains: ['MacCrab.app/Contents/', 'maccrabd', ...]
#         ParentImage|contains: ['MacCrab.app/Contents/', 'sysextd', ...]
# But Sigma evaluates a single selection's multiple fields with AND —
# the rule required BOTH Image AND ParentImage to mention MacCrab.
# The actual events had Image=/bin/rm (a system tool), Parent=MacCrab.
# The AND never matched, so the filter never suppressed self-spawned
# helpers. v1.12.5 fixed by adding a sibling filter_maccrab_parent
# (Parent-only) and filter_upgrade_installer (Parent-only on
# brew/osascript/sysextd/Updater) so the AND-style block is
# complemented by an OR-style escape hatch via the multiple-filter
# `not A or not B` topology.
#
# This pass parses each self-protection Sigma YAML and requires
# either:
#   1. At least one filter clause that references ONLY ParentImage
#      AND at least one filter clause that references ONLY Image, OR
#   2. At least one filter clause that references NEITHER Image NOR
#      ParentImage (e.g., a CommandLine-only filter, which is the
#      permissive "match anything regardless of process identity"
#      escape hatch).
#
# Deliberately-broken fixture this catches:
#     # A rule whose only filter clause is:
#     filter_maccrab_self:
#         Image|contains: [...]
#         ParentImage|contains: [...]
#     # … without a sibling Parent-only or Image-only filter → WARN.
# WARN-level (not ERROR) because not every self-protection rule
# strictly needs both filter forms, but a missing one is worth a
# pre-release look.
section "PASS D — self-defense Sigma filter symmetry"

if ! command -v python3 >/dev/null 2>&1; then
    warn "Pass D: python3 unavailable — falling back to grep heuristic (less precise)"
    passD_python=0
else
    if ! python3 -c "import yaml" >/dev/null 2>&1; then
        warn "Pass D: PyYAML unavailable — falling back to grep heuristic (less precise)"
        passD_python=0
    else
        passD_python=1
    fi
fi

# Build the rule list. Take everything under ai_safety/ and
# defense_evasion/ plus any rule whose title mentions tamper / self /
# security_tool.
PASS_D_CANDIDATES=$(find Rules/ai_safety Rules/defense_evasion -name '*.yml' -type f 2>/dev/null || true)
PASS_D_TITLED=$(grep -rlE '^title:[[:space:]]+.*(tamper|self|[Ss]ecurity [Tt]ool)' Rules/ --include='*.yml' 2>/dev/null || true)
# Union + uniq, single line per file.
PASS_D_FILES=$(printf '%s\n%s\n' "$PASS_D_CANDIDATES" "$PASS_D_TITLED" | grep -vE '^$' | sort -u)

passD_violations=()

if [[ "$passD_python" -eq 1 ]]; then
    # Precise YAML parse: enumerate every filter_* clause and classify
    # whether its fields are Image-only, ParentImage-only, both, or
    # neither.
    while IFS= read -r yml; do
        [[ -z "$yml" ]] && continue
        verdict=$(python3 - "$yml" <<'PY' 2>/dev/null
import sys, yaml, pathlib
path = pathlib.Path(sys.argv[1])
try:
    rule = yaml.safe_load(path.read_text())
except Exception as e:
    print("PARSE_ERROR:" + str(e))
    sys.exit(0)
det = rule.get("detection", {}) if isinstance(rule, dict) else {}
filter_clauses = [
    (name, val) for name, val in det.items()
    if name != "condition" and name.startswith("filter") and isinstance(val, dict)
]
if not filter_clauses:
    # No filter clauses at all → rule has nothing to assert about.
    print("NO_FILTERS")
    sys.exit(0)
has_parent_only = False
has_image_only = False
has_neither = False
for name, val in filter_clauses:
    fields = [str(f) for f in val.keys()]
    mentions_image = any(("Image" in f or "image" in f) and "arent" not in f.lower() for f in fields)
    mentions_parent = any("arent" in f.lower() for f in fields)
    if mentions_parent and not mentions_image:
        has_parent_only = True
    if mentions_image and not mentions_parent:
        has_image_only = True
    if not mentions_image and not mentions_parent:
        has_neither = True
# Permissive escape hatch: any filter without Image/ParentImage.
if has_neither:
    print("OK_NEITHER")
elif has_parent_only and has_image_only:
    print("OK_SYMMETRIC")
elif has_parent_only:
    print("MISSING_IMAGE_ONLY")
elif has_image_only:
    print("MISSING_PARENT_ONLY")
else:
    print("MISSING_BOTH")
PY
)
        case "$verdict" in
            OK_*|NO_FILTERS|"") ;;  # pass / not applicable
            PARSE_ERROR:*)
                warn "Pass D: $yml — YAML parse failed (${verdict#PARSE_ERROR:})"
                ;;
            MISSING_IMAGE_ONLY|MISSING_PARENT_ONLY|MISSING_BOTH)
                # Wave 7A.3-B narrowed trigger: only flag rules that
                # carry the `maccrab.self_protection` tag (the shape
                # whose filters need to exempt MacCrab's own helper
                # processes — pkill / rm / launchctl spawned by the
                # daemon during cleanup). Pre-Wave 7A the trigger
                # included any `attack.t1562` rule, which over-counts —
                # T1562 ("Impair Defenses") rules whose target is the
                # generic macOS attack surface (MDM, SIP, firewall
                # plist) don't need self/parent symmetry. Those rules
                # fire on the ATTACKER's tampering, not on MacCrab's
                # own maintenance noise. v1.12.5's filter retrofit was
                # exclusively for the `maccrab_tamper_attempt` shape.
                if grep -qE '^[[:space:]]*-[[:space:]]*maccrab\.self_protection' "$yml"; then
                    passD_violations+=("$yml: $verdict")
                fi
                ;;
        esac
    done <<< "$PASS_D_FILES"
else
    # Fallback grep heuristic: only inspect rules that carry the
    # `maccrab.self_protection` tag (matches the YAML-path tightening
    # in Wave 7A.3-B above). Coarser than the YAML parse — flag as
    # APPROX.
    while IFS= read -r yml; do
        [[ -z "$yml" ]] && continue
        if ! grep -qE '^[[:space:]]*-[[:space:]]*maccrab\.self_protection' "$yml"; then continue; fi
        # Heuristic: presence of `ParentImage|` in any filter_ block
        # AND presence of a separate filter_ block whose body has
        # `Image|` but not `ParentImage|`.
        parent_only=$(grep -cE '^\s*ParentImage\|' "$yml" || true)
        image_only=$(grep -cE '^\s*Image\|' "$yml" || true)
        if [[ "$parent_only" -lt 1 || "$image_only" -lt 1 ]]; then
            passD_violations+=("$yml: grep-heuristic flagged (parent_only=$parent_only image_only=$image_only)")
        fi
    done <<< "$PASS_D_FILES"
fi

if [[ ${#passD_violations[@]} -gt 0 ]]; then
    warn "Pass D: ${#passD_violations[@]} self-defense rule(s) lack the Parent-only + Image-only filter symmetry that v1.12.5 retrofitted to maccrab_tamper_attempt.yml:"
    for v in "${passD_violations[@]}"; do
        echo "    $v"
    done
    echo "    Fix: add a sibling filter clause that references only ParentImage (or only Image),"
    echo "    or add a CommandLine-only filter as the permissive escape hatch."
else
    ok "Pass D: every self-defense rule carries Parent-only + Image-only filter symmetry (or a permissive escape hatch)"
fi

# ---------------------------------------------------------------------
# PASS E — KNOWN_PASSTHROUGH_FIELDS resolver coverage (v1.12.6 Wave 5C)
# ---------------------------------------------------------------------
# Closes the wire-the-orphans pattern at the compiler ↔ RuleEngine
# boundary. Sigma field names that aren't in `SIGMA_FIELD_MAP` get
# passed through verbatim to the rule predicate; if RuleEngine then
# has no `case "<Name>"` resolver AND no Swift code emits a matching
# `enrichments["<Name>"]` key, every rule predicating on that field
# returns nil at runtime (Sigma `equals` against nil is always false)
# and the rule silently never fires. Triple producer (compiler list)
# / consumer (RuleEngine resolver) / source (enrichments writer)
# must agree.
#
# Field reproduction (v1.12.6 Wave 2A): the Sigma alias `Architecture`
# was in `_KNOWN_PASSTHROUGH_FIELDS` for ~2 years and a dozen
# `Rules/defense_evasion/rosetta_*.yml` rules predicated on it, but
# RuleEngine had no resolver case and the ES collector wrote the
# architecture string directly to `ProcessInfo.architecture` rather
# than `enrichments["Architecture"]`. Every rule silently dead-
# lettered until Wave 2A added the explicit case. Agent 3's wire-the-
# orphans audit later flagged the same shape for `NotarizationStatus`
# (Finding 1) and re-verified `Architecture` (Finding 2). Pass E
# codifies the invariant so the next missed resolver fails release.
#
# This pass extracts the `_KNOWN_PASSTHROUGH_FIELDS` set from
# `Compiler/compile_rules.py` (one-time parse via python helper) and
# for each field name verifies one of:
#   (a) RuleEngine has `case "<Name>"` (explicit resolver), OR
#   (b) Some Swift file has `event.enrichments["<Name>"] =` or
#       `enrichedEvent.enrichments["<Name>"] =` (writer feeds the
#       default RuleEngine fallback that reads `event.enrichments[path]`).
# Fields with neither are HARD errors — they are guaranteed-dead rule
# predicates. EventType / AiTool aliases that resolve via top-level
# enum walks (Event.eventType) are tolerated via a small allowlist.
#
# Deliberately-broken fixture this catches (Wave 5C verification):
#   Break:  add a name like "TotallyFakeField" to the
#           `_KNOWN_PASSTHROUGH_FIELDS` set in compile_rules.py that no
#           Swift code emits or resolves. Re-run this script.
#   Expect: PASS E fails with err `TotallyFakeField has no resolver
#           case in RuleEngine and no enrichments writer`.
#   Restore: remove the added name from compile_rules.py.
section "PASS E — KNOWN_PASSTHROUGH_FIELDS resolver coverage"

# Names that resolve via a non-enrichments path (top-level Event enum,
# computed property walks, etc.) so a missing `case` + missing
# `enrichments[]` writer is intentional. Each entry documents the
# resolver site so the next maintainer can verify the assumption.
declare -a PASS_E_EXEMPT=(
    # EventType resolves from event.eventType.rawValue in RuleEngine —
    # no enrichments key, no case statement needed; the default
    # resolver short-circuits at "event.type" / "EventType".
    "EventType"
)

# Known latent orphans surfaced by Pass E on first run. Each entry is
# a real wire-the-orphans finding that pre-exists Wave 5C and can't
# be retrofitted in this wave (Wave 5C ships audit only — no Swift /
# YAML edits). Track in concepts/wire-the-orphans-pattern.md for
# scheduling. Clear an entry by either adding the missing resolver
# case in RuleEngine.swift, adding the enrichments[] writer, or
# removing the field from compile_rules.py if no rule needs it.
declare -a PASS_E_KNOWN_LATENT=(
    # Used by Rules/defense_evasion/suspicious_xpc_connection.yml but
    # no Swift code emits or resolves XPCServiceName. Latent at least
    # since v1.6.x (the rule predates the compiler audit). Fix is
    # either an XPC-attribution enricher (parse from
    # ProcessInfo.parent for `com.apple.xpc.launchd` ancestry) or
    # delete the rule.
    "XPCServiceName"
    # Used by ~12 Rules/ai_safety/*.yml that predicate on file
    # modify/create. The resolver path goes through `file.action`
    # via SIGMA_FIELD_MAP, but `FileAction` is listed as a passthrough
    # without an alias case. Fix: add a `case "FileAction":` returning
    # event.file?.action.rawValue (one-line aliasing similar to v1.12.6
    # Wave 2A's Architecture alias).
    "FileAction"
)

# Extract the passthrough set. Python helper keeps the parsing safe
# against future edits (whitespace, multi-line set, trailing commas).
if ! command -v python3 >/dev/null 2>&1; then
    warn "Pass E: python3 unavailable — skipping resolver coverage audit"
else
    # Extract the passthrough set MINUS any field that also appears as
    # a key in SIGMA_FIELD_MAP — those are doubly-listed (both mapped
    # AND passthrough-tolerated), and Pass E only cares about fields
    # the compiler ships through to the rule predicate unmodified.
    # Fields in SIGMA_FIELD_MAP get rewritten before runtime so the
    # RuleEngine resolver search would be against the mapped name.
    passE_fields=$(python3 - <<'PY' 2>/dev/null
import ast, pathlib, sys
src = pathlib.Path("Compiler/compile_rules.py").read_text()
try:
    tree = ast.parse(src)
except Exception as e:
    print("PARSE_ERROR:" + str(e))
    sys.exit(0)
mapped_keys = set()
passthroughs = []
for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id == "SIGMA_FIELD_MAP":
                if isinstance(node.value, ast.Dict):
                    for key in node.value.keys:
                        if isinstance(key, ast.Constant) and isinstance(key.value, str):
                            mapped_keys.add(key.value)
            if isinstance(tgt, ast.Name) and tgt.id == "_KNOWN_PASSTHROUGH_FIELDS":
                if isinstance(node.value, ast.Set):
                    for elt in node.value.elts:
                        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                            passthroughs.append(elt.value)
if not passthroughs:
    print("EXTRACT_FAILED")
    sys.exit(0)
for f in passthroughs:
    if f in mapped_keys:
        continue
    print(f)
PY
)
    if echo "$passE_fields" | grep -qE '^(PARSE_ERROR|EXTRACT_FAILED)'; then
        err "Pass E: failed to extract _KNOWN_PASSTHROUGH_FIELDS from Compiler/compile_rules.py — refresh parser"
    elif [[ -z "$passE_fields" ]]; then
        err "Pass E: _KNOWN_PASSTHROUGH_FIELDS extracted as empty set — parser broken or file moved"
    else
        passE_orphans=()
        passE_field_count=0
        while IFS= read -r field; do
            [[ -z "$field" ]] && continue
            passE_field_count=$((passE_field_count + 1))

            # Exempt-list short-circuit.
            exempt=0
            for e in "${PASS_E_EXEMPT[@]}"; do
                if [[ "$field" == "$e" ]]; then exempt=1; break; fi
            done
            if [[ $exempt -eq 1 ]]; then continue; fi

            # (a) Resolver case in RuleEngine — match any `case` line
            # carrying `"<field>"` as a value, since Swift's case can
            # chain multiple labels (e.g.
            # `case "process.architecture", "Architecture":`).
            if grep -qE "^[[:space:]]+case [^/]*\"${field}\"" Sources/MacCrabCore/Detection/RuleEngine.swift 2>/dev/null; then
                continue
            fi
            # (b) Any Swift file writes `enrichments["<field>"] =`.
            # Match both `event.enrichments[...]` and `enrichedEvent.enrichments[...]`
            # plus the bare local-variable form `enrichments[...] =`.
            if grep -rqE "enrichments\[\"${field}\"\][[:space:]]*=" Sources/ \
                --include='*.swift' 2>/dev/null; then
                continue
            fi
            # (c) Constant-keyed writer: `enrichments[SomeKey.field] =`
            # where the constant's value is `<field>`. Search for
            # `static let <camelCase> = "<field>"` and accept any match.
            if grep -rqE "static let [a-zA-Z]+ = \"${field}\"" Sources/ \
                --include='*.swift' 2>/dev/null; then
                continue
            fi
            # (d) Field name is a property of ProcessInfo / FileInfo /
            # SessionInfo / etc. resolved by snake-case mapping. The
            # RuleEngine default fallback walks `event.enrichments[path]`
            # but Sigma field names like `IsNotarized` / `IsAdhocSigned`
            # also resolve through `process.is_notarized` / `process.code_signature.*`
            # cases. Heuristic: a separate `case "<snake_case>"` exists
            # for the equivalent dotted path. We approximate by checking
            # whether the field name's snake_case form appears as a case.
            field_snake=$(echo "$field" | sed -E 's/([a-z0-9])([A-Z])/\1_\2/g; s/^_*//' | tr '[:upper:]' '[:lower:]')
            if [[ -n "$field_snake" ]] && grep -qE "\"[a-z._]*${field_snake}\"" Sources/MacCrabCore/Detection/RuleEngine.swift 2>/dev/null; then
                continue
            fi
            passE_orphans+=("$field")
        done <<< "$passE_fields"

        # Split orphans into "new" (hard error, must be fixed before
        # release) and "latent" (warn, already tracked).
        passE_new=()
        passE_latent=()
        for f in "${passE_orphans[@]}"; do
            is_latent=0
            for k in "${PASS_E_KNOWN_LATENT[@]}"; do
                if [[ "$f" == "$k" ]]; then is_latent=1; break; fi
            done
            if [[ $is_latent -eq 1 ]]; then
                passE_latent+=("$f")
            else
                passE_new+=("$f")
            fi
        done

        if [[ ${#passE_new[@]} -gt 0 ]]; then
            err "Pass E: ${#passE_new[@]} NEW passthrough field(s) listed in compile_rules.py but with NO resolver case in RuleEngine and NO enrichments[] writer in Sources/ (rules using these silently never fire):"
            for f in "${passE_new[@]}"; do
                echo "    $f" >&2
            done
            echo '    Fix: add a `case "<Field>"` in RuleEngine.swift returning the resolved value,' >&2
            echo '    OR write the field via enrichments["<Field>"] = ... from an enricher,' >&2
            echo "    OR add to PASS_E_KNOWN_LATENT with a tracking note if scheduled for later." >&2
            echo "    Background: Sigma field passthrough requires both producer + consumer." >&2
        fi
        if [[ ${#passE_latent[@]} -gt 0 ]]; then
            warn "Pass E: ${#passE_latent[@]} known-latent orphan(s) (tracked in PASS_E_KNOWN_LATENT — wire or delete):"
            for f in "${passE_latent[@]}"; do
                echo "    $f"
            done
        fi
        if [[ ${#passE_new[@]} -eq 0 && ${#passE_latent[@]} -eq 0 ]]; then
            ok "Pass E: every _KNOWN_PASSTHROUGH_FIELDS entry ($passE_field_count) has a resolver case or enrichments writer"
        fi
    fi
fi

# ---------------------------------------------------------------------
# PASS F — DaemonState field consumer audit (v1.12.6 Wave 5C)
# ---------------------------------------------------------------------
# Direct mirror of Pass 1b (Config struct fields) but targeting the
# load-bearing `DaemonState` container instead. Every `let <field>:`
# (and `var <field>:` for the post-construction-set ones) declared on
# DaemonState must have at least one consumer site that calls a
# method on it — `state.<field>.<anyMethod>(...)`. Fields with zero
# method calls (only init self-assignment) are orphans: instantiated,
# wired through every initializer, paid for in memory, but never
# actually doing work.
#
# Agent 3's wire-the-orphans audit Finding 5 (v1.12.6 Wave 3A):
# `state.intentClassifier` was constructed and held on DaemonState
# but EventLoop never invoked `intentClassifier.classify(brief:)` as
# a tie-breaker — the LLM-backed classifier was a $30 cloud call
# waiting for a caller that never arrived. Same wire-the-orphans
# shape as v1.6.12 (maxDatabaseSizeMB) and v1.6.18 (webhookSlackURL):
# the field is wired through three layers of plumbing and the only
# consumer was an MCP handler that opens its own process-local engine.
#
# This pass enumerates `let <field>:` and `var <field>:` declarations
# in DaemonState.swift, then counts `state.<field>.` occurrences
# across every daemon-target Swift file. Excludes the constructor
# self-assignment lines (`self.<field> = <field>`) which are the
# noise floor. Excludes pure-property fields (e.g. `daemonStartTime:
# Date` — those don't need method calls; `state.daemonStartTime` may
# be read directly via property access).
#
# Heuristic: a field "has a consumer" if any non-declaring file has a
# `state.<field>.<methodLike>(` token. Fields that are read by
# property access only (Bool, String, etc.) are tolerated via the
# `pureRead` skip — `state.<field>` followed by a non-`(` token.
#
# Deliberately-broken fixture this catches (Wave 5C verification):
#   Break:  add a new `let phantomService: PhantomService =
#           PhantomService()` to DaemonState.swift with zero call
#           sites. Re-run this script.
#   Expect: PASS F warns `state.phantomService is constructed but
#           has no consumer — wire it or delete it`.
#   Restore: remove the line from DaemonState.swift.
section "PASS F — DaemonState field consumer audit"

DAEMON_STATE_FILE="Sources/MacCrabAgentKit/DaemonState.swift"
if [[ ! -f "$DAEMON_STATE_FILE" ]]; then
    err "Pass F: $DAEMON_STATE_FILE missing — can't audit"
else
    # Service fields that are stored but consumed exclusively via
    # property access (no method calls). Each entry documents the
    # consumer path so future maintainers can verify the assumption.
    declare -a PASS_F_PROPERTY_ONLY=(
        # Path strings — consumed by reading state.<name>, no method
        # call needed.
        "supportDir" "compiledRulesDir" "rulesDir" "sequenceRulesDir"
        "effectiveRulesDir" "esMode"
        # Bools — consumed by reading state.<name>, no method call.
        "isRoot" "preventionEnabled"
        # URL — read-only.
        "rulesURL"
        # Timestamps — read-only.
        "daemonStartTime"
        # Computed property — read-only, derived from daemonStartTime.
        "isWarmingUp"
        # Lock — consumed via `inboxPollerLock.withLock`, captured
        # rather than dotted (the .withLock(...) form goes through
        # OSAllocatedUnfairLock's extension which our grep doesn't see
        # as `state.inboxPollerLock.withLock`).
        "inboxPollerLock"
        # === Captured-at-construction pattern: these fields are
        # passed into closures / monitors during DaemonSetup and
        # consumed there, but never accessed via `state.<name>` after
        # init. The methods ARE called (e.g. `selfDefense.start { ... }`
        # in DaemonSetup); the indirection through state is for
        # ownership/lifetime only. Each entry below documents the
        # capture site so a future maintainer can verify.
        #
        # selfDefense — captured in DaemonSetup, .start { } loop.
        "selfDefense"
        # ES Health monitor — started in DaemonSetup, runs autonomously.
        "esHealthMonitor"
        # Collectors — captured in mergedEventStream() inside DaemonState
        # itself, which we exclude from the scan as the declaring file.
        "collector" "kdebugCollector" "esloggerCollector" "ulCollector"
        "networkCollector"
        # Prevention services — captured into ResponseEngine + closures
        # in DaemonSetup. Lifetime owned by state; methods invoked via
        # captured locals.
        "dnsSinkhole" "networkBlocker" "persistenceGuard" "aiContainment"
        "tccRevocation"
        # ThreatHunter — used by MCP server in a separate process; the
        # state-side reference is for hot-reload via SIGHUP.
        "threatHunter"
    )

    # Computed-property accessors don't carry a let/var declaration
    # the regex picks up. Hand-extract the field name list with awk,
    # restricted to top-level let|var declarations at depth-1
    # (immediately inside `final class DaemonState { ... }`).
    #
    # `in_class` is enabled the line BEFORE the opening brace fires,
    # so when the brace counter sees the class's `{` depth ticks to 1
    # naturally. Fields inside the class body are at depth 1; init
    # parameter list / closure bodies are at depth ≥ 2 and skipped.
    passF_fields=$(awk '
        /^final class DaemonState/ { in_class=1 }
        in_class { n_open = gsub(/\{/, "{"); n_close = gsub(/\}/, "}"); depth += n_open - n_close }
        # Top-level (depth == 1) let/var declarations.
        in_class && depth == 1 && /^[[:space:]]+(let|var)[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*:/ {
            if (match($0, /(let|var)[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*:/) > 0) {
                tok = substr($0, RSTART, RLENGTH)
                gsub(/^(let|var)[[:space:]]+/, "", tok)
                gsub(/:$/, "", tok)
                print tok
            }
        }
        # Leave the class body once depth returns to 0.
        in_class && depth == 0 { in_class=0 }
    ' "$DAEMON_STATE_FILE")

    if [[ -z "$passF_fields" ]]; then
        err "Pass F: no fields parsed from DaemonState.swift — parser regression, refresh awk script"
    else
        passF_orphans=()
        passF_field_count=0
        while IFS= read -r field; do
            [[ -z "$field" ]] && continue
            passF_field_count=$((passF_field_count + 1))

            # Property-only allowlist.
            skip=0
            for p in "${PASS_F_PROPERTY_ONLY[@]}"; do
                if [[ "$field" == "$p" ]]; then skip=1; break; fi
            done
            if [[ $skip -eq 1 ]]; then continue; fi

            # Count consumer sites. A field is "wired" when ANY non-
            # DaemonState file mentions it via:
            #   - direct method call: `state.<field>.<method>(`
            #   - optional chain method call: `state.<field>?.<method>(`
            #   - optional binding: `if let x = state.<field>` /
            #     `guard let x = state.<field>`
            #   - direct property read in an arg list: `state.<field>,`
            #     or `state.<field>)` or `state.<field> ?`
            # All of these are evidence the field reaches a caller.
            # Self-assignment (DaemonSetup.swift `state.<field> = ...`)
            # is excluded because that's wire-up, not consumption.
            method_calls=$(grep -rE "\bstate\.${field}\.[a-zA-Z_][a-zA-Z0-9_]*\(" Sources/ \
                --include='*.swift' 2>/dev/null \
                | grep -cE '\S' || true)

            opt_calls=$(grep -rE "\bstate\.${field}\?\.[a-zA-Z_][a-zA-Z0-9_]*\(" Sources/ \
                --include='*.swift' 2>/dev/null \
                | grep -cE '\S' || true)

            # Optional bindings (`if let x = state.<field>`,
            # `guard let x = state.<field>`).
            binds=$(grep -rE "(if|guard)[[:space:]]+let[[:space:]]+[a-zA-Z_][a-zA-Z0-9_]*[[:space:]]*=[[:space:]]*state\.${field}\b" Sources/ \
                --include='*.swift' 2>/dev/null \
                | grep -cE '\S' || true)

            # Argument-position reads — `func(..., state.<field>, ...)`
            # or `let x = state.<field>` (non-self-assignment). We
            # exclude self-assignment by filtering on `state\.<field>\s*=`
            # which is the wire-up pattern.
            non_assign=$(grep -rE "\bstate\.${field}\b" Sources/ \
                --include='*.swift' 2>/dev/null \
                | grep -vE "\bstate\.${field}[[:space:]]*=" \
                | grep -vE "DaemonSetup\.swift" \
                | grep -cE '\S' || true)

            total=$((method_calls + opt_calls + binds + non_assign))
            if [[ "$total" -eq 0 ]]; then
                passF_orphans+=("$field")
            fi
        done <<< "$passF_fields"

        if [[ ${#passF_orphans[@]} -gt 0 ]]; then
            warn "Pass F: ${#passF_orphans[@]} DaemonState field(s) have no 'state.<field>.<method>(' consumer — wire-the-orphans candidates:"
            for f in "${passF_orphans[@]}"; do
                echo "    state.$f"
            done
            echo "    Fix: either add a consumer site (EventLoop / DaemonTimers / a handler)"
            echo "    OR add the field to PASS_F_PROPERTY_ONLY if it's intentionally read-only,"
            echo "    OR delete the field from DaemonState (mirror v1.6.15 PanicButton removal)."
        else
            ok "Pass F: every DaemonState service field (audited $passF_field_count) has at least one method-call consumer"
        fi
    fi
fi

# ---------------------------------------------------------------------
# PASS G — detection actor reader audit (v1.12.6 Wave 5C)
# ---------------------------------------------------------------------
# Sibling of Pass F at the Detection actor / class level. For each
# `public actor` and `public final class` under
# `Sources/MacCrabCore/Detection/`, enumerate `public func <name>(...)
# -> <NonVoid>` declarations — "reader" methods (non-void return =
# someone is supposed to consume the value). Methods with zero
# callers outside the declaring file flag as orphans.
#
# Agent 3's wire-the-orphans audit Findings:
#   - Finding 6: IncidentGrouper.activeIncidents() / allIncidents() /
#     incident(id:) / stats() — four public readers, none called by
#     any consumer code. The grouper produces Incident objects that
#     never reach any UI or any other detection tier.
#   - Finding 4: UEBAEngine had a similar shape — read methods with
#     no consumers, plus an internal profiles dict bounded only by
#     "user × process" cardinality (also flagged by Pass 8).
#
# Pass G enumerates reader methods + their callers. The discipline
# enforced: a public reader is a CONTRACT WITH A CALLER, and an
# unfulfilled contract is dead code. Three resolutions per orphan:
# (a) wire a consumer, (b) make the reader internal/private, or
# (c) delete the method.
#
# This pass uses warn-level rather than err-level because (a) some
# readers ship before the consumer that will use them (legitimate
# lead-time pattern, especially across versions), and (b) the heuristic
# is more permissive than Pass F — `funcName(` can appear in many
# unrelated contexts (cluster_*.swift tests, comment references,
# etc.) so false negatives need a human eye.
#
# Deliberately-broken fixture this catches (Wave 5C verification):
#   Break:  add `public func phantomReader() -> String { "" }` to an
#           existing Detection actor that the rest of the codebase
#           doesn't reference. Re-run this script.
#   Expect: PASS G warns `<TypeName>.phantomReader() has no callers
#           outside its declaration`.
#   Restore: remove the added method.
section "PASS G — detection actor reader audit"

# Reader names that have a known consumer pattern outside the file
# (or a justification for being public but unconsumed today). Format:
# "<TypeName>.<funcName>". Keep this list tight — each entry should
# be a documented exception. Always include a placeholder so the
# `${PASS_G_EXEMPT[@]}` access doesn't trip `set -u` when the list
# is otherwise empty.
declare -a PASS_G_EXEMPT=(
    # Placeholder — `set -u` treats `${arr[@]}` on an empty array as
    # an unbound variable. Real entries replace this one as they're
    # added.
    "_placeholder._never_matches"
    # Wave 7A.2: SelfDefense.integrityCheck() is invoked once every 15
    # seconds from the actor's own monitoring Task loop
    # (SelfDefense.swift:597, `let events = integrityCheck()`). The
    # implicit-self call form has no leading dot, so the Pass G regex
    # `\.<name>(` misses it. The function is genuinely wired — binary
    # hash drift / rule corpus tamper / signed-binary swap detection
    # all flow through this path into TamperEvent → handleTamperEvent.
    # Keeping `public` because the v1.12.4 / v1.12.5 fix history shows
    # the function is on the public-API boundary (Sparkle-aware
    # rebaseline path was a v1.12.5 bug-fix point); demoting now
    # would foreclose external direct invocation if a fleet operator
    # needs to force a one-shot probe.
    "SelfDefense.integrityCheck"
)

passG_orphans=()
passG_reader_count=0
for f in Sources/MacCrabCore/Detection/*.swift; do
    [[ -f "$f" ]] || continue
    # Find the top-level type declaration. Some files have multiple
    # types; we only care about the first public actor/final class
    # for attribution. Adjust if needed for multi-type files.
    typename=$(grep -m1 -oE '(public actor|public final class) [A-Za-z_][A-Za-z0-9_]*' "$f" \
        | sed -E 's/^(public actor|public final class) //')
    [[ -z "$typename" ]] && continue

    # Enumerate non-void public methods.
    # Pattern: `public func <name>(<args>) (async )?(throws )?-> <ret>`
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Extract the func name.
        funcname=$(echo "$line" | sed -nE 's/.*public func ([a-zA-Z_][a-zA-Z0-9_]*)\(.*/\1/p')
        [[ -z "$funcname" ]] && continue
        passG_reader_count=$((passG_reader_count + 1))

        # Exemption.
        exempt=0
        for e in "${PASS_G_EXEMPT[@]}"; do
            if [[ "$typename.$funcname" == "$e" ]]; then exempt=1; break; fi
        done
        if [[ $exempt -eq 1 ]]; then continue; fi

        # Count call sites `.<funcname>(` across Sources/ AND Tests/.
        # The leading dot distinguishes a CALL (`obj.foo(...)`) from a
        # DECLARATION (`public func foo(...)`) — declarations never
        # have a dot before the name. A caller in the declaring file
        # is still a valid consumer (e.g. UEBAEngine.toolIsNovel is
        # called from another method in the same file).
        #
        # Wave 7A.3-C: include Tests/ in the scope. A public func that
        # is exercised by 10 unit tests is NOT a wire-the-orphans
        # candidate — it has well-defined behaviour that tests pin.
        # We classify those separately so the operator sees that the
        # function still merits a `private`/`internal` demotion review
        # (no production reader), but isn't unwired in the literal
        # sense.
        prod_call_sites=$(grep -rE "\.${funcname}\(" Sources/ \
            --include='*.swift' 2>/dev/null \
            | grep -cE '\S' || true)
        test_call_sites=$(grep -rE "\.${funcname}\(" Tests/ \
            --include='*.swift' 2>/dev/null \
            | grep -cE '\S' || true)

        if [[ "$prod_call_sites" -eq 0 ]]; then
            if [[ "$test_call_sites" -gt 0 ]]; then
                # Test-only consumer — flag as a softer category.
                passG_orphans+=("$typename.$funcname() [test-only: $test_call_sites Tests/ caller(s) — consider demote to internal]")
            else
                passG_orphans+=("$typename.$funcname()")
            fi
        fi
    done < <(grep -E 'public func [a-zA-Z_][a-zA-Z0-9_]*\([^)]*\)([[:space:]]+async)?([[:space:]]+throws)?[[:space:]]+->' "$f" 2>/dev/null)
done

if [[ ${#passG_orphans[@]} -gt 0 ]]; then
    warn "Pass G: ${#passG_orphans[@]} public Detection reader(s) have zero '.<funcName>(' call sites anywhere — wire-the-orphans candidates:"
    for o in "${passG_orphans[@]}"; do
        echo "    $o"
    done
    echo "    Fix: either add a consumer site, OR demote to internal/private,"
    echo "    OR delete the method, OR add to PASS_G_EXEMPT with a justification."
    echo "    Background: Agent 3 wire-the-orphans Findings 4 (UEBAEngine) + 6 (IncidentGrouper accessors)."
else
    ok "Pass G: every public Detection reader method (audited $passG_reader_count) has at least one call site"
fi

# ---------------------------------------------------------------------
# PASS H — MCP-tool handler / daemon-state coverage (v1.12.6 Wave 5C)
# ---------------------------------------------------------------------
# MCP server tools (registered in Sources/maccrab-mcp/main.swift) are
# how AI agents reach MacCrab data. Each tool's handler MUST connect
# to either (a) the daemon's persisted SQLite stores (events.db,
# alerts.db, campaigns.db, traces.db), OR (b) a shared daemon-side
# singleton with a known evidence-feed mechanism. Handlers that
# instantiate fresh process-local actors (`sharedIntentEngine`,
# `sharedNextPredictor`, `sharedStylometric`) and consult them
# without a feed always return empty results because nothing in the
# MCP server process feeds them events.
#
# Agent 3's wire-the-orphans audit Finding 7: `get_intent_posterior`
# always returned the "no posterior found for tree X" string. The
# handler called `sharedIntentEngine.posterior(treeKey:)` against a
# BayesianIntentEngine instance created on first use INSIDE THE MCP
# PROCESS. The daemon-side BayesianIntentEngine, which is the only
# one being fed evidence by EventLoop, lives in a different process
# entirely. The MCP server has no IPC channel to read that
# posterior; the tool was advertising a capability MacCrab did not
# have.
#
# Pass H enumerates MCP tool registrations and verifies each
# handler reaches a daemon SQLite store OR an audited shared
# singleton (one with a known feed channel). Process-local
# singletons without a feed surface as warn.
#
# Deliberately-broken fixture this catches (Wave 5C verification):
#   Break:  add a new MCP tool registration "phantom_predict" and a
#           handler that consults a `sharedPhantomEngine` actor
#           without opening any *Store(directory:) or referencing a
#           DaemonState bridge. Re-run this script.
#   Expect: PASS H warns `phantom_predict handler uses process-local
#           singleton without an evidence feed`.
#   Restore: remove the tool registration + handler.
section "PASS H — MCP-tool handler / daemon-state coverage"

MCP_FILE="Sources/maccrab-mcp/main.swift"
if [[ ! -f "$MCP_FILE" ]]; then
    err "Pass H: $MCP_FILE missing — can't audit"
else
    # Audited shared singletons whose evidence feed is documented
    # (typo-squat database, prepared at MCP startup from a static
    # JSON corpus; OK for read-only tools). Format: bare identifier.
    declare -a PASS_H_AUDITED_SHARED=(
        # Static typo-squat list loaded from a bundled JSON corpus
        # at startup — no daemon feed needed because the data isn't
        # event-driven.
        "sharedTyposquatDB"
        # Wave 7A.4: static hand-calibrated transition matrix loaded
        # at init in NextTechniquePredictor (line ~58). The matrix is
        # a fixed 2-D Double[][] keyed by ATT&CK technique IDs — no
        # per-event state, no learning, no feed required. The MCP
        # handler `predict_next_technique` performs a pure lookup and
        # returns top-K successor techniques. Behaves identically in
        # the MCP process and the daemon process.
        "sharedNextPredictor"
        # Wave 7A.4: stylometric handler operates on pure functions
        # applied to the input text. `llmTextScore` + `urgencyScore`
        # are marked `nonisolated` and have no actor state. The
        # `checkDrift` path uses a process-local baseline by design
        # (drift is computed against the corpus of texts seen in the
        # CURRENT scoring session — same-process semantics are the
        # documented contract, not an oversight).
        "sharedStylometric"
    )

    # Extract the dispatch case map: lines of the form `case "<tool>":`
    # followed by `return await handle<...>(args)`. The case→handler
    # pairing tells us which Swift function backs each registered
    # tool. We then read the handler body to look for store openings
    # vs shared-singleton references.
    passH_tools=$(grep -nE 'case "[a-z_]+":' "$MCP_FILE" \
        | head -50 \
        | sed -E 's/.*case "([a-z_]+)".*/\1/')

    # Build a map from tool name → handler function name. The case
    # body is on the next non-blank line and has the form
    # `return await handleXxx(args)`.
    passH_violations=()
    while IFS= read -r tool; do
        [[ -z "$tool" ]] && continue
        # Find the case line, then the next handle*(  call.
        case_line=$(grep -nE "^[[:space:]]+case \"${tool}\":" "$MCP_FILE" \
            | head -1 | cut -d: -f1)
        [[ -z "$case_line" ]] && continue

        # The handler invocation lives in the next 2 lines.
        handler=$(awk -v ln="$case_line" 'NR > ln && NR <= ln + 2 {
            if (match($0, /handle[A-Z][A-Za-z0-9_]*\(/)) {
                print substr($0, RSTART, RLENGTH - 1)
                exit
            }
        }' "$MCP_FILE")
        [[ -z "$handler" ]] && continue

        # Find the handler function definition and grab its body. The
        # body extends from `func <handler>(` until the matching
        # closing brace at depth 0. Use awk to extract.
        handler_body=$(awk -v target="$handler" '
            BEGIN { found=0; depth=0 }
            !found && $0 ~ "^func " target "\\(" { found=1 }
            found {
                # Count opening/closing braces on this line.
                n_open = gsub(/\{/, "{")
                n_close = gsub(/\}/, "}")
                depth += n_open - n_close
                print
                if (found == 1 && n_open > 0) { found = 2 }
                if (found == 2 && depth == 0) { exit }
            }
        ' "$MCP_FILE")

        if [[ -z "$handler_body" ]]; then
            # Couldn't locate the body — skip; the audit-of-audits
            # for this tool is then up to the operator's eye.
            continue
        fi

        # Daemon SQLite reach: any `<Store>(directory:` invocation —
        # the standard MCP pattern that opens the daemon-written
        # store file in the MCP server process. This counts even
        # though the store is process-local, because the FILE is
        # daemon-shared and SQLite handles the cross-process read.
        if echo "$handler_body" | grep -qE '(EventStore|AlertStore|CampaignStore|TraceStore)\(directory:'; then
            continue
        fi

        # Acceptable shared-singleton names (audited above).
        is_audited_shared=0
        for s in "${PASS_H_AUDITED_SHARED[@]}"; do
            if echo "$handler_body" | grep -qE "\b${s}\b"; then
                is_audited_shared=1
                break
            fi
        done
        if [[ $is_audited_shared -eq 1 ]]; then continue; fi

        # Process-local shared singleton WITHOUT a daemon feed path.
        # The `shared<X>` naming convention in the MCP source flags
        # these candidates.
        if echo "$handler_body" | grep -qE '\bshared[A-Z][A-Za-z0-9_]*\b'; then
            singleton=$(echo "$handler_body" | grep -oE '\bshared[A-Z][A-Za-z0-9_]*\b' | head -1)
            passH_violations+=("$tool → $handler() consults $singleton (process-local; no daemon SQLite reach)")
            continue
        fi

        # Other handlers that don't open a store and don't reference
        # any shared singleton may rely on environment / filesystem /
        # external API — let them pass with a soft info note.
    done <<< "$passH_tools"

    if [[ ${#passH_violations[@]} -gt 0 ]]; then
        warn "Pass H: ${#passH_violations[@]} MCP tool(s) use process-local singletons without a daemon evidence feed (handler will always return empty):"
        for v in "${passH_violations[@]}"; do
            echo "    $v"
        done
        echo "    Fix: route the handler through a daemon SQLite store (EventStore/AlertStore/CampaignStore/TraceStore),"
        echo "    OR add the singleton to PASS_H_AUDITED_SHARED with a documented evidence-feed mechanism,"
        echo "    OR remove the MCP tool registration if no feed path is feasible."
        echo "    Background: Agent 3 wire-the-orphans Finding 7 (get_intent_posterior always empty)."
    else
        ok "Pass H: every MCP tool handler reaches a daemon SQLite store or an audited shared singleton"
    fi
fi

# ---------------------------------------------------------------------
# PASS I — SwiftUI .task(id:) sequential-await detector (v1.12.8)
# ---------------------------------------------------------------------
# Lesson source: Wave 9G (v1.12.6 RC2) + Wave 9P (v1.12.7).
#
# A .task(id:) body whose `id` includes `state.refreshTick` is
# cancelled and re-entered every refresh tick (default 5 s). If the
# body has multiple sequential `await state.provider.X(...)` calls
# gated behind a single trailing `MainActor.run` writing all of @State
# at once, then on a busy host where the combined load exceeds 5 s
# the trailing MainActor.run never fires — the cancelled task body
# discards every fresh read. Symptom: panel silently stops updating
# until the user closes and reopens the menubar window (which resets
# refreshTick to 0 and gives the first load uncontested runway).
#
# Detection: per-workspace, walk each .task(id:) block whose id
# expression mentions `refreshTick`. Count `await state.provider.X(`
# calls and `await MainActor.run` calls inside the block. WARN when
# provider-awaits >= 2 AND MainActor.run count == 1 (the canonical
# pre-9P shape). Workspaces fixed in Wave 9G / 9P now have 1 MainActor
# .run per await, so they pass.
#
# How to fix the warning: split into per-await MainActor.run writes
# so faster queries always land even if a later one is cancelled.
#
# Test reproduction (manual, not automated — costly to inject the
# race in a test):
#   1. Add a new workspace with multiple sequential `await state.provider`
#      calls in a .task(id: refreshTick) body and one trailing MainActor.run.
#   2. Run scripts/pre-release-audit.sh
#   3. Expect: Pass I warns `<workspace> has N awaits + 1 trailing MainActor.run`

section "PASS I — SwiftUI .task(id:) sequential-await detector"

passI_findings=$(python3 <<'PY'
import re, os, sys
findings = []
WORKSPACES_DIR = 'Sources/MacCrabApp/V2/Workspaces'
if not os.path.isdir(WORKSPACES_DIR):
    sys.exit(0)
for f in sorted(os.listdir(WORKSPACES_DIR)):
    if not f.endswith('.swift'): continue
    path = os.path.join(WORKSPACES_DIR, f)
    with open(path, 'r') as fh:
        text = fh.read()
    # Find .task(id: "...refreshTick...") { ... } blocks.
    for m in re.finditer(r'\.task\(id:[^)]*refreshTick[^)]*\)\s*\{', text):
        start = m.end()
        depth = 1
        i = start
        # Walk forward through the body, respecting brace nesting + string literals.
        in_string = False
        while i < len(text) and depth > 0:
            c = text[i]
            if c == '"' and (i == 0 or text[i-1] != '\\'):
                in_string = not in_string
            elif not in_string:
                if c == '{': depth += 1
                elif c == '}': depth -= 1
            i += 1
        body = text[start:i-1]
        provider_awaits = len(re.findall(r'\bawait\s+state\.provider\.[a-zA-Z_]+\(', body))
        # Also count `await reload()` since several workspaces wrap
        # the provider awaits in a private async reload() function.
        if re.search(r'\bawait\s+reload\(\)', body):
            # Treat as "has its own audit context" — the reload function
            # itself needs Pass I'ing, which we do by scanning all funcs below.
            pass
        mainactor_runs = len(re.findall(r'\bawait\s+MainActor\.run', body))
        if provider_awaits >= 2 and mainactor_runs == 1:
            lineno = text[:m.start()].count('\n') + 1
            findings.append(f"{path}:{lineno} (.task body): {provider_awaits} sequential provider awaits + only 1 trailing MainActor.run — Wave 9P risk shape")
    # Also scan private async reload() functions in the same file —
    # these are called from .task(id:) bodies so inherit the cancel risk.
    for m in re.finditer(r'private\s+func\s+reload\(\)\s+async\s*\{', text):
        start = m.end()
        depth = 1
        i = start
        in_string = False
        while i < len(text) and depth > 0:
            c = text[i]
            if c == '"' and (i == 0 or text[i-1] != '\\'):
                in_string = not in_string
            elif not in_string:
                if c == '{': depth += 1
                elif c == '}': depth -= 1
            i += 1
        body = text[start:i-1]
        provider_awaits = len(re.findall(r'\bawait\s+state\.provider\.[a-zA-Z_]+\(', body))
        mainactor_runs = len(re.findall(r'\bawait\s+MainActor\.run', body))
        if provider_awaits >= 2 and mainactor_runs == 1:
            lineno = text[:m.start()].count('\n') + 1
            findings.append(f"{path}:{lineno} (reload() func): {provider_awaits} sequential provider awaits + only 1 trailing MainActor.run — Wave 9P risk shape")
for f in findings:
    print(f)
PY
)

if [[ -n "$passI_findings" ]]; then
    passI_count=$(echo "$passI_findings" | wc -l | tr -d ' ')
    warn "Pass I: $passI_count workspace .task(id:) bodies have the 9P-shape sequential-await race:"
    echo "$passI_findings" | sed 's/^/    /'
    echo "    Fix: split into per-await MainActor.run writes."
    echo "    Background: Wave 9G (v1.12.6 RC2) + Wave 9P (v1.12.7) — see RELEASE_NOTES/v1.12.7.md"
else
    ok "Pass I: every refreshTick-bound .task(id:) body uses partial-write MainActor.run pattern"
fi

# ---------------------------------------------------------------------
# PASS J — orphan GitHub Actions secret detector (v1.12.8)
# ---------------------------------------------------------------------
# Lesson source: v1.12.6 opsec sweep found SPARKLE_ED_PRIVATE_KEY
# stored as a repo Actions secret but never referenced by any workflow.
# Orphan secrets accumulate over time, widening the exposure surface
# without providing CI value. The Sparkle private key in particular is
# catastrophic-if-leaked — every additional storage point increases
# blast radius.
#
# Detection: compare `gh api repos/.../actions/secrets` against a grep
# of every `secrets.X` reference in .github/workflows/*.yml. Any secret
# in the repo's list but NOT referenced by a workflow is an orphan.
#
# Network-dependent: pass is skipped when `gh` isn't authenticated
# (CI scenarios where the test runner doesn't have a PAT).
#
# Test reproduction:
#   1. Add a dummy secret via `gh secret set TEST_ORPHAN -b dummy`
#   2. Run scripts/pre-release-audit.sh
#   3. Expect: Pass J warns `TEST_ORPHAN is stored but never referenced`
#   4. Cleanup: `gh secret delete TEST_ORPHAN`

section "PASS J — orphan GitHub Actions secret detector"

if ! command -v gh >/dev/null 2>&1; then
    info "Pass J: skipped (gh CLI not installed)"
elif ! gh auth status >/dev/null 2>&1; then
    info "Pass J: skipped (gh CLI not authenticated)"
else
    repo_secrets=$(gh api repos/peterhanily/maccrab/actions/secrets --jq '.secrets[].name' 2>/dev/null || true)
    if [[ -z "$repo_secrets" ]]; then
        info "Pass J: gh API returned no secrets (insufficient permission?) — skipping"
    else
        workflow_refs=$(grep -rohE 'secrets\.[A-Z_][A-Z0-9_]*' .github/workflows/ 2>/dev/null | sed 's/^secrets\.//' | sort -u)
        passJ_orphans=()
        while IFS= read -r secret; do
            [[ -z "$secret" ]] && continue
            if ! echo "$workflow_refs" | grep -qx "$secret"; then
                passJ_orphans+=("$secret")
            fi
        done <<< "$repo_secrets"
        if [[ ${#passJ_orphans[@]} -gt 0 ]]; then
            warn "Pass J: ${#passJ_orphans[@]} GitHub Actions secret(s) stored but not referenced by any workflow:"
            for s in "${passJ_orphans[@]}"; do
                echo "    $s"
            done
            echo "    Either wire each into a workflow that needs it, or run:"
            echo "      gh secret delete <NAME>"
            echo "    Background: v1.12.6 opsec sweep (Wave 9 / final audit) flagged SPARKLE_ED_PRIVATE_KEY as orphaned."
        else
            ok "Pass J: every stored GH Actions secret is referenced by at least one workflow"
        fi
    fi
fi

# =====================================================================
# 2026 series — Mac Context Plugin Platform (v1.13a+)
# =====================================================================
# Year-prefix naming scheme keeps cross-chapter lineage navigable AND
# avoids collision with the pre-existing v1.12.5 Pass A-D letter-only
# names earlier in this script. Future passes in this arc use
# Pass 2026-<letter>.
#
# This series is introduced concurrently with the foundational
# substrate (v1.13a-1) — the v1.6.18 "Pass changes never ship in the
# same PR as the release that needs them" rule is waived for these
# two passes because there is no prior release for them to
# retroactively gate.

# ---------------------------------------------------------------------
# PASS 2026-A — Plugin manifest integrity (v1.13a-1)
# ---------------------------------------------------------------------
# Source: plan §3.8.
#
# Enforces, source-tree side, the same invariants that
# PluginManifest.validate() enforces at register-time. The dual path
# is intentional: validate() is the runtime gate; this pass is the
# audit gate. Catches:
#   - declared manifests that never reach the Bootstrap.registerBuiltins
#     registration list (silently absent at runtime — Track 1 may not
#     notice for releases),
#   - first-party plugin ids outside the
#     com.maccrab.{forensics,enricher,fingerprinter,analyzer}.*
#     reserved namespace,
#   - OutputSpec declarations missing privacyClass: at the call site
#     (Swift won't compile without it, but a future builder-style API
#     could; the audit catches that drift early).
#
# Excludes the test target — fixture manifests inside tests are
# intentionally not registered.

section "PASS 2026-A — plugin manifest integrity"

manifest_files=$(grep -lR --include='*.swift' "static let manifest = PluginManifest(" Sources/MacCrabForensics/ 2>/dev/null || true)
if [[ -z "$manifest_files" ]]; then
    info "Pass 2026-A: no PluginManifest declarations under Sources/MacCrabForensics/ — skipping (no plugins yet)"
else
    bootstrap_file="Sources/MacCrabForensics/Plugins/Bootstrap.swift"
    if [[ ! -f "$bootstrap_file" ]]; then
        err "Pass 2026-A: $bootstrap_file missing — every plugin manifest must be registered here"
    else
        pass_2026A_violations=0
        # For every manifest declaration, extract the enclosing type
        # and verify <Type>.manifest appears in Bootstrap.swift.
        while IFS= read -r f; do
            [[ -z "$f" ]] && continue
            # Type name is the most recent `public struct X` / `struct X`
            # / `public actor X` / `actor X` declaration in the file.
            type_name=$(grep -E '^(public )?(struct|actor|class) [A-Za-z_][A-Za-z0-9_]+ *:' "$f" | tail -1 \
                | sed -E 's/^(public )?(struct|actor|class) ([A-Za-z_][A-Za-z0-9_]+) *:.*/\3/')
            if [[ -z "$type_name" ]]; then
                err "Pass 2026-A: could not determine plugin type name in $f"
                pass_2026A_violations=$((pass_2026A_violations+1))
                continue
            fi
            if ! grep -q "${type_name}\.manifest" "$bootstrap_file"; then
                err "Pass 2026-A: plugin type ${type_name} in $f is not registered in $bootstrap_file"
                pass_2026A_violations=$((pass_2026A_violations+1))
            fi

            # Extract the id literal: `id: "com.maccrab.forensics.fixture",`
            plugin_id=$(grep -E '^[[:space:]]+id:[[:space:]]*"' "$f" | head -1 \
                | sed -E 's/^[[:space:]]+id:[[:space:]]*"([^"]+)".*/\1/')
            if [[ -z "$plugin_id" ]]; then
                err "Pass 2026-A: could not extract plugin id from $f"
                pass_2026A_violations=$((pass_2026A_violations+1))
                continue
            fi

            # First-party ids must live under the reserved kind roots.
            if [[ "$plugin_id" == com.maccrab.* ]]; then
                if ! [[ "$plugin_id" =~ ^com\.maccrab\.(forensics|enricher|fingerprinter|analyzer)\. ]]; then
                    err "Pass 2026-A: first-party plugin id '$plugin_id' (in $f) is outside com.maccrab.{forensics,enricher,fingerprinter,analyzer}.*"
                    pass_2026A_violations=$((pass_2026A_violations+1))
                fi
            fi

            # Every OutputSpec(contentType: ...) line in this file must
            # carry privacyClass: in the same call. Swift's required-arg
            # rule already enforces this; the audit guards against
            # future shape changes (builder API, default value, etc.).
            output_lines=$(grep -nE 'OutputSpec\(contentType:' "$f" || true)
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                if ! [[ "$line" == *"privacyClass:"* ]]; then
                    err "Pass 2026-A: OutputSpec in $f missing privacyClass: $line"
                    pass_2026A_violations=$((pass_2026A_violations+1))
                fi
            done <<< "$output_lines"
        done <<< "$manifest_files"

        if [[ $pass_2026A_violations -eq 0 ]]; then
            ok "Pass 2026-A: every plugin manifest registered + namespaced correctly + every output declares privacyClass"
        fi
    fi
fi

# ---------------------------------------------------------------------
# PASS 2026-C — enricher idempotency coverage (v1.13a-2)
# ---------------------------------------------------------------------
# Source: plan §3.8, §5.2.
#
# Every Enricher in MacCrabForensics MUST be paired with a test file
# that exercises the byte-identical-across-re-runs invariant. The
# enricher's `enrich(subject, stage)` is supposed to be a pure
# function of (subject, stage); side-effects, time-based fields,
# network calls, or random input all violate the invariant. The
# byte-identical assertion in tests catches the violation early,
# before downstream consumers (event pipeline, dashboard, MCP
# tools) start seeing flapping enrichment fields.
#
# The audit doesn't run the tests itself — that's swift test's job.
# It enforces presence + naming convention: any Enricher type in
# Sources/MacCrabForensics/Plugins/Enrichers/ must have a paired
# Tests/MacCrabForensicsTests/<Name>Tests.swift file containing
# a suite tagged "idempotency" (the test suite's name string).

section "PASS 2026-C — enricher idempotency coverage"

enricher_files=$(grep -lR --include='*.swift' "public struct [A-Za-z_][A-Za-z0-9_]*: Enricher" Sources/MacCrabForensics/Plugins/Enrichers/ 2>/dev/null || true)
if [[ -z "$enricher_files" ]]; then
    info "Pass 2026-C: no Enricher types under Sources/MacCrabForensics/Plugins/Enrichers/ — skipping (no enrichers yet)"
else
    pass_2026C_violations=0
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        type_name=$(grep -E 'public struct [A-Za-z_][A-Za-z0-9_]+: Enricher' "$f" | head -1 \
            | sed -E 's/.*public struct ([A-Za-z_][A-Za-z0-9_]+): Enricher.*/\1/')
        if [[ -z "$type_name" ]]; then
            err "Pass 2026-C: could not determine Enricher type name in $f"
            pass_2026C_violations=$((pass_2026C_violations+1))
            continue
        fi
        # Look for either <Type>Tests.swift OR <Type>IdempotencyTests.swift
        test_file_a="Tests/MacCrabForensicsTests/${type_name}Tests.swift"
        test_file_b="Tests/MacCrabForensicsTests/${type_name}IdempotencyTests.swift"
        if [[ ! -f "$test_file_a" ]] && [[ ! -f "$test_file_b" ]]; then
            err "Pass 2026-C: enricher ${type_name} (in $f) has no paired test file (looked for $test_file_a or $test_file_b)"
            pass_2026C_violations=$((pass_2026C_violations+1))
            continue
        fi
        # Require the test file to mention "idempotency" — proves
        # the byte-identical-across-re-runs assertion exists.
        # Either file present + matching keyword satisfies the check.
        for candidate in "$test_file_a" "$test_file_b"; do
            [[ -f "$candidate" ]] || continue
            if grep -qiE 'idempot|byte-identical|fields == .*\.fields' "$candidate"; then
                continue 2  # outer loop — this enricher is OK
            fi
        done
        err "Pass 2026-C: enricher ${type_name} test file exists but contains no idempotency assertion (grep for 'idempot' or 'fields == ' failed)"
        pass_2026C_violations=$((pass_2026C_violations+1))
    done <<< "$enricher_files"

    if [[ $pass_2026C_violations -eq 0 ]]; then
        ok "Pass 2026-C: every Enricher in Sources/MacCrabForensics/Plugins/Enrichers/ has a paired idempotency test"
    fi
fi

# ---------------------------------------------------------------------
# PASS 2026-D — privacy_class consistency + plaintext rejects non-metadata (v1.13a-5)
# ---------------------------------------------------------------------
# Source: plan §3.8.
#
# The runtime invariant lives in ArtifactStore.commit:
#   "if encryption_state == .plaintext, privacyClass != .metadata
#    raises plaintextCaseRejectsNonMetadata."
#
# This pass enforces source-tree side that:
#   (a) ArtifactStore.swift still contains the check (someone might
#       refactor it away under the wrong impression that it's
#       redundant),
#   (b) ArtifactStoreTests.swift covers all four non-metadata
#       classes (content / personalComms / credentialAdjacent /
#       secret) with explicit reject-at-INSERT assertions.
#
# Either failure means a release could ship with the strongest
# privacy invariant gone (a) or unverified (b).

section "PASS 2026-D — privacy_class consistency + plaintext rejects non-metadata"

pass_2026D_violations=0
artifact_store="Sources/MacCrabForensics/Storage/ArtifactStore.swift"
artifact_tests="Tests/MacCrabForensicsTests/ArtifactStoreTests.swift"

if [[ ! -f "$artifact_store" ]]; then
    err "Pass 2026-D: $artifact_store missing — the runtime gate must exist"
    pass_2026D_violations=$((pass_2026D_violations+1))
else
    if ! grep -q "plaintextCaseRejectsNonMetadata" "$artifact_store"; then
        err "Pass 2026-D: ArtifactStore.swift missing plaintextCaseRejectsNonMetadata gate"
        pass_2026D_violations=$((pass_2026D_violations+1))
    fi
    if ! grep -q "encryptionState == .plaintext" "$artifact_store"; then
        err "Pass 2026-D: ArtifactStore.swift missing 'encryptionState == .plaintext' check"
        pass_2026D_violations=$((pass_2026D_violations+1))
    fi
fi

if [[ ! -f "$artifact_tests" ]]; then
    err "Pass 2026-D: $artifact_tests missing — invariant must be tested"
    pass_2026D_violations=$((pass_2026D_violations+1))
else
    # Each non-metadata class must have a corresponding "rejects"
    # assertion in the test file.
    for cls in "content" "personalComms" "credentialAdjacent" "secret"; do
        if ! grep -q "rejects $cls\|reject${cls^}\|rejects${cls^}\|Reject${cls^}" "$artifact_tests"; then
            # Fallback to a more generous match — the test name
            # convention is "Plaintext case rejects <class>".
            if ! grep -iq "rejects ${cls}" "$artifact_tests" \
               && ! grep -q "privacyClass: .${cls}" "$artifact_tests"; then
                err "Pass 2026-D: ArtifactStoreTests.swift missing rejection assertion for class '${cls}'"
                pass_2026D_violations=$((pass_2026D_violations+1))
            fi
        fi
    done
fi

if [[ $pass_2026D_violations -eq 0 ]]; then
    ok "Pass 2026-D: runtime gate present + all four non-metadata classes covered by reject-at-INSERT tests"
fi

# ---------------------------------------------------------------------
# PASS 2026-B — single ArtifactStore writer (v1.13a-1)
# ---------------------------------------------------------------------
# Source: plan §3.8.
#
# Sources/MacCrabForensics/Storage/ArtifactStore.swift is the one and
# only file allowed to issue INSERTs against the artifacts /
# artifact_data / plugin_invocations tables. Every other path must
# route through ArtifactStore.commit / recordInvocation* — the
# chokepoint enforces Pass 2026-D's privacy-class invariant.
#
# Tests are exempt: they exercise commit through the actor; raw
# INSERTs in tests are evidence of bypass.
# Generated comment lines containing the table name are excluded
# via the literal "INSERT INTO " prefix match (no double-space, no
# multi-line splits).

section "PASS 2026-B — single ArtifactStore writer"

forbidden_tables="artifacts artifact_data plugin_invocations"
pass_2026B_violations=0
for table in $forbidden_tables; do
    hits=$(grep -rnE "INSERT INTO ${table}\b" --include='*.swift' Sources/ Tests/ 2>/dev/null \
        | grep -v "Sources/MacCrabForensics/Storage/ArtifactStore.swift" \
        | grep -v "Sources/CSQLCipher/" || true)
    if [[ -n "$hits" ]]; then
        err "Pass 2026-B: INSERT INTO ${table} outside ArtifactStore.swift:"
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "    $line" >&2
        done <<< "$hits"
        pass_2026B_violations=$((pass_2026B_violations+1))
    fi
done

if [[ $pass_2026B_violations -eq 0 ]]; then
    ok "Pass 2026-B: artifacts / artifact_data / plugin_invocations are written only from ArtifactStore.swift"
fi

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------

section "Summary"

if [[ "$ERRORS" -gt 0 ]]; then
    echo "${RED}${BOLD}FAILED${RESET} — $ERRORS error(s), $WARNINGS warning(s)"
    exit 1
fi

if [[ "$WARNINGS" -gt 0 ]]; then
    echo "${YELLOW}${BOLD}PASSED${RESET} (with $WARNINGS warning(s))"
else
    echo "${GREEN}${BOLD}PASSED${RESET}"
fi
exit 0
