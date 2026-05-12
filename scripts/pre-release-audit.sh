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
        "alertNotifications"
        "minAlertSeverity"
        "pollIntervalSeconds"
        "launchAtLogin"
        "uiMode.storageKey"   # UIMode.storageKey constant
    )

    # Bindings that MUST round-trip to the daemon. Each maps to a sync
    # function that writes a JSON file the sysext reads.
    declare -a DAEMON_BINDINGS=(
        "retentionDays:syncStorageOverrides"
        "maxDatabaseSizeMB:syncStorageOverrides"
        "retentionWindowDays:syncStorageOverrides"
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
    declared_keys=$(grep -oE '@AppStorage\("[^"]+"' "$SETTINGS_FILE" \
        | sed -E 's/@AppStorage\("([^"]+)"/\1/')
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
            warn "Unclassified @AppStorage(\"$key\"): add to UI_ONLY_KEYS (UI-only) or DAEMON_BINDINGS (must reach daemon)"
        fi
    done

    if [[ $ERRORS -eq 0 ]]; then
        ok "All daemon-bound Settings keys have a sync function"
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
        warn "$label: couldn't extract one or both values (a=$val_a b=$val_b) — audit may need updating"
    elif [[ "$val_a" != "$val_b" ]]; then
        err "$label drift: $val_a vs $val_b"
    else
        ok "$label → $val_a"
    fi
}

# Default support directory: appears in DaemonState (docstring), AlertStore
# (init default), and the Casks zap stanza. The init default is the
# canonical value; verify the cask references it.
SUPPORT_DIR_INIT=$(grep -E 'directory: String = "/Library/Application Support/MacCrab"' \
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
# PASS 5 — duplicate SQLite handles to events.db (v1.6.22)
# ---------------------------------------------------------------------
# Each open `events.db` connection carries its own page cache (set via
# StoragePragmas.eventCacheSizeKB) and mmap region (eventMmapSizeBytes).
# Two long-lived connections (EventStore + AlertStore) is the audited
# steady state; a third actor opening the same file would re-double the
# per-connection memory cost. ThreatHunter open/close per query is OK
# (transient, not long-lived).
#
# This pass counts long-lived `OpaquePointer?` declarations in actor
# bodies that point at events.db. When the count rises above 2, the
# release should consolidate before shipping.

section "PASS 5 — events.db long-lived connection count"

# Find every actor that BOTH (a) opens events.db specifically (matches
# `appendingPathComponent("events.db")`) AND (b) declares a long-lived
# `private var db: OpaquePointer?`. CampaignStore opens campaigns.db so
# it is excluded by the precise path match. ThreatHunter uses a local
# var inside `executeSQL` so it doesn't match the long-lived field
# pattern — that's the desired pattern for a transient read.
events_db_actors=$(grep -rln 'appendingPathComponent("events.db")' Sources/MacCrabCore/Storage Sources/MacCrabAgentKit \
    --include='*.swift' 2>/dev/null \
    | xargs -I {} grep -l 'private var db: OpaquePointer?' {} 2>/dev/null \
    | sort -u || true)

events_db_actor_count=$(echo "$events_db_actors" | grep -cE '\S' || true)

if [[ "$events_db_actor_count" -gt 2 ]]; then
    err "More than 2 actors hold a long-lived events.db handle — each costs cache_size + mmap_size. Consolidate (current: $events_db_actor_count):"
    echo "$events_db_actors" | sed 's/^/    /' >&2
elif [[ "$events_db_actor_count" -lt 2 ]]; then
    warn "Fewer than 2 actors hold a long-lived events.db handle — has the schema changed? (count: $events_db_actor_count)"
else
    ok "events.db long-lived connection count is at audited target (2: EventStore + AlertStore)"
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
# PASS 7 — primary panel view richness invariants (v1.7.1)
# ---------------------------------------------------------------------
# Every primary panel view must declare:
#  - a `searchText` (or equivalent `@State` String) for searching, AND
#  - at least one nav-destination (sheet/popover/HSplitView detail/
#    NavigationLink) for drill-down.
# Codifies the v1.6.17 Threat Intel rebuild template as an architectural
# invariant so future panel additions don't ship as bare lists.

section "PASS 7 — primary panel view richness audit"

declare -a PRIMARY_PANELS=(
    "Sources/MacCrabApp/Views/RuleBrowser.swift"
    "Sources/MacCrabApp/Views/BrowserExtensionsView.swift"
    "Sources/MacCrabApp/Views/TCCTimeline.swift"
    "Sources/MacCrabApp/Views/ESHealthView.swift"
    "Sources/MacCrabApp/Views/ThreatIntelView.swift"
    "Sources/MacCrabApp/Views/MCPActivityView.swift"
    "Sources/MacCrabApp/Views/AlertDashboard.swift"
)

for panel in "${PRIMARY_PANELS[@]}"; do
    if [[ ! -f "$panel" ]]; then
        warn "PASS 7: $panel missing — panel list out of date"
        continue
    fi
    base=$(basename "$panel" .swift)
    has_search=0
    # Accept any plausible search-state name — `searchText`, `query`,
    # `filterText`, `searchQuery`, etc.
    if grep -qE '@State[^;]*\b(searchText|query|filterText|searchQuery)\b' "$panel"; then
        has_search=1
    fi
    has_drill=0
    # Drill-down hooks: .sheet, .popover, NavigationLink, HSplitView,
    # OR a tabbed/segmented multi-view (Picker bound to a `viewMode` /
    # selectedSection state acts as a richness alternative for status
    # panels that don't have row-level detail).
    if grep -qE '\.sheet\(|\.popover\(|NavigationLink|HSplitView|detail:' "$panel"; then
        has_drill=1
    fi
    if grep -qE '@State.*\b(viewMode|selectedSection|selectedTab|selectedMode)\b' "$panel"; then
        has_drill=1
    fi
    # ES Health is permitted to skip both — it's a status grid; the
    # sparkline + matrix + collector list are ITS richness.
    if [[ "$base" == "ESHealthView" ]]; then
        has_search=1
        has_drill=1
    fi

    if [[ $has_search -eq 0 ]]; then
        err "PASS 7: $base has no search state (@State searchText/query/filterText/searchQuery) — primary panel must support search"
    fi
    if [[ $has_drill -eq 0 ]]; then
        err "PASS 7: $base has no drill-down hook (sheet/popover/NavigationLink/HSplitView/multi-view picker)"
    fi
done

if [[ $ERRORS -eq 0 ]]; then
    ok "All primary panels expose search + drill-down"
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
    #   - `removeValue(forKey:` or `removeFirst(`
    #   - `.removeAll(`
    #   - explicit cap constant referenced near the field
    #   - `.count >=` checks
    if grep -qE "\b${field}\.(removeValue|removeFirst|removeAll|popFirst)\b|${field}\.count\s*[><=]|let max[A-Z]" "$file"; then
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
    err "Pass 8: ${#IN_ACTOR[@]} unbounded actor collection field(s) found — add cap+evict, an inline '// bounded:' comment, or an allowlist entry:"
    for finding in "${IN_ACTOR[@]}"; do
        echo "    $finding" >&2
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
