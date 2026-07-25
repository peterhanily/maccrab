#!/usr/bin/env bash
# soak-status.sh — guard the per-rule false-positive soak window.
#
# WHY THIS EXISTS
#   CONTRIBUTING.md's promotion bar (criterion 1) reads: a rule at
#   <= 0.5 alerts/day over >= 14 days "provided the rule was actually
#   enabled for the window, e.g. under rule_profile: all".
#
#   That proviso is the whole problem. scripts/fp-rate-benchmark.sh reports
#   per-rule alerts/day, and a rule ABSENT from its output is treated as
#   0/day — which passes. So a rule scores a perfect false-positive record
#   in exactly three situations:
#
#     1. it genuinely never fired            (real evidence)
#     2. it was disabled by the rule profile (absence of evidence)
#     3. the sensor was not ingesting        (absence of evidence)
#
#   Cases 2 and 3 are indistinguishable from case 1 in the benchmark JSON.
#   Promoting on either one ships a rule to users on the strength of a
#   measurement that never happened. This script exists to make that
#   impossible: it records when the window opened, samples the engine while
#   it runs, and refuses to produce a benchmark over a window it cannot
#   vouch for.
#
# USAGE
#   scripts/soak-status.sh start [--force]   open a window (records profile + build)
#   scripts/soak-status.sh sample            record one liveness sample (cron/launchd)
#   scripts/soak-status.sh report [--days N] validate, then run fp-rate-benchmark.sh
#   scripts/soak-status.sh install-sampler   load an hourly LaunchAgent that samples
#   scripts/soak-status.sh uninstall-sampler unload it
#
# EXIT CODES
#   0  ok
#   1  window invalid — refused (report only)
#   2  environment problem (no engine, no marker, unreadable store)
#
# Read-only with respect to MacCrab: opens the stores immutable, never
# writes to the support dir, never needs sudo. All state lives under
# ~/Library/Application Support/MacCrab/soak/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOAK_DIR="$HOME/Library/Application Support/MacCrab/soak"
MARKER="$SOAK_DIR/marker.json"
SAMPLES="$SOAK_DIR/samples.jsonl"

# The engine writes to /Library when it is the root System Extension and to
# ~/Library when it is a non-root dev daemon. Prefer whichever is readable.
resolve_store() {
    local name="$1" cand
    for cand in "/Library/Application Support/MacCrab/$name" \
                "$HOME/Library/Application Support/MacCrab/$name"; do
        [ -r "$cand" ] && { printf '%s' "$cand"; return 0; }
    done
    return 1
}

# Newest event age in seconds. A stalled sensor is the failure mode that
# silently makes every rule look clean, so it is sampled explicitly.
event_lag_seconds() {
    local db; db="$(resolve_store events.db)" || { echo ""; return; }
    sqlite3 "file:${db}?immutable=1" \
        "select cast(strftime('%s','now') - max(timestamp) as int) from events;" 2>/dev/null || echo ""
}

alerts_total() {
    local db; db="$(resolve_store alerts.db)" || { echo ""; return; }
    sqlite3 "file:${db}?immutable=1" "select count(*) from alerts;" 2>/dev/null || echo ""
}

# Parse `maccrabctl status`. The rule line reads:
#   Rules:  87 active / 438 loaded standard, 11 active / 41 shipped sequence rule(s) ...
# Under rule_profile: all, active should equal loaded on both tiers.
read_rule_counts() {
    command -v maccrabctl >/dev/null 2>&1 || { echo ""; return; }
    maccrabctl status 2>/dev/null \
      | sed -n 's/.*[^0-9]\([0-9][0-9]*\) active \/ \([0-9][0-9]*\) loaded standard, \([0-9][0-9]*\) active \/ \([0-9][0-9]*\) shipped.*/\1 \2 \3 \4/p' \
      | head -1
}

engine_version() {
    systemextensionsctl list 2>/dev/null \
      | awk '/com\.maccrab\.agent/ && /activated enabled/ {print $4; exit}' \
      | tr -d '()' | cut -d/ -f1
}

# One sample as a single JSON line. Emitted by both `start` and `sample` so a
# window always has at least its opening observation.
emit_sample() {
    local counts lag alerts ver
    counts="$(read_rule_counts)"; lag="$(event_lag_seconds)"
    alerts="$(alerts_total)"; ver="$(engine_version)"
    COUNTS="$counts" LAG="$lag" ALERTS="$alerts" VER="$ver" python3 - "$SAMPLES" <<'PY'
import json, os, sys, time
counts = (os.environ.get("COUNTS") or "").split()
active = loaded = seq_active = seq_loaded = None
if len(counts) == 4:
    active, loaded, seq_active, seq_loaded = (int(c) for c in counts)

def num(key):
    v = os.environ.get(key) or ""
    return int(v) if v.strip().lstrip("-").isdigit() else None

# profile_ok is tri-state on purpose: unknown (None) must never read as ok.
profile_ok = None
if active is not None:
    profile_ok = (active == loaded and seq_active == seq_loaded)

sample = {
    "ts": int(time.time()),
    "engine_version": os.environ.get("VER") or None,
    "rules_active": active, "rules_loaded": loaded,
    "seq_active": seq_active, "seq_loaded": seq_loaded,
    "profile_ok": profile_ok,
    "event_lag_s": num("LAG"),
    "alerts_total": num("ALERTS"),
}
with open(sys.argv[1], "a") as f:
    f.write(json.dumps(sample, sort_keys=True) + "\n")
print(json.dumps(sample, sort_keys=True))
PY
}

cmd_start() {
    local force=0
    [ "${1:-}" = "--force" ] && force=1
    mkdir -p "$SOAK_DIR"
    if [ -f "$MARKER" ] && [ "$force" -ne 1 ]; then
        echo "ERROR: a soak window is already open:" >&2
        cat "$MARKER" >&2
        echo "Re-opening discards the accrued window. Pass --force if that is intended." >&2
        exit 2
    fi

    local counts; counts="$(read_rule_counts)"
    if [ -z "$counts" ]; then
        echo "ERROR: could not read 'maccrabctl status' — is the engine running?" >&2
        exit 2
    fi
    set -- $counts
    if [ "$1" -ne "$2" ] || [ "$3" -ne "$4" ]; then
        echo "REFUSING to open a window: the rule profile is not 'all'." >&2
        echo "  standard rules: $1 active / $2 loaded" >&2
        echo "  sequence rules: $3 active / $4 loaded" >&2
        echo "" >&2
        echo "Set \"rule_profile\": \"all\" in the engine's daemon_config.json and" >&2
        echo "reload, then re-run. Opening a window with rules disabled would score" >&2
        echo "them 0 alerts/day on absence of evidence." >&2
        exit 2
    fi

    VER="$(engine_version)" RULES="$1" SEQ="$3" python3 - "$MARKER" <<'PY'
import json, os, sys, time
now = int(time.time())
json.dump({
    "schema": "maccrab.soak_marker.v1",
    "started_at": now,
    "started_at_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    "rule_profile": "all",
    "rules_enabled_at_start": int(os.environ["RULES"]),
    "sequence_rules_enabled_at_start": int(os.environ["SEQ"]),
    "engine_version_at_start": os.environ.get("VER") or None,
}, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
    echo "Soak window opened:"
    cat "$MARKER"
    emit_sample >/dev/null
    echo ""
    echo "Sample it periodically (hourly is plenty):  scripts/soak-status.sh sample"
    echo "Earliest valid report is 14 days from now."
}

cmd_sample() {
    [ -f "$MARKER" ] || { echo "ERROR: no soak window open (run 'start')." >&2; exit 2; }
    mkdir -p "$SOAK_DIR"
    emit_sample
}

cmd_report() {
    local want_days=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --days) want_days="$2"; shift 2 ;;
            *) echo "unknown arg: $1" >&2; exit 2 ;;
        esac
    done
    [ -f "$MARKER" ] || { echo "ERROR: no soak window open (run 'start')." >&2; exit 2; }
    touch "$SAMPLES"

    # Validation is deliberately in one place and prints its reasoning, so a
    # refusal explains itself rather than just failing.
    local verdict
    verdict="$(WANT_DAYS="$want_days" python3 - "$MARKER" "$SAMPLES" <<'PY'
import json, sys, time
marker = json.load(open(sys.argv[1]))
samples = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
now = int(time.time())
elapsed_days = (now - marker["started_at"]) / 86400.0

want = (__import__("os").environ.get("WANT_DAYS") or "").strip()
want_days = float(want) if want else min(28.0, elapsed_days)

problems, warnings = [], []
if want_days > elapsed_days:
    problems.append(
        f"requested a {want_days:.0f}-day window but only {elapsed_days:.1f} days have "
        f"elapsed since the profile was set to 'all'. Alerts before that point were "
        f"recorded with most rules DISABLED; scoring them would credit absence of "
        f"evidence as evidence of absence.")
if elapsed_days < 14:
    problems.append(f"window is {elapsed_days:.1f} days; the promotion bar requires >= 14.")

bad = [s for s in samples if s.get("profile_ok") is False]
if bad:
    problems.append(
        f"{len(bad)} of {len(samples)} samples observed the rule profile NOT set to 'all'. "
        f"The window is not uniform — rules were dark for part of it.")
unknown = [s for s in samples if s.get("profile_ok") is None]
if unknown:
    warnings.append(f"{len(unknown)} samples could not determine the rule profile.")

STALL_S = 3600
stalled = [s for s in samples if (s.get("event_lag_s") or 0) > STALL_S]
if stalled:
    worst = max(s.get("event_lag_s") or 0 for s in stalled)
    warnings.append(
        f"{len(stalled)} of {len(samples)} samples saw event ingest stalled >1h "
        f"(worst {worst/3600:.1f}h). A stalled sensor makes every rule look clean. "
        f"Sleep explains some of this; sustained stalls do not.")

expected = max(1, int(elapsed_days))
if len(samples) < expected:
    warnings.append(
        f"only {len(samples)} samples over {elapsed_days:.1f} days (<1/day). "
        f"Coverage is too thin to vouch for the window.")

print(json.dumps({
    "elapsed_days": round(elapsed_days, 2),
    "window_days": round(want_days, 2),
    "samples": len(samples),
    "problems": problems,
    "warnings": warnings,
}))
PY
)"

    python3 - <<PY
import json
v = json.loads('''$verdict''')
print("Soak window")
print("  elapsed        : %.2f days" % v["elapsed_days"])
print("  requested      : %.2f days" % v["window_days"])
print("  samples        : %d" % v["samples"])
for w in v["warnings"]:
    print("  WARN  " + w)
for p in v["problems"]:
    print("  BLOCK " + p)
PY

    if printf '%s' "$verdict" | grep -q '"problems": \[\]'; then
        local days
        days="$(printf '%s' "$verdict" | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["window_days"]))')"
        echo ""
        echo "Window valid — running fp-rate-benchmark.sh --days $days"
        exec "$SCRIPT_DIR/fp-rate-benchmark.sh" --days "$days"
    fi

    echo ""
    echo "REFUSED: not producing a benchmark over a window that cannot be vouched for."
    exit 1
}

# A user-level LaunchAgent — no sudo, no root, removable in one command. It
# only samples; it never writes to MacCrab's stores.
AGENT_LABEL="com.maccrab.soak-sampler"
AGENT_PLIST="$HOME/Library/LaunchAgents/$AGENT_LABEL.plist"

cmd_install_sampler() {
    [ -f "$MARKER" ] || { echo "ERROR: open a soak window first ('start')." >&2; exit 2; }
    mkdir -p "$HOME/Library/LaunchAgents" "$SOAK_DIR"
    cat > "$AGENT_PLIST" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>$AGENT_LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$SCRIPT_DIR/soak-status.sh</string>
        <string>sample</string>
    </array>
    <key>StartInterval</key><integer>3600</integer>
    <key>RunAtLoad</key><true/>
    <key>StandardOutPath</key><string>$SOAK_DIR/sampler.log</string>
    <key>StandardErrorPath</key><string>$SOAK_DIR/sampler.err</string>
</dict>
</plist>
PLIST
    launchctl bootout "gui/$(id -u)/$AGENT_LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$AGENT_PLIST"
    echo "Sampler loaded (hourly). Remove with: scripts/soak-status.sh uninstall-sampler"
}

cmd_uninstall_sampler() {
    launchctl bootout "gui/$(id -u)/$AGENT_LABEL" 2>/dev/null || true
    rm -f "$AGENT_PLIST"
    echo "Sampler unloaded and removed. Accrued samples are untouched."
}

case "${1:-}" in
    start)  shift; cmd_start "$@" ;;
    sample) shift; cmd_sample "$@" ;;
    report) shift; cmd_report "$@" ;;
    install-sampler)   shift; cmd_install_sampler "$@" ;;
    uninstall-sampler) shift; cmd_uninstall_sampler "$@" ;;
    -h|--help|"") grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed '1d'; exit 0 ;;
    *) echo "unknown command: $1 (try --help)" >&2; exit 2 ;;
esac
