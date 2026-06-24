#!/bin/bash
# measure-fp-baseline.sh — capture the false-positive baseline for an endpoint.
#
# WHY: the acquisition audit's single most adoption-critical UNMEASURED number is
# the true per-day HIGH/CRITICAL alert + campaign rate on a CLEAN, IDLE machine
# (and on a representative non-developer endpoint). The dev-tooling FP fixes
# (the campaign dev-tooling carve-out, and the pending behavior-scoring /
# AI-investigator "unsigned==suspicious" recalibration) must be tuned AGAINST
# this baseline, not guessed — over-suppression is the worst EDR outcome.
#
# HOW TO GET A TRUE BASELINE:
#   1. Run this on a host that has been IDLE for the window (no active dev/agent
#      session, no builds) — otherwise the per-event firehose contaminates it.
#   2. Run it again on a representative NON-developer endpoint.
#   3. Compare the per-process table below: the rows dominated by benign signed
#      dev tooling (esbuild/gh/node/workerd/swiftpm-testing-helper/Chrome) are
#      the recalibration targets; a clean non-dev box should be near-zero.
#   4. Re-run after a tuning change to measure the delta (and confirm real
#      detections — credential theft / C2 / persistence — still fire).
#
# Vendor's own release gate: < 30 single-event HIGH/CRITICAL alerts/day, and
# ~0 campaigns/week post-release.

set -uo pipefail
HOURS="${1:-24}"

# Resolve maccrabctl: prefer the installed app bundle, fall back to a local build.
CTL=""
for c in \
    "/Applications/MacCrab.app/Contents/Resources/bin/maccrabctl" \
    "$(dirname "$0")/../.build/release/maccrabctl" \
    "$(dirname "$0")/../.build/debug/maccrabctl"; do
    if [ -x "$c" ]; then CTL="$c"; break; fi
done
if [ -z "$CTL" ]; then echo "ERROR: maccrabctl not found (install MacCrab.app or 'swift build')" >&2; exit 1; fi

echo "════════════════════════════════════════════════════════════════"
echo "  MacCrab FP baseline — last ${HOURS}h   ($(date '+%Y-%m-%d %H:%M:%S'))"
echo "  host: $(hostname -s)   maccrabctl: $CTL"
echo "════════════════════════════════════════════════════════════════"

alerts="$("$CTL" alerts 1000 --hours "$HOURS" 2>/dev/null)"
campaigns="$("$CTL" campaigns 2>/dev/null)"

ch_count="$(printf '%s\n' "$alerts" | grep -cE '\[CRITICAL\]|\[HIGH\]')"
crit_count="$(printf '%s\n' "$alerts" | grep -cE '\[CRITICAL\]')"
camp_count="$(printf '%s\n' "$campaigns" | grep -cE '\[CRITICAL\]|\[HIGH\]')"

# Per-day extrapolation from the window.
per_day=$(( ch_count * 24 / (HOURS > 0 ? HOURS : 24) ))

echo
echo "HIGH/CRITICAL single-event alerts : ${ch_count}  (CRITICAL: ${crit_count})"
echo "  → ~${per_day}/day extrapolated   (release gate: < 30/day)"
if [ "$per_day" -ge 30 ]; then
    echo "  → ⚠️  ABOVE the < 30/day gate — recalibrate (or confirm this host was NOT idle)."
else
    echo "  → ✓ within the < 30/day gate."
fi
echo "HIGH/CRITICAL campaigns shown      : ${camp_count}  (release gate: ~0/week)"
echo
echo "── HIGH/CRITICAL alerts by process (recalibration targets) ──"
printf '%s\n' "$alerts" \
    | grep -A4 -E '\[CRITICAL\]|\[HIGH\]' \
    | grep -iE 'process' \
    | sed -E 's/.*[Pp]rocess[: ]*//' | awk '{print $1}' \
    | sort | uniq -c | sort -rn | head -20
echo
echo "── HIGH/CRITICAL alerts by rule ──"
printf '%s\n' "$alerts" \
    | grep -oE 'maccrab\.[a-z0-9._-]+' \
    | sort | uniq -c | sort -rn | head -15
echo
echo "NOTE: a contaminated (active dev/agent) host inflates this — it is an"
echo "      UPPER bound. The adoptable number is from a clean, IDLE soak."
