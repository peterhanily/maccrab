#!/bin/bash
# Fixed bounded burst used by the installed-host qualification recorder.
# The synthetic alert can invoke configured response actions; see below.
set -euo pipefail

RUN_ID=""
ALERT_ONLY=0
# Retained bounded workload: prior-host measurements put 3,000 iterations at
# about 49,200 offered events and 22 seconds. That is provenance, not a promise
# of candidate throughput or a fixed events-per-iteration conversion.
#
# The recorder now requires at least 38,220 offered events across the nearest
# heartbeats bracketing actual process execution, and at least 1,274 offered
# events per independently measured burst second. The volume preserves the
# old 1,274/s x 30s minimum burden without making success depend on heartbeat
# phase. The heartbeat interval peak is reported, not used for acceptance.
# Bracketing counters include ambient host traffic; the report exposes the
# leading and trailing heartbeat slack rather than claiming exact attribution.
#
# Load and retirement are one budget: every lane must be drained at offset 780,
# 480 seconds after launch at 300. Prior 6,000-iteration runs offered ~98,290
# events and took ~690 seconds to drain; increasing the load count alone can
# therefore make this prescribed workload impossible to retire on time.
# Re-measure both load and drainability before changing this count or boundary.
BURST_ITERATIONS=3000

usage() {
    echo "usage: $0 [--alert-only] --run-id <32-lowercase-hex>" >&2
    exit 64
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --alert-only)
            ALERT_ONLY=1
            shift
            ;;
        --run-id)
            [[ $# -ge 2 ]] || usage
            RUN_ID="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

[[ "$RUN_ID" =~ ^[0-9a-f]{32}$ ]] || usage

ALERT_DIR="/private/tmp/maccrab-runtime-alert.$RUN_ID"
ALERT_EXECUTABLE="$ALERT_DIR/maccrab-qualification-alert"
BULK_DIR="/Users/Shared/MacCrabQualificationRuntime-$RUN_ID"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIRECTORY_HELPER="$SCRIPT_DIR/runtime-workload-directories.py"
ALERT_DIRECTORY_ID=""
BULK_DIRECTORY_ID=""

cleanup() {
    local status=$?
    if [[ -n "$ALERT_DIRECTORY_ID" ]]; then
        /usr/bin/python3 -B "$DIRECTORY_HELPER" remove "$ALERT_DIR" "$ALERT_DIRECTORY_ID" || status=1
    fi
    if [[ -n "$BULK_DIRECTORY_ID" ]]; then
        /usr/bin/python3 -B "$DIRECTORY_HELPER" remove "$BULK_DIR" "$BULK_DIRECTORY_ID" || status=1
    fi
    return "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Both paths are run-unique and must not pre-exist. The file-pressure tree is
# deliberately outside /tmp: stable sequence rules use temporary paths as
# later-stage payload predicates, so a broad temporary burst would test a
# different semantic and can exhaust pending sequence state.
ALERT_DIRECTORY_ID=$(/usr/bin/python3 -B "$DIRECTORY_HELPER" create "$ALERT_DIR")
if [[ "$ALERT_ONLY" -eq 0 ]]; then
    BULK_DIRECTORY_ID=$(/usr/bin/python3 -B "$DIRECTORY_HELPER" create "$BULK_DIR")
fi

# Generate one synthetic alert without opening a socket. The matched rule is
# CRITICAL, not merely HIGH: configured response rules, notifications, external
# integrations and AI investigations can run. Use only an approved qualification
# environment whose response policy has been reviewed; this is not passive or
# consequence-free runtime testing. Alert
# deduplication is keyed by rule ID plus executable path for one hour, so a
# byte-for-byte copy of Apple's echo at this unique path cannot be suppressed
# by an earlier qualification run.
#
# Deliberately NOT `cp -p`: /bin/echo ships with the `restricted,compressed`
# file flags, and -p tries to replicate them onto the copy — a chflags the
# kernel refuses for everyone, root included. Whether cp then exits non-zero
# depends on the OS build's flag set, so this worked for months and then
# failed the recorder before its first sample after an OS update recompressed
# /bin/echo (rc.39, 2026-08-20). Only the bytes and the exec bit matter to the
# detection rule; content reads are transparently decompressed, so the copy
# stays byte-for-byte.
/bin/cp /bin/echo "$ALERT_EXECUTABLE"
/bin/chmod 0755 "$ALERT_EXECUTABLE"
# rc.43: ad-hoc re-sign the copy before running it. /bin/echo is a platform
# binary whose code signature is only valid in place; a plain copy is an
# invalid-signature Mach-O, and on macOS 26 (arm64) AMFI SIGKILLs it on exec
# (exit 137 "Killed: 9"), so the alert never fired and the recorder failed at
# the prewarm trigger. An ad-hoc signature makes the copy a legitimately
# runnable executable at its unique path without changing the bytes the
# detection rule matches. `codesign` is present on every host that can build
# and qualify the product.
/usr/bin/codesign --sign - --force "$ALERT_EXECUTABLE" >/dev/null 2>&1 || {
    echo "FAIL: could not ad-hoc sign the qualification alert executable" >&2
    exit 1
}
"$ALERT_EXECUTABLE" '/dev/tcp/maccrab-qualification.invalid/1' >/dev/null

echo "IDENTITY: run_id=$RUN_ID alert_executable=$ALERT_EXECUTABLE bulk_path=$BULK_DIR"

if [[ "$ALERT_ONLY" -eq 1 ]]; then
    echo "PASS: fixed alert-only workload completed run_id=$RUN_ID alert_triggers=1"
    exit 0
fi

# Exercise the actual loopback OTLP receiver. HTTP acceptance is not treated
# as persistence proof: the root-owned recorder separately requires the live
# TraceStore offered/completed ledger to advance during this same window, and
# verifies the emitted exact trace/span IDs separately. No attributes are printed.
/bin/bash "$SCRIPT_DIR/test-otlp-curl.sh" --receiver-only

# One bounded, non-networking stable-sequence probe. The reverse-shell sequence
# admits this shell as an early step, then its ten-second window expires without
# a connection. The recorder requires journal movement, clean expiry/drain, and
# zero shed; it is separate from the bulk pressure proof below.
/bin/sh -c ':'

# Exercise process creation and the rule-relevant file create/write/rename path
# without touching operator data or entering a stable sequence's temporary-file
# later-step predicate.
for index in $(/usr/bin/jot "$BURST_ITERATIONS" 1); do
    /usr/bin/true
    /usr/bin/printf 'maccrab qualification %05d\n' "$index" \
        > "$BULK_DIR/event-$index.txt"
done
for index in $(/usr/bin/jot "$BURST_ITERATIONS" 1); do
    /bin/mv "$BULK_DIR/event-$index.txt" \
        "$BULK_DIR/renamed-$index.txt"
done
/usr/bin/find "$BULK_DIR" -type f -print0 \
    | /usr/bin/xargs -0 /usr/bin/shasum -a 256 >/dev/null

echo "PASS: fixed workload completed run_id=$RUN_ID iterations=$BURST_ITERATIONS otlp_spans=1 alert_triggers=1 sequence_probes=1"
