#!/bin/bash
# Fixed benign burst used by the installed-host qualification recorder.
set -euo pipefail

RUN_ID=""
ALERT_ONLY=0
# Sized from MEASURED loop throughput, not arithmetic.
#
# Measured on this host: 500 iterations take 2.26s (221 iterations/s), and one
# iteration offers ~7 events -- an exec of /usr/bin/true, an exec of /bin/mv,
# and the create/write/close/rename file path. That is ~1,546 offered events/s,
# already above the 1,274/s floor the gate requires.
#
# The floor is a rate measured over ONE 30s sample interval, so what matters is
# how much of that interval the burst SPANS, not how fast it runs. The previous
# 2,000 iterations finished in 9.1s and offered ~14,000 events, which the 30s
# window averages down to ~467/s -- comfortably under the floor despite the loop
# running above it the whole time. Confirmed against the recorder capture:
# file+10,621 priority+3,556 = 14,177 events, a 473/s interval rate.
#
# The ~7 events/iteration above was wrong, and 6,000 iterations did NOT offer
# ~42,000 events. Measured on an installed host (build 1.22.0.1788459825) by
# reading offered_by_lane across the burst:
#   N=6000 -> ~98,290 offered   N=3600 -> 58,998   N=2700 -> 44,931
# That is a steady 16.4 events/iteration, not 7 -- so 6,000 offered 2.3x its
# intended load and took ~690s to drain.
#
# THE UPPER BOUND IS DRAINABILITY, NOT CAPACITY. (This paragraph was deleted
# when the count went 2,000 -> 6,000; that deletion is what let the two
# constants drift apart.) Every lane must be drained at the fixed boundary
# BURST_DRAIN_OFFSET_SECONDS after the burst starts, so offering more than the
# engine can retire in that window fails the run no matter how much headroom
# the stream caps have. Measured post-burst retirement is ~196 ev/s (the tail is
# priority-bound; the ~400 ev/s seen mid-burst is the fast file lane and does
# not govern time-to-empty).
#
# 3,000 iterations offer ~49,200 events. Against the floor: the burst runs ~22s
# and the recorder launches it on the minute-five sample boundary, so one
# interval sees ~1,640 ev/s -- 29% above the 1,274/s floor, enough that sampling
# jitter cannot drop it under. (N=2,700 was measured at 1,119 ev/s, UNDER the
# floor, because that burst straddled two intervals -- the margin matters.)
# Against drainability: ~49,200 at ~196 ev/s is ~251s of drain after a ~22s
# burst, ~273s total, inside the 660s checkpoint with ~30% headroom.
#
# These two bounds are one budget. If either the floor or the engine's write
# path changes, re-measure BOTH this and BURST_DRAIN_OFFSET_SECONDS together.
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

cleanup_tree() {
    local target="$1"
    if [[ -d "$target" && ! -L "$target" ]]; then
        /usr/bin/find "$target" -depth -delete
    fi
}

cleanup() {
    cleanup_tree "$ALERT_DIR"
    if [[ "$ALERT_ONLY" -eq 0 ]]; then
        cleanup_tree "$BULK_DIR"
    fi
}
trap cleanup EXIT HUP INT TERM

# Both paths are run-unique and must not pre-exist. The file-pressure tree is
# deliberately outside /tmp: stable sequence rules use temporary paths as
# later-stage payload predicates, so a broad temporary burst would test a
# different semantic and can exhaust pending sequence state.
/bin/mkdir -m 0700 "$ALERT_DIR"
if [[ "$ALERT_ONLY" -eq 0 ]]; then
    /bin/mkdir -m 0700 "$BULK_DIR"
fi

# Generate one harmless HIGH alert without opening a socket. Alert
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
# TraceStore offered/completed ledger to advance during this same window.
/bin/bash scripts/test-otlp-curl.sh --receiver-only

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
