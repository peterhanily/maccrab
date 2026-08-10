#!/bin/bash
# Fixed benign burst used by the installed-host qualification recorder.
set -euo pipefail

WORKLOAD_DIR=$(/usr/bin/mktemp -d /private/tmp/maccrab-runtime-workload.XXXXXX)
BURST_ITERATIONS=20000
cleanup() {
    /bin/rm -rf "$WORKLOAD_DIR"
}
trap cleanup EXIT

# Exercise the actual loopback OTLP receiver.  HTTP acceptance is not treated
# as persistence proof: the root-owned recorder separately requires the live
# TraceStore offered/completed ledger to advance during this same window.
/bin/bash scripts/test-otlp-curl.sh --receiver-only

# Generate one harmless HIGH alert without opening a socket. Alert deduplication
# is keyed by rule ID plus executable path for one hour, so execute a byte-for-
# byte copy of Apple's echo from this run's unique directory. A prior failed
# qualification therefore cannot suppress the required investigation.
ALERT_EXECUTABLE="$WORKLOAD_DIR/maccrab-qualification-alert"
/bin/cp -p /bin/echo "$ALERT_EXECUTABLE"
"$ALERT_EXECUTABLE" '/dev/tcp/maccrab-qualification.invalid/1' >/dev/null

# Exercise process creation and the rule-relevant file create/write/rename/remove
# path without touching operator data or requiring network access.
for index in $(/usr/bin/jot "$BURST_ITERATIONS" 1); do
    /usr/bin/true
    /usr/bin/printf 'maccrab qualification %05d\n' "$index" \
        > "$WORKLOAD_DIR/event-$index.txt"
done
for index in $(/usr/bin/jot "$BURST_ITERATIONS" 1); do
    /bin/mv "$WORKLOAD_DIR/event-$index.txt" \
        "$WORKLOAD_DIR/renamed-$index.txt"
done
/usr/bin/find "$WORKLOAD_DIR" -type f -print0 \
    | /usr/bin/xargs -0 /usr/bin/shasum -a 256 >/dev/null

echo "PASS: fixed workload completed iterations=$BURST_ITERATIONS otlp_spans=1 alert_triggers=1"
