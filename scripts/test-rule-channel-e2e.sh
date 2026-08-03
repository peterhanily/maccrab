#!/usr/bin/env bash
# End-to-end release-policy probe for `maccrabctl rules`. The channel is
# intentionally disabled pending owner-approved offline key rotation/custody.
# Both network-facing commands must refuse before issuing even a local request.
# This harness never reads or changes the MacCrab support directory.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/.build/debug/maccrabctl"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/maccrab-rulechan-disabled.XXXXXX")"
PORT_FILE="$WORK/port"
REQUEST_LOG="$WORK/requests.log"
SERVER_PID=""

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: swift build --product maccrabctl" >&2; exit 2; }

python3 - "$PORT_FILE" "$REQUEST_LOG" <<'PY' &
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys

port_file, request_log = sys.argv[1:3]

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open(request_log, "a", encoding="utf-8") as out:
            out.write(self.path + "\n")
        self.send_response(500)
        self.end_headers()

    def log_message(self, *_):
        pass

server = HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w", encoding="utf-8") as out:
    out.write(str(server.server_port))
server.serve_forever()
PY
SERVER_PID=$!

for _ in $(seq 1 100); do
    [ -s "$PORT_FILE" ] && break
    sleep 0.05
done
[ -s "$PORT_FILE" ] || { echo "local request sentinel failed to start" >&2; exit 2; }
BASE="http://127.0.0.1:$(cat "$PORT_FILE")/"

set +e
CHECK_OUTPUT="$($BIN rules check-updates --rules-base "$BASE" 2>&1)"
CHECK_RC=$?
UPDATE_OUTPUT="$($BIN rules update --rules-base "$BASE" 2>&1)"
UPDATE_RC=$?
set -e

if [ "$CHECK_RC" -eq 0 ] || ! grep -q "rule-update channel is disabled" <<<"$CHECK_OUTPUT"; then
    echo "FAIL: check-updates did not fail closed with the disabled-channel diagnostic" >&2
    echo "$CHECK_OUTPUT" >&2
    exit 1
fi
echo "PASS: check-updates refused while release policy is disabled"

if [ "$UPDATE_RC" -eq 0 ] || ! grep -q "rule-update channel is disabled" <<<"$UPDATE_OUTPUT"; then
    echo "FAIL: update did not fail closed with the disabled-channel diagnostic" >&2
    echo "$UPDATE_OUTPUT" >&2
    exit 1
fi
echo "PASS: update refused while release policy is disabled"

if [ -s "$REQUEST_LOG" ]; then
    echo "FAIL: disabled commands issued network request(s):" >&2
    sed 's/^/  /' "$REQUEST_LOG" >&2
    exit 1
fi
echo "PASS: neither command reached the local network sentinel"
echo "rule-channel disabled-state e2e: ALL GREEN"
