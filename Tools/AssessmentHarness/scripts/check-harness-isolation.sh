#!/usr/bin/env bash
# assessment-framework (P0): the non-contamination gate.
#
# The root MacCrab package MUST NEVER reference the Tools/AssessmentHarness
# sub-package — the harness triggers/orchestrates and must not ship inside the
# detection engine. This gate asserts that a root RELEASE build produces NO
# harness artifacts (no `maccrab-assess` executable, no `HarnessCore.*` module
# products). If any appear, the isolation boundary has been breached.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# ../../.. : scripts -> AssessmentHarness -> Tools -> repo root
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$REPO_ROOT"

BIN_PATH="$(swift build -c release --show-bin-path)"

if [ ! -d "$BIN_PATH" ]; then
    echo "OK: root release bin dir does not exist yet ($BIN_PATH) — nothing to contaminate"
    exit 0
fi

# grep the directory listing; a match means a harness artifact leaked into root.
if ls -1 "$BIN_PATH" | grep -qE '^(maccrab-assess$|HarnessCore\.)'; then
    echo "FAIL: harness artifact found in root release bin dir: $BIN_PATH" >&2
    ls -1 "$BIN_PATH" | grep -E '^(maccrab-assess$|HarnessCore\.)' >&2
    exit 1
fi

echo "OK: no harness artifacts in root release bin ($BIN_PATH)"
