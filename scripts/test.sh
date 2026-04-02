#!/bin/bash
# Run HawkEye tests using Swift Testing framework.
# Requires CommandLineTools with the Testing framework installed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

FRAMEWORK_DIR="/Library/Developer/CommandLineTools/Library/Developer/Frameworks"

if [ ! -d "$FRAMEWORK_DIR/Testing.framework" ]; then
    echo "ERROR: Swift Testing framework not found at $FRAMEWORK_DIR"
    echo "Install the latest Command Line Tools: xcode-select --install"
    exit 1
fi

cd "$PROJECT_DIR"
exec swift test \
    -Xswiftc -F"$FRAMEWORK_DIR" \
    -Xlinker -rpath -Xlinker "$FRAMEWORK_DIR" \
    "$@"
