#!/usr/bin/env bash
# regenerate-otlp-proto.sh
#
# Regenerate Sources/MacCrabCore/Network/Generated/*.pb.swift from the
# vendored .proto files at vendor/opentelemetry-proto/.
#
# v1.9 PR-3a ships a hand-rolled minimal protobuf wire-format reader
# (Sources/MacCrabCore/Network/MinimalProtoReader.swift) that satisfies the
# stub OTLP receiver's "decode and drop" contract without requiring protoc.
# This regen script is for PR-3b+ when the receiver wires to TraceStore and
# we need full SwiftProtobuf-generated message types for deep field access.
#
# Requirements:
#   - protoc (Apple-recommended: `brew install protobuf`)
#   - protoc-gen-swift (`brew install swift-protobuf`)
#
# Usage:
#   scripts/regenerate-otlp-proto.sh
#
# Output: Sources/MacCrabCore/Network/Generated/*.pb.swift
#
# Pin the generated commit in vendor/opentelemetry-proto/COMMIT.txt so the
# wire-format contract is locked across builds.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROTO_ROOT="$REPO_ROOT/vendor/opentelemetry-proto"
OUT_DIR="$REPO_ROOT/Sources/MacCrabCore/Network/Generated"

if ! command -v protoc >/dev/null 2>&1; then
    echo "error: protoc not found in PATH" >&2
    echo "install with: brew install protobuf swift-protobuf" >&2
    exit 1
fi

if ! command -v protoc-gen-swift >/dev/null 2>&1; then
    echo "error: protoc-gen-swift not found in PATH" >&2
    echo "install with: brew install swift-protobuf" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"

# Generate Swift code for every vendored .proto. The
# `--swift_opt=Visibility=Public` option exposes the generated types so
# MacCrabCore's OTLPReceiver can use them across module boundaries cleanly.
find "$PROTO_ROOT" -name '*.proto' -print0 | while IFS= read -r -d '' proto; do
    echo "→ $(basename "$proto")"
    protoc \
        --proto_path="$PROTO_ROOT" \
        --swift_out="$OUT_DIR" \
        --swift_opt=Visibility=Public \
        --swift_opt=FileNaming=DropPath \
        "$proto"
done

echo
echo "Generated files in $OUT_DIR:"
ls -1 "$OUT_DIR"
echo
echo "Reminder: re-run the OTLPReceiver golden-fixture test:"
echo "  swift test --filter OTLPReceiver"
