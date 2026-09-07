#!/usr/bin/python3
"""Verify the qualification compiler identity using fixed, read-only tools."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


LOCK_PATH = Path(__file__).resolve().with_name("swift-toolchain.json")
LOCK_KEYS = {"schema_version", "swift_banner", "xcode_version", "xcode_build"}


def parse_lock(text: str) -> dict:
    def unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate toolchain lock key")
            result[key] = value
        return result

    lock = json.loads(text, object_pairs_hook=unique_keys)
    if not isinstance(lock, dict) or set(lock) != LOCK_KEYS:
        raise ValueError("toolchain lock must contain exactly the documented fields")
    if type(lock["schema_version"]) is not int or lock["schema_version"] != 1:
        raise ValueError("unsupported toolchain lock schema")
    for key in LOCK_KEYS - {"schema_version"}:
        value = lock[key]
        if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
            raise ValueError(f"invalid toolchain lock field: {key}")
    return lock


def validate_identity(lock: dict, swift_output: str, xcode_output: str) -> None:
    swift_banners = [line.strip() for line in swift_output.splitlines()
                     if line.strip().startswith("Apple Swift version ")]
    if swift_banners != [lock["swift_banner"]]:
        raise ValueError(f"Swift compiler build differs from scripts/swift-toolchain.json: expected {lock['swift_banner']!r}; observed {swift_banners!r}")
    xcode_lines = [line.strip() for line in xcode_output.splitlines() if line.strip()]
    expected_xcode = [f"Xcode {lock['xcode_version']}", f"Build version {lock['xcode_build']}"]
    if xcode_lines != expected_xcode:
        raise ValueError(f"Xcode version/build differs from scripts/swift-toolchain.json: expected {expected_xcode!r}; observed {xcode_lines!r}")


def main() -> int:
    try:
        if len(sys.argv) != 1:
            raise ValueError("this check does not accept tool or lock overrides")
        lock = parse_lock(LOCK_PATH.read_text(encoding="utf-8"))
        swift = subprocess.run(
            ["/usr/bin/swift", "--version"], check=True, capture_output=True,
            text=True, timeout=10,
        )
        xcode = subprocess.run(
            ["/usr/bin/xcodebuild", "-version"], check=True, capture_output=True,
            text=True, timeout=10,
        )
        validate_identity(lock, swift.stdout, xcode.stdout)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: qualification toolchain: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"result": "PASSED", **lock}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
