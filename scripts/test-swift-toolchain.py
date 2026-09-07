#!/usr/bin/python3
"""Canned identity contracts only: never invokes compiler or Xcode tools."""

import importlib.util
import json
from pathlib import Path
import unittest


SCRIPT_DIR = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("toolchain_check", SCRIPT_DIR / "check-swift-toolchain.py")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ToolchainIdentityTests(unittest.TestCase):
    def setUp(self):
        self.lock = CHECK.parse_lock((SCRIPT_DIR / "swift-toolchain.json").read_text())
        self.swift = self.lock["swift_banner"] + "\nTarget: arm64-apple-macosx26.0\n"
        self.xcode = f"Xcode {self.lock['xcode_version']}\nBuild version {self.lock['xcode_build']}\n"

    def test_exact_identity_is_accepted(self):
        CHECK.validate_identity(self.lock, self.swift, self.xcode)

    def test_different_host_target_with_same_compiler_is_accepted(self):
        CHECK.validate_identity(self.lock, self.swift.replace("arm64-apple-macosx26.0", "x86_64-apple-macosx14.0"), self.xcode)

    def test_same_swift_version_different_compiler_build_is_rejected(self):
        with self.assertRaises(ValueError):
            CHECK.validate_identity(self.lock, self.swift.replace("swiftlang-", "swiftlang-unqualified-"), self.xcode)

    def test_same_xcode_version_different_build_is_rejected(self):
        with self.assertRaises(ValueError):
            CHECK.validate_identity(self.lock, self.swift, self.xcode.replace(self.lock["xcode_build"], "unqualified"))

    def test_missing_identity_is_rejected(self):
        for swift, xcode in [("", self.xcode), (self.swift, "")]:
            with self.subTest(swift=bool(swift), xcode=bool(xcode)), self.assertRaises(ValueError):
                CHECK.validate_identity(self.lock, swift, xcode)

    def test_ambiguous_swift_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            CHECK.validate_identity(self.lock, self.swift + self.swift, self.xcode)

    def test_unknown_and_duplicate_lock_fields_are_rejected(self):
        with self.assertRaises(ValueError):
            CHECK.parse_lock(json.dumps({**self.lock, "override": "ignored"}))
        with self.assertRaises(ValueError):
            CHECK.parse_lock('{"schema_version": 1, "schema_version": 1}')


if __name__ == "__main__":
    unittest.main()
