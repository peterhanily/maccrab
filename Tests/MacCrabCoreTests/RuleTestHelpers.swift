// RuleTestHelpers.swift
// Shared rule compilation helper for all MacCrabCore test files.
//
// The NSLock serializes the one-time compilation step across all parallel
// Swift Testing tests, which run concurrently in the same process.
// Without this guard, multiple tests hitting an empty /tmp/maccrab_v3
// simultaneously would write overlapping partial JSON files — producing
// "Unexpected end of file" decode errors in whichever test reads first.

import Foundation
@testable import MacCrabCore

let _compileLock = NSLock()

/// Compiles all rules from the project's Rules/ directory to /tmp/maccrab_v3
/// (idempotent — skips compilation if the directory already exists).
func ensureRulesCompiled() {
    let compiledDir = "/tmp/maccrab_v3"
    _compileLock.lock()
    defer { _compileLock.unlock() }

    guard !FileManager.default.fileExists(atPath: compiledDir) else { return }

    let projectDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()   // Tests/MacCrabCoreTests
        .deletingLastPathComponent()   // Tests
        .deletingLastPathComponent()   // project root
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    proc.arguments = [
        projectDir.appendingPathComponent("Compiler/compile_rules.py").path,
        "--input-dir", projectDir.appendingPathComponent("Rules").path,
        "--output-dir", compiledDir,
    ]
    proc.standardOutput = FileHandle.nullDevice
    proc.standardError = FileHandle.nullDevice
    try? proc.run()
    proc.waitUntilExit()
}
