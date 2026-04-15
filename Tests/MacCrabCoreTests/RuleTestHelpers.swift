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

/// Compiles all rules from the project's Rules/ directory to /tmp/maccrab_v3.
/// Idempotent and cache-aware: skips compilation when the compiled dir
/// already exists AND nothing under Rules/ has been modified more recently.
/// Deleting /tmp/maccrab_v3 is no longer required after adding a new rule.
func ensureRulesCompiled() {
    let compiledDir = "/tmp/maccrab_v3"
    _compileLock.lock()
    defer { _compileLock.unlock() }

    let projectDir = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()   // Tests/MacCrabCoreTests
        .deletingLastPathComponent()   // Tests
        .deletingLastPathComponent()   // project root
    let rulesDir = projectDir.appendingPathComponent("Rules").path

    if FileManager.default.fileExists(atPath: compiledDir),
       !rulesDirNewerThan(compiledDir, rulesRoot: rulesDir) {
        return
    }

    // Wipe any stale compiled output so the compiler can regenerate cleanly.
    try? FileManager.default.removeItem(atPath: compiledDir)

    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
    proc.arguments = [
        projectDir.appendingPathComponent("Compiler/compile_rules.py").path,
        "--input-dir", rulesDir,
        "--output-dir", compiledDir,
    ]
    proc.standardOutput = FileHandle.nullDevice
    proc.standardError = FileHandle.nullDevice
    try? proc.run()
    proc.waitUntilExit()
}

/// Return true if any .yml under `rulesRoot` has an mtime newer than the
/// most-recently-modified file in `compiledDir`. Cheap walk — both trees
/// are small (≤ a few hundred files).
private func rulesDirNewerThan(_ compiledDir: String, rulesRoot: String) -> Bool {
    let fm = FileManager.default
    let compiledNewest = newestMTime(at: compiledDir)
    let rulesNewest = newestMTime(at: rulesRoot, extension: "yml")
    guard let compiledMTime = compiledNewest, let rulesMTime = rulesNewest else {
        return true
    }
    _ = fm
    return rulesMTime > compiledMTime
}

private func newestMTime(at path: String, extension ext: String? = nil) -> Date? {
    guard let enumerator = FileManager.default.enumerator(atPath: path) else { return nil }
    var newest: Date?
    for case let rel as String in enumerator {
        if let ext, !rel.hasSuffix(".\(ext)") { continue }
        let full = (path as NSString).appendingPathComponent(rel)
        if let attrs = try? FileManager.default.attributesOfItem(atPath: full),
           let mtime = attrs[.modificationDate] as? Date {
            if newest == nil || mtime > newest! {
                newest = mtime
            }
        }
    }
    return newest
}
