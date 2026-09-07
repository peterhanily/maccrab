// RuleTestHelpers.swift
// A test process compiles its own rule fixture once. It never reuses another
// checkout's output or relies on source/generated-file modification times.

import Foundation
import Darwin
@testable import MacCrabCore

let compiledRulesDirectory = FileManager.default.temporaryDirectory
    .appendingPathComponent("maccrab-test-rules-\(UUID().uuidString)", isDirectory: true)

private enum RuleCompilationFixture {
    // Swift initializes static stored properties once, even when parallel tests
    // arrive together. Cache failure as well as success so every caller gets the
    // original compiler diagnostic instead of reading partially generated JSON.
    static let result: Result<URL, Error> = Result {
        let projectDirectory = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try compileRuleFixture(
            projectDirectory: projectDirectory,
            outputDirectory: compiledRulesDirectory
        )
    }
}

/// Returns this process's freshly compiled rules, or throws the compilation
/// failure. Callers must not read the fixture until this succeeds.
@discardableResult
func ensureRulesCompiled() throws -> URL {
    try RuleCompilationFixture.result.get()
}

struct RuleFixtureCompilationError: Error, CustomStringConvertible {
    let description: String
}

/// Kept separate from the once-per-process wrapper so compiler launch, exit,
/// timeout, and incomplete-output handling can be exercised without touching
/// the shared fixture used by detection tests.
func compileRuleFixture(
    projectDirectory: URL,
    outputDirectory: URL,
    timeout: TimeInterval = 120,
    pythonExecutableURL: URL = URL(fileURLWithPath: "/usr/bin/python3")
) throws -> URL {
    let fileManager = FileManager.default
    // An existing directory is a caller error, never permission to reuse or
    // remove someone else's generated data.
    guard !fileManager.fileExists(atPath: outputDirectory.path) else {
        throw RuleFixtureCompilationError(description: "Rule fixture output already exists: \(outputDirectory.path)")
    }
    try fileManager.createDirectory(at: outputDirectory, withIntermediateDirectories: false)
    var succeeded = false
    defer {
        if !succeeded { try? fileManager.removeItem(at: outputDirectory) }
    }

    let logURL = outputDirectory.appendingPathComponent("compiler.log")
    guard fileManager.createFile(atPath: logURL.path, contents: nil) else {
        throw RuleFixtureCompilationError(description: "Cannot create rule compiler log at \(logURL.path)")
    }
    let log = try FileHandle(forWritingTo: logURL)
    defer {
        try? log.close()
        try? fileManager.removeItem(at: logURL)
    }

    let process = Process()
    process.executableURL = pythonExecutableURL
    process.arguments = [
        projectDirectory.appendingPathComponent("Compiler/compile_rules.py").path,
        "--input-dir", projectDirectory.appendingPathComponent("Rules").path,
        "--output-dir", outputDirectory.path,
    ]
    var environment = Foundation.ProcessInfo.processInfo.environment
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    process.environment = environment
    process.standardOutput = log
    process.standardError = log
    let completion = DispatchSemaphore(value: 0)
    process.terminationHandler = { _ in completion.signal() }
    do {
        try process.run()
    } catch {
        throw RuleFixtureCompilationError(description: "Could not launch rule compiler: \(error)")
    }

    guard completion.wait(timeout: .now() + timeout) == .success else {
        if process.isRunning { process.terminate() }
        if completion.wait(timeout: .now() + 2) != .success, process.isRunning {
            kill(process.processIdentifier, SIGKILL)
            _ = completion.wait(timeout: .now() + 2)
        }
        throw RuleFixtureCompilationError(description: "Rule compiler exceeded \(timeout) seconds")
    }
    guard process.terminationReason == .exit, process.terminationStatus == 0 else {
        let diagnostic = (try? Data(contentsOf: logURL)).map {
            String(decoding: $0.suffix(64 * 1024), as: UTF8.self)
        } ?? "(compiler log unavailable)"
        throw RuleFixtureCompilationError(
            description: "Rule compiler failed (status \(process.terminationStatus)): \(diagnostic)"
        )
    }
    let ruleFiles = try fileManager.contentsOfDirectory(
        at: outputDirectory, includingPropertiesForKeys: nil
    ).filter { $0.pathExtension == "json" }
    guard !ruleFiles.isEmpty else {
        throw RuleFixtureCompilationError(description: "Rule compiler exited successfully but produced no rule JSON")
    }
    succeeded = true
    return outputDirectory
}
