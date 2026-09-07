import Foundation
import MacCrabCore

/// Explicit maintenance only. Opening EventStore here would run journal work
/// before the diagnostic's budget even starts, so use a direct read-only handle.
func runStorageCheck(args: [String]) {
    let usage = "Usage: maccrabctl storage check --directory PATH [--timeout-seconds 1…300] [--json]"
    guard args.first == "check" else { MacCrabCtl.usageError(usage) }
    var directory: String?
    var timeout: Double = 30
    var json = false
    var index = 1
    while index < args.count {
        switch args[index] {
        case "--directory" where index + 1 < args.count && directory == nil:
            directory = args[index + 1]
            index += 2
        case "--timeout-seconds" where index + 1 < args.count:
            guard let value = Double(args[index + 1]), value.isFinite, value >= 1, value <= 300 else {
                MacCrabCtl.usageError(usage)
            }
            timeout = value
            index += 2
        case "--json" where !json:
            json = true
            index += 1
        default: MacCrabCtl.usageError(usage)
        }
    }
    guard let directory, !directory.isEmpty else { MacCrabCtl.usageError(usage) }
    let root = URL(fileURLWithPath: directory, isDirectory: true)
    let names = ["events.db", "alerts.db", "tracegraph.db", "traces.db", "campaigns.db"]
    let results = names.map {
        SQLiteIntegrityDiagnostic.check(database: root.appendingPathComponent($0), timeoutSeconds: timeout)
    }
    let passed = results.allSatisfy { $0.status == "passed" }
    if json {
        struct Report: Encodable {
            let schemaVersion = 1
            let diagnostic = "sqlite_quick_check"
            let writesDatabase = false
            let timeoutSecondsPerDatabase: Double
            let results: [SQLiteIntegrityDiagnostic.Result]
        }
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
            encoder.keyEncodingStrategy = .convertToSnakeCase
            let data = try encoder.encode(Report(timeoutSecondsPerDatabase: timeout, results: results))
            FileHandle.standardOutput.write(data + Data("\n".utf8))
        } catch { cliFailure("Could not encode storage diagnostic") }
    } else {
        print("SQLite quick_check: explicit read-only diagnostic (\(Int(timeout)) seconds per database)")
        for result in results {
            print("\(result.database): \(result.status) (\(String(format: "%.3f", result.elapsedSeconds))s)")
        }
        print("This checks SQLite structure. It does not attest journal evidence, FTS content, encryption, or detection readiness.")
        print("Unavailable optional stores remain unverified; no store was created, moved, or repaired.")
    }
    if !passed { exit(1) }
}
