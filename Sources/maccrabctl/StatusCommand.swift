import Foundation
import MacCrabCore

extension MacCrabCtl {
    static func showStatus() async {
        let supportDir = maccrabDataDir()
        let dbPath = supportDir + "/events.db"
        let alertsPath = supportDir + "/alerts.jsonl"

        // LOCALIZE: "MacCrab Status"
        print("MacCrab Status")
        print("══════════════════════════════════════")

        // Check if daemon is running
        let daemonRunning = isDaemonRunning()
        // LOCALIZE: "Running", "Not running"
        print("Daemon:     \(daemonRunning ? "Running \u{2713}" : "Not running \u{2717}")")

        // Database info
        if FileManager.default.fileExists(atPath: dbPath) {
            let attrs = try? FileManager.default.attributesOfItem(atPath: dbPath)
            let size = attrs?[.size] as? UInt64 ?? 0
            let modified = attrs?[.modificationDate] as? Date
            print("Database:   \(dbPath)")
            print("DB Size:    \(formatBytes(size))")
            if let modified = modified {
                print("Last Event: \(formatDate(modified))")
            }
        } else {
            print("Database:   Not found (daemon has not run yet)")
        }

        // Alerts info
        if FileManager.default.fileExists(atPath: alertsPath) {
            let attrs = try? FileManager.default.attributesOfItem(atPath: alertsPath)
            let size = attrs?[.size] as? UInt64 ?? 0
            print("Alerts Log: \(formatBytes(size))")
        }

        // Rules info
        let compiledDir = supportDir + "/compiled_rules"
        if FileManager.default.fileExists(atPath: compiledDir) {
            let files = try? FileManager.default.contentsOfDirectory(atPath: compiledDir)
            let ruleCount = files?.filter { $0.hasSuffix(".json") }.count ?? 0
            print("Rules:      \(ruleCount) compiled rules loaded")
        } else {
            print("Rules:      No compiled rules found")
        }

        print("══════════════════════════════════════")
    }

    static func isDaemonRunning() -> Bool {
        let pipe = Pipe()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
        process.arguments = ["-x", "maccrabd"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
        return process.terminationStatus == 0
    }
}
