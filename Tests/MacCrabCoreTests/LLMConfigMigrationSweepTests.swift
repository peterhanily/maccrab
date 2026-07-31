// LLMConfigMigrationSweepTests.swift
// Guard for the v1.21.6 `LLMConfig.enabled` default flip (true -> false).
//
// Four independent readers parse `llm_config.json` by hand — DaemonSetup (root
// sysext), maccrabctl/Helpers, maccrab-mcp/main, and the dashboard's AI-backend
// status tile. All four treat the file's existence as "the operator configured a
// backend", so all four need `enabled = true` seeded BEFORE the optional
// `enabled` key is read; otherwise an existing user whose file predates that key
// silently loses LLM analysis on upgrade. The first pass of this change updated
// only DaemonSetup and the other three went dark — the same one-site-missed
// shape as the v1.21.4 admin-gate sweep that left AgentTracesConfig behind.
//
// This fails the build if a fifth reader is added without the migration.
import Testing
import Foundation

@Suite("llm_config.json readers all carry the enabled-default migration")
struct LLMConfigMigrationSweepTests {

    @Test("every hand-rolled `json[\"enabled\"]` read seeds the pre-flip default first")
    func allReadersMigrate() throws {
        let sources = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // repo root
            .appendingPathComponent("Sources")

        let enumerator = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)
        var readerCount = 0
        var offenders: [String] = []

        while let url = enumerator?.nextObject() as? URL {
            guard url.pathExtension == "swift" else { continue }
            let lines = try String(contentsOf: url, encoding: .utf8).components(separatedBy: "\n")
            for (i, line) in lines.enumerated() {
                let code = line.components(separatedBy: "//").first ?? line
                guard code.contains(#"json["enabled"] as? Bool"#) else { continue }
                // `enabled` is a generic key — prevention_config.json,
                // alert_notifications.json and per-rule entries all use it and are
                // NOT part of this migration. Only count a read that sits just
                // below the llm_config.json path it is parsing.
                let lead = lines[max(0, i - 40)..<i]
                guard lead.contains(where: { $0.contains("llm_config.json") }) else { continue }
                readerCount += 1
                // The seed must be close by — same statement block, not merely
                // somewhere in the file. Either an explicit pre-seed assignment or
                // a `?? true` fallback on the read itself satisfies it.
                let window = lines[max(0, i - 10)..<i]
                let seeded = code.contains("?? true") || window.contains { seed in
                    let seedCode = seed.components(separatedBy: "//").first ?? seed
                    return seedCode.contains(".enabled = true")
                }
                if !seeded {
                    offenders.append("\(url.lastPathComponent):\(i + 1)  \(line.trimmingCharacters(in: .whitespaces))")
                }
            }
        }

        // If this drops to zero the scan has stopped finding anything and the
        // guard is vacuous — fail rather than pass silently.
        #expect(readerCount >= 4, "expected at least the 4 known llm_config.json readers, found \(readerCount)")
        let detail = offenders.joined(separator: "\n")
        #expect(
            offenders.isEmpty,
            "llm_config.json reader(s) missing the `enabled = true` pre-flip migration:\n\(detail)"
        )
    }
}
