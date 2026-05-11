// GraphRuleLoader.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-13) — loads graph rule JSON files from disk
// per §23 of the v1.10.0 spec.
//
// Convention: rules live in `Rules/graph/*.json` in the source tree;
// at runtime they're read from
// `<support-dir>/compiled_rules/graph/` (production) or directly from
// the source tree (development / tests).

import Foundation
import os.log

public enum GraphRuleLoader {

    private static let logger = Logger(subsystem: "com.maccrab.tracegraph", category: "rule-loader")

    /// Load every `*.json` file from the directory and decode it as
    /// a `GraphRule`. Files that fail to decode are skipped with a
    /// log message — one bad rule should not silence the rest of the
    /// graph-rule pipeline.
    public static func loadRules(from directory: URL) -> [GraphRule] {
        guard let urls = try? FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }
        var rules: [GraphRule] = []
        for url in urls where url.pathExtension == "json" {
            do {
                let data = try Data(contentsOf: url)
                let rule = try JSONDecoder().decode(GraphRule.self, from: data)
                rules.append(rule)
            } catch {
                logger.warning("graph rule \(url.lastPathComponent, privacy: .public) failed to decode: \(error.localizedDescription, privacy: .public)")
            }
        }
        return rules.sorted { $0.id < $1.id }
    }

    /// Load directly from the project's source tree
    /// `Rules/graph/` directory. Useful for tests and dev workflows.
    public static func loadFromProjectSource(projectRoot: URL) -> [GraphRule] {
        let dir = projectRoot.appendingPathComponent("Rules/graph", isDirectory: true)
        return loadRules(from: dir)
    }
}
