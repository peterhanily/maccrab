// RuleFixtureSupport.swift
// MacCrabCLITests
//
// A temporary support directory and a compiled rule for the tests of the rule
// commands. Those tests call the functions the commands use with a support
// directory, not the commands, which act on the real support directory and
// exit the process.

import Foundation
import Testing

/// A support directory with empty compiled_rules and user_rules folders.
struct RuleFixtureDirectory {
    let root: URL

    init() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-rule-command-\(UUID().uuidString)", isDirectory: true)
        for folder in ["compiled_rules", "user_rules"] {
            try FileManager.default.createDirectory(
                at: root.appendingPathComponent(folder), withIntermediateDirectories: true)
        }
    }

    var path: String { root.path }

    func remove() { try? FileManager.default.removeItem(at: root) }

    /// Writes `object` as JSON to `name` under the support directory.
    @discardableResult
    func write(_ object: [String: Any], to name: String) throws -> URL {
        let url = root.appendingPathComponent(name)
        try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
        return url
    }

    func object(at url: URL) throws -> [String: Any] {
        try #require(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }
}

/// A compiled single-event rule in the shape the engine decodes.
/// `status: nil` leaves that key out.
func fixtureRule(_ id: String, status: String? = "stable", enabled: Bool = true,
                 level: String = "medium") -> [String: Any] {
    var rule: [String: Any] = [
        "id": id, "title": "Fixture \(id)", "description": "rule command fixture", "level": level,
        "tags": ["attack.discovery"], "logsource": ["category": "file_event", "product": "macos"],
        "predicates": [["field": "file.path", "modifier": "contains",
                        "values": ["/maccrab-rule-command-fixture/"], "negate": false]],
        "condition": "all_of", "falsepositives": ["test fixture"], "enabled": enabled,
    ]
    if let status { rule["status"] = status }
    return rule
}
