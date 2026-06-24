// ATTACKRefTests.swift
// FIQ-7: ATTACKRef humanizes ATT&CK technique codes for the dashboard.
// Pin normalization (both spellings), the mechanical URL, the parent-name
// lookup + bare-code fallback, and that every parent technique the shipped
// rules reference has a name (no silent gaps).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ATTACKRef")
struct ATTACKRefTests {

    @Test("normalize accepts the Sigma tag form and the bare code, rejects non-codes")
    func normalize() {
        #expect(ATTACKRef.normalize("attack.t1059.004") == "T1059.004")
        #expect(ATTACKRef.normalize("T1059") == "T1059")
        #expect(ATTACKRef.normalize("attack.t1059") == "T1059")
        #expect(ATTACKRef.normalize("attack.command_and_control") == nil)  // a tactic, not a technique
        #expect(ATTACKRef.normalize("nonsense") == nil)
    }

    @Test("url is mechanical + correct for parent and sub-technique")
    func url() {
        #expect(ATTACKRef.url(forCode: "attack.t1059.004") == "https://attack.mitre.org/techniques/T1059/004/")
        #expect(ATTACKRef.url(forCode: "T1059") == "https://attack.mitre.org/techniques/T1059/")
        #expect(ATTACKRef.url(forCode: "not-a-code") == nil)
    }

    @Test("name resolves via the parent map; sub-techniques inherit it; unknown → nil")
    func name() {
        #expect(ATTACKRef.name(forCode: "attack.t1059.004") == "Command and Scripting Interpreter")
        #expect(ATTACKRef.name(forCode: "T1003") == "OS Credential Dumping")
        #expect(ATTACKRef.name(forCode: "T1059") == "Command and Scripting Interpreter")
        #expect(ATTACKRef.name(forCode: "T9999") == nil)   // real form, not in the curated map
    }

    @Test("display humanizes when known, bare-code when unknown, raw when unparseable")
    func display() {
        #expect(ATTACKRef.display(forCode: "attack.t1059.004") == "T1059.004 — Command and Scripting Interpreter")
        #expect(ATTACKRef.display(forCode: "T9999.001") == "T9999.001")   // parseable, unknown → bare code
        #expect(ATTACKRef.display(forCode: "garbage") == "garbage")        // unparseable → raw
    }

    @Test("every parent technique referenced by the shipped rules has a name")
    func coverageOfShippedRules() throws {
        // Source-derived: a rule adding a new attack.t#### tag without a name
        // here fails CI (the bare code would render instead of the technique).
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let rulesDir = root.appendingPathComponent("Rules")
        let fm = FileManager.default
        guard let en = fm.enumerator(at: rulesDir, includingPropertiesForKeys: nil) else {
            Issue.record("Rules/ not found at \(rulesDir.path)"); return
        }
        var parents = Set<String>()
        let re = try NSRegularExpression(pattern: "attack\\.t[0-9]+", options: [.caseInsensitive])
        for case let url as URL in en where ["yml", "yaml", "json"].contains(url.pathExtension.lowercased()) {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            let ns = text as NSString
            for m in re.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                if let code = ATTACKRef.normalize(ns.substring(with: m.range)) {
                    parents.insert(ATTACKRef.parent(code))
                }
            }
        }
        #expect(!parents.isEmpty, "extracted zero technique tags from Rules/ — extraction broke")
        let missing = parents.filter { ATTACKRef.parentNames[$0] == nil }.sorted()
        #expect(missing.isEmpty, "rules reference ATT&CK parents with no name in ATTACKRef.parentNames: \(missing)")
    }
}
