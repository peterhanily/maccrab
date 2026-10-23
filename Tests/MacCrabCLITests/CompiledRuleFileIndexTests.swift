import Foundation
import Testing
@testable import maccrab_mcp

/// get_alert_detail finds a compiled rule by id without reopening the corpus
/// for every lookup, including lookups for ids the corpus no longer has.
@Suite("Compiled rule index")
struct CompiledRuleFileIndexTests {
    /// A rule file the engine decodes, as every user rule it loads must.
    private func write(_ id: String, to path: String, title: String? = nil) throws {
        let json = try JSONSerialization.data(withJSONObject: [
            "id": id, "title": title ?? id, "description": "rule index fixture", "level": "low",
            "tags": ["attack.discovery"], "logsource": ["category": "file_event", "product": "macos"],
            "predicates": [["field": "file.path", "modifier": "contains",
                            "values": ["/maccrab-rule-index-fixture/"], "negate": false]],
            "condition": "all_of", "falsepositives": ["test fixture"], "enabled": true, "status": "stable",
        ])
        try json.write(to: URL(fileURLWithPath: path))
    }

    /// Moves a directory's mtime on, as any change to its entries would.
    private func touch(_ path: String) throws {
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: 5)], ofItemAtPath: path)
    }

    /// compiled_rules and user_rules under a fresh support directory.
    private func supportDirectory() throws -> (root: String, compiled: String, user: String) {
        let root = NSTemporaryDirectory() + "maccrab-rule-index-\(UUID().uuidString)"
        let compiled = root + "/compiled_rules"
        try FileManager.default.createDirectory(atPath: compiled, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: root + "/user_rules", withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root + "/user_rules")
        return (root, compiled, root + "/user_rules")
    }

    @Test("every rule directory resolves; an unknown id does not rebuild until the rules change")
    func lookups() throws {
        // supportDirectory() makes user_rules 0755: under a umask of 002 a
        // default mkdir leaves it group-writable, which the engine refuses.
        let (root, dir, _) = try supportDirectory()
        for sub in ["/sequences", "/graph", "/auto_generated"] {
            try FileManager.default.createDirectory(atPath: dir + sub, withIntermediateDirectories: true)
        }
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.a", to: dir + "/a.json")
        try write("seq.b", to: dir + "/sequences/b.json")
        try write("graph.g", to: dir + "/graph/g.json")
        try write("auto.x", to: dir + "/auto_generated/x.json")
        try write("user.u", to: root + "/user_rules/u.json")
        let index = CompiledRuleFileIndex()
        for id in ["rule.a", "seq.b", "graph.g", "auto.x", "user.u"] {
            #expect(index.rule(id: id, in: dir)?["id"] as? String == id, "\(id)")
        }

        // Add a file, then restore the directory's exact mtime: an id with no
        // entry must not rebuild while the directories look unchanged.
        var before = stat()
        #expect(stat(dir, &before) == 0)
        #expect(index.rule(id: "rule.missing", in: dir) == nil)
        try write("rule.c", to: dir + "/c.json")
        var times = [before.st_atimespec, before.st_mtimespec]
        #expect(utimensat(AT_FDCWD, dir, &times, 0) == 0)
        #expect(index.rule(id: "rule.c", in: dir) == nil, "no rebuild while the directories are unchanged")

        // A compile changes the directory: the next miss rebuilds.
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: 5)], ofItemAtPath: dir)
        #expect(index.rule(id: "rule.c", in: dir)?["id"] as? String == "rule.c")
    }

    @Test("a trusted user rule replaces the bundled rule with its id, as the engine loads it")
    func userRulesTakePrecedence() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.dup", to: compiled + "/a.json", title: "bundled")
        try write("rule.dup", to: user + "/a.json", title: "user override")
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.dup", in: compiled)?["title"] as? String == "user override")
    }

    @Test("an insecure user_rules directory is ignored, also after it was trusted")
    func insecureUserRulesAreIgnored() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.dup", to: compiled + "/a.json", title: "bundled")
        try write("rule.dup", to: user + "/a.json", title: "user override")
        try write("user.only", to: user + "/b.json")
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.dup", in: compiled)?["title"] as? String == "user override")
        #expect(index.rule(id: "user.only", in: compiled) != nil)
        // Group-writable: the engine refuses the whole overlay, and so does
        // the index, though it already holds the user files.
        try FileManager.default.setAttributes([.posixPermissions: 0o775], ofItemAtPath: user)
        #expect(index.rule(id: "rule.dup", in: compiled)?["title"] as? String == "bundled")
        #expect(index.rule(id: "user.only", in: compiled) == nil)
        #expect(CompiledRuleFileIndex().rule(id: "user.only", in: compiled) == nil)
    }

    @Test("a FIFO or a symlink among the user rules is skipped without blocking")
    func unsafeCarriersAreSkipped() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.a", to: compiled + "/a.json")
        #expect(mkfifo(user + "/f.json", 0o644) == 0)
        try write("outside.rule", to: root + "/outside.json")
        try FileManager.default.createSymbolicLink(atPath: user + "/l.json", withDestinationPath: root + "/outside.json")
        let index = CompiledRuleFileIndex()
        // The old reader waited forever on a FIFO; give the lookup a thread of
        // its own so a regression fails here instead of hanging the run.
        final class Box: @unchecked Sendable { var linked: [String: Any]?; var plain: [String: Any]? }
        let box = Box()
        let done = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            box.linked = index.rule(id: "outside.rule", in: compiled)
            box.plain = index.rule(id: "rule.a", in: compiled)
            done.signal()
        }
        guard done.wait(timeout: .now() + 10) == .success else {
            Issue.record("the index blocked on a FIFO in user_rules")
            return
        }
        #expect(box.linked == nil, "a symlinked rule file is not followed")
        #expect(box.plain?["id"] as? String == "rule.a")
    }

    @Test("an override installed after a bundled lookup is shown on the same index")
    func overrideAddedDuringASession() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "bundled")
        // The engine's install-rule handler writes the override; the server,
        // alive for the whole agent session, must not keep the bundled entry.
        try write("rule.x", to: user + "/x.json", title: "user override")
        try touch(user)
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "user override")
    }

    @Test("making user_rules trusted again is seen though its mtime is unchanged")
    func chmodToTrustedIsSeen() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        try write("rule.x", to: user + "/x.json", title: "user override")
        try FileManager.default.setAttributes([.posixPermissions: 0o775], ofItemAtPath: user)
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "bundled")
        var before = stat()
        #expect(stat(user, &before) == 0)
        // chmod changes only the ctime and mode; the mtime stays as it was.
        #expect(chmod(user, 0o755) == 0)
        var after = stat()
        #expect(stat(user, &after) == 0)
        #expect(after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec
            && after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec)
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "user override")
    }

    @Test("a user file the engine cannot decode leaves the bundled rule in place")
    func undecodableUserRuleIsIgnored() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        // An id and a title only: the engine logs a load error and keeps the
        // bundled definition, so the index must not show this one.
        try JSONSerialization.data(withJSONObject: ["id": "rule.x", "title": "refused override"])
            .write(to: URL(fileURLWithPath: user + "/x.json"))
        try JSONSerialization.data(withJSONObject: ["id": "user.refused", "title": "refused rule"])
            .write(to: URL(fileURLWithPath: user + "/y.json"))
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "bundled")
        #expect(index.rule(id: "user.refused", in: compiled) == nil)
    }

    @Test("an id resolves single-event, then sequence, then graph; user rules override single-event ids only")
    func precedenceAcrossEngines() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        for sub in ["/sequences", "/graph"] {
            try FileManager.default.createDirectory(atPath: compiled + sub, withIntermediateDirectories: true)
        }
        try write("dup.id", to: compiled + "/a.json", title: "single")
        try write("dup.id", to: compiled + "/sequences/a.json", title: "sequence")
        try write("dup.id", to: compiled + "/graph/a.json", title: "graph")
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "dup.id", in: compiled)?["title"] as? String == "single")
        try FileManager.default.removeItem(atPath: compiled + "/a.json")
        try touch(compiled)
        #expect(index.rule(id: "dup.id", in: compiled)?["title"] as? String == "sequence")
        try FileManager.default.removeItem(atPath: compiled + "/sequences/a.json")
        try touch(compiled + "/sequences")
        #expect(index.rule(id: "dup.id", in: compiled)?["title"] as? String == "graph")

        // The engine overlays user rules on single-event rules only; sequence
        // and graph rules run from their own files.
        try write("seq.id", to: compiled + "/sequences/s.json", title: "sequence")
        try write("graph.id", to: compiled + "/graph/g.json", title: "graph")
        try write("seq.id", to: user + "/s.json", title: "user")
        try write("graph.id", to: user + "/g.json", title: "user")
        try write("new.id", to: user + "/n.json", title: "user rule")
        let fresh = CompiledRuleFileIndex()
        #expect(fresh.rule(id: "seq.id", in: compiled)?["title"] as? String == "sequence")
        #expect(fresh.rule(id: "graph.id", in: compiled)?["title"] as? String == "graph")
        #expect(fresh.rule(id: "new.id", in: compiled)?["title"] as? String == "user rule")
    }

    @Test("trust follows the engine's directory and file checks")
    func trustMatchesTheEngine() {
        typealias Index = CompiledRuleFileIndex
        #expect(Index.trustsUserRulesDirectory(owner: 0, mode: 0o40755, isSymlink: false, engineUID: 0))
        #expect(!Index.trustsUserRulesDirectory(owner: 0, mode: 0o40775, isSymlink: false, engineUID: 0))
        #expect(!Index.trustsUserRulesDirectory(owner: 0, mode: 0o40757, isSymlink: false, engineUID: 0))
        #expect(!Index.trustsUserRulesDirectory(owner: 501, mode: 0o40755, isSymlink: false, engineUID: 0))
        #expect(Index.trustsUserRulesDirectory(owner: 501, mode: 0o40755, isSymlink: false, engineUID: 501))
        #expect(Index.trustsUserRulesDirectory(owner: 0, mode: 0o40755, isSymlink: false, engineUID: 501))
        #expect(!Index.trustsUserRulesDirectory(owner: 0, mode: 0o120755, isSymlink: true, engineUID: 0))
        #expect(Index.trustsUserRuleFile(owner: 0, engineUID: 0))
        #expect(!Index.trustsUserRuleFile(owner: 501, engineUID: 0))
        #expect(Index.engineUID(forCompiledDir: "/Library/Application Support/MacCrab/compiled_rules") == 0)
        #expect(Index.engineUID(forCompiledDir: NSTemporaryDirectory() + "x/compiled_rules") == getuid())
        // Each user rule file is held to the engine's owner check while the
        // index is built and before a cached one is used.
        let source = (try? String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrab-mcp/ReadParityTools.swift"), encoding: .utf8)) ?? ""
        #expect(source.contains("for path in Self.ruleFiles(in: userDir) where Self.userRuleTrusted(path, engineUID: engineUID) {"))
        #expect(source.contains("Self.userRuleTrusted(path, engineUID: engineUID) else { return nil }"))
    }
}
