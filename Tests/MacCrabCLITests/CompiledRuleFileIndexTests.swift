import Foundation
import MacCrabCore
import Testing
@testable import maccrab_mcp

/// explain_alert finds a compiled rule by id without reopening the corpus
/// for every lookup, including lookups for ids the corpus no longer has.
@Suite("Compiled rule index")
struct CompiledRuleFileIndexTests {
    /// A rule file the engine decodes, as every user rule it loads must.
    private func write(_ id: String, to path: String, title: String? = nil) throws {
        try ruleData(id, title: title).write(to: URL(fileURLWithPath: path))
    }

    /// The bytes `write` puts in a rule file. Keys are sorted, so two ids of
    /// one length give files of one size.
    private func ruleData(_ id: String, title: String? = nil) throws -> Data {
        try JSONSerialization.data(withJSONObject: [
            "id": id, "title": title ?? id, "description": "rule index fixture", "level": "low",
            "tags": ["attack.discovery"], "logsource": ["category": "file_event", "product": "macos"],
            "predicates": [["field": "file.path", "modifier": "contains",
                            "values": ["/maccrab-rule-index-fixture/"], "negate": false]],
            "condition": "all_of", "falsepositives": ["test fixture"], "enabled": true, "status": "stable",
        ], options: [.sortedKeys])
    }

    /// `ruleData` with "enabled": false, as the dashboard's Disable writes a
    /// copy of a rule into user_rules.
    private func disabledRuleData(_ id: String) throws -> Data {
        var rule = try #require(JSONSerialization.jsonObject(with: ruleData(id)) as? [String: Any])
        rule["enabled"] = false
        return try JSONSerialization.data(withJSONObject: rule, options: [.sortedKeys])
    }

    /// Rewrites an existing file through its own inode, as an editor that saves
    /// in place does: the directory's entries, mtime and ctime stay as they were.
    private func overwriteInPlace(_ path: String, with data: Data) throws {
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        try handle.truncate(atOffset: 0)
        try handle.write(contentsOf: data)
    }

    /// Moves a directory's mtime on, as any change to its entries would.
    private func touch(_ path: String) throws {
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: 5)], ofItemAtPath: path)
    }

    /// Runs /bin/chmod for the ACL changes chmod(2) cannot make.
    private func chmodACL(_ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = arguments
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
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
        #expect(index.rebuildCount == 1)

        // Add a file, then restore the directory's exact mtime. The directory
        // stamps (mtime only for the bundled folders) look unchanged, but the
        // file listing does not, so the miss rebuilds and finds the new rule.
        var before = stat()
        #expect(stat(dir, &before) == 0)
        #expect(index.rule(id: "rule.missing", in: dir) == nil)
        #expect(index.rebuildCount == 1, "a miss with unchanged rules does not rebuild")
        try write("rule.c", to: dir + "/c.json")
        var times = [before.st_atimespec, before.st_mtimespec]
        #expect(utimensat(AT_FDCWD, dir, &times, 0) == 0)
        #expect(index.rule(id: "rule.c", in: dir)?["id"] as? String == "rule.c",
                "a file added without moving the directory mtime is found")
        #expect(index.rebuildCount == 2)

        // A compile changes the directory: the next lookup rebuilds.
        try FileManager.default.setAttributes([.modificationDate: Date(timeIntervalSinceNow: 5)], ofItemAtPath: dir)
        #expect(index.rule(id: "rule.c", in: dir)?["id"] as? String == "rule.c")
        #expect(index.rebuildCount == 3, "a directory mtime change rebuilds")
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

    @Test("a user override whose condition tree the engine rejects leaves the bundled rule in place")
    func structurallyInvalidOverrideIsIgnored() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        // One predicate and a tree that names predicate 99: it decodes, but
        // RuleEngine.loadRules refuses it and keeps the bundled rule.
        var override = try #require(JSONSerialization.jsonObject(
            with: Data(contentsOf: URL(fileURLWithPath: compiled + "/x.json"))) as? [String: Any])
        override["title"] = "invalid override"
        override["condition_tree"] = ["type": "predicate", "index": 99]
        let invalid = try JSONSerialization.data(withJSONObject: override)
        try invalid.write(to: URL(fileURLWithPath: user + "/x.json"))
        #expect(throws: RuleEngineError.self) { _ = try RuleEngine.decodeLoadableRule(invalid) }
        #expect(CompiledRuleFileIndex().rule(id: "rule.x", in: compiled)?["title"] as? String == "bundled")
        // The same override with an in-range reference is the one the engine applies.
        override["title"] = "valid override"
        override["condition_tree"] = ["type": "predicate", "index": 0]
        try JSONSerialization.data(withJSONObject: override).write(to: URL(fileURLWithPath: user + "/x.json"))
        #expect(CompiledRuleFileIndex().rule(id: "rule.x", in: compiled)?["title"] as? String == "valid override")
    }

    @Test("duplicate user rules for one id show the first by name and are reported")
    func duplicateUserRulesAreReported() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.dup", to: compiled + "/a.json", title: "bundled")
        try write("rule.dup", to: user + "/b.json", title: "first")
        try write("rule.dup", to: user + "/c.json", title: "second")
        try write("rule.single", to: user + "/d.json", title: "single")
        let index = CompiledRuleFileIndex()
        // explain_alert's rule section is the first lookup on this index, and
        // again the first after c.json goes, so the flag it shows comes from
        // the build that lookup makes.
        let alertID = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9f0a1b2e"
        func head() -> [String] {
            Array(explainRuleSectionLines(ruleID: "rule.dup", alertID: alertID, hasDetail: true,
                                          compiledDir: compiled, index: index).prefix(3))
        }
        #expect(head() == ["Rule definition:", Self.duplicateNote, Self.userSource])
        #expect(index.rule(id: "rule.dup", in: compiled)?["title"] as? String == "first")
        #expect(index.hasDuplicateUserRules(id: "rule.dup", in: compiled))
        #expect(!index.hasDuplicateUserRules(id: "rule.single", in: compiled))
        try FileManager.default.removeItem(atPath: user + "/c.json")
        #expect(head() == ["Rule definition:", Self.userSource, "  description: rule index fixture"])
        #expect(index.rule(id: "rule.dup", in: compiled)?["title"] as? String == "first")
        #expect(!index.hasDuplicateUserRules(id: "rule.dup", in: compiled))
    }

    @Test("an in-place id edit is found with every directory stamp unchanged, and the old id misses")
    func inPlaceIDEditIsFound() throws {
        let (root, compiled, _) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let path = compiled + "/x.json"
        try ruleData("rule.old").write(to: URL(fileURLWithPath: path))
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.old", in: compiled)?["id"] as? String == "rule.old")
        var dirBefore = stat(), fileBefore = stat()
        #expect(stat(compiled, &dirBefore) == 0)
        #expect(lstat(path, &fileBefore) == 0)
        // Same inode and size, and the file's mtime is put back, so only its
        // ctime moves.
        try overwriteInPlace(path, with: ruleData("rule.new"))
        var times = [fileBefore.st_atimespec, fileBefore.st_mtimespec]
        #expect(utimensat(AT_FDCWD, path, &times, AT_SYMLINK_NOFOLLOW) == 0)
        var dirAfter = stat(), fileAfter = stat()
        #expect(stat(compiled, &dirAfter) == 0)
        #expect(lstat(path, &fileAfter) == 0)
        #expect(fileAfter.st_ino == fileBefore.st_ino && fileAfter.st_size == fileBefore.st_size)
        #expect(fileAfter.st_mtimespec.tv_sec == fileBefore.st_mtimespec.tv_sec
            && fileAfter.st_mtimespec.tv_nsec == fileBefore.st_mtimespec.tv_nsec)
        #expect(dirAfter.st_mtimespec.tv_sec == dirBefore.st_mtimespec.tv_sec
            && dirAfter.st_mtimespec.tv_nsec == dirBefore.st_mtimespec.tv_nsec)
        #expect(index.rule(id: "rule.new", in: compiled)?["id"] as? String == "rule.new")
        #expect(index.rule(id: "rule.old", in: compiled) == nil)
    }

    @Test("a true miss rebuilds nothing, so it opens no rule file")
    func trueMissDoesNotRebuild() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.a", to: compiled + "/a.json")
        try write("user.u", to: user + "/u.json")
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.a", in: compiled) != nil)
        #expect(index.rebuildCount == 1)
        // Rule files are read only while building and when a cached entry is
        // used, and a miss has no entry.
        for _ in 0..<3 { #expect(index.rule(id: "rule.missing", in: compiled) == nil) }
        #expect(index.rule(id: "user.u", in: compiled) != nil)
        #expect(index.rebuildCount == 1)
    }

    @Test("an override made in place is shown for an id already resolved to its bundled rule")
    func inPlaceOverrideOfAResolvedID() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        try write("user.y", to: user + "/y.json", title: "user rule")
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "bundled")
        var before = stat()
        #expect(lstat(user, &before) == 0)
        // y.json is saved in place with the bundled rule's id, which the
        // engine then applies; user_rules' entries, mtime and ctime stay.
        try overwriteInPlace(user + "/y.json", with: ruleData("rule.x", title: "user override"))
        var after = stat()
        #expect(lstat(user, &after) == 0)
        #expect(after.st_mtimespec.tv_sec == before.st_mtimespec.tv_sec
            && after.st_mtimespec.tv_nsec == before.st_mtimespec.tv_nsec)
        #expect(after.st_ctimespec.tv_sec == before.st_ctimespec.tv_sec
            && after.st_ctimespec.tv_nsec == before.st_ctimespec.tv_nsec)
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "user override")
    }

    @Test("explain_alert shows a rule's description, status and logsource, not its matching logic, and points to maccrabctl why")
    func explainShowsTheDefinitionAndPointsToWhy() throws {
        // The fixture with each engine's logic added, and the Sigma `detection`
        // block the handler used to look for.
        var rule = try #require(JSONSerialization.jsonObject(with: ruleData("rule.x")) as? [String: Any])
        rule["condition_tree"] = ["type": "predicate", "index": 0]
        rule["steps"] = [["id": "install", "logsourceCategory": "process_creation"]]
        rule["nodes"] = ["shell": ["type": "process"]]
        rule["edges"] = [["from": "shell", "to": "shell", "relation": "spawned"]]
        rule["detection"] = ["selection": ["file.path|contains": "/maccrab-rule-index-fixture/"]]
        let alertID = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9f0a1b2c"
        let pointer = "  matching logic: run `maccrabctl why \(alertID)` on this Mac; it prints a single-event rule's "
            + "predicates and how they combine, a sequence rule's steps, or a graph rule's nodes and edges (long value "
            + "lists are shortened)."

        let lines = explainRuleDefinitionLines(rule, alertID: alertID, isUserRule: false, duplicateUserRules: false, disabledDuplicateUserRule: false, unreadableUserRules: false)
        #expect(lines == [
            "Rule definition:", "  description: rule index fixture", "  status: stable",
            "  logsource: category=file_event, product=macos", pointer,
        ])
        // No predicate value and no logic key reaches the text. The pointer
        // names predicates, steps, nodes and edges only as what `why` prints,
        // so the keys are looked for in the lines above it.
        let text = lines.joined(separator: "\n")
        #expect(!text.contains("/maccrab-rule-index-fixture/"))
        let definition = lines.dropLast().joined(separator: "\n")
        for key in ["predicates", "condition", "steps", "nodes", "edges", "detection"] {
            #expect(!definition.contains(key), "\(key)")
        }
        // The pointer survives the sanitizer every explain_alert response passes through.
        #expect(LLMSanitizer.sanitize(text).hasSuffix(pointer))

        let noted = explainRuleDefinitionLines(rule, alertID: alertID, isUserRule: false, duplicateUserRules: true, disabledDuplicateUserRule: false, unreadableUserRules: false)
        #expect(noted == Array(lines.prefix(1)) + [
            "  note: several user rules have this id. The engine applies one of them, in an order MacCrab does not "
                + "define; this is the first by file name.",
        ] + Array(lines.dropFirst()))

        // Part of user_rules this process cannot read gets one note, which
        // survives the sanitizer too.
        let unreadableNote = Self.unreadableNote(alertID)
        let unreadable = explainRuleDefinitionLines(rule, alertID: alertID, isUserRule: false, duplicateUserRules: false, disabledDuplicateUserRule: false, unreadableUserRules: true)
        #expect(unreadable == Array(lines.prefix(1)) + [unreadableNote] + Array(lines.dropFirst()))
        #expect(LLMSanitizer.sanitize(unreadable.joined(separator: "\n")).contains(unreadableNote))

        // With both, a file this process cannot read may hold another rule
        // with this id, and the engine may apply it.
        let bothNote = "  note: at least two user rules have this id. The engine applies one of them or one this "
            + "process cannot read, in an order MacCrab does not define; this is the first by file name of those "
            + "this process can read."
        let both = explainRuleDefinitionLines(rule, alertID: alertID, isUserRule: false, duplicateUserRules: true, disabledDuplicateUserRule: false, unreadableUserRules: true)
        #expect(both == Array(lines.prefix(1)) + [bothNote, unreadableNote] + Array(lines.dropFirst()))
        #expect(LLMSanitizer.sanitize(both.joined(separator: "\n")).contains(bothNote))

        // A user rule is marked as one. With "enabled": false, the engine
        // raises no alerts for the id while it applies the rule, which a note
        // saying it may apply another makes a condition. A bundled rule's
        // "enabled": false is not shown.
        func definitionLines(_ rule: [String: Any], isUserRule: Bool, duplicateUserRules: Bool = false,
                             disabledDuplicateUserRule: Bool = false, unreadableUserRules: Bool = false) -> [String] {
            explainRuleDefinitionLines(rule, alertID: alertID, isUserRule: isUserRule,
                                       duplicateUserRules: duplicateUserRules,
                                       disabledDuplicateUserRule: disabledDuplicateUserRule,
                                       unreadableUserRules: unreadableUserRules)
        }
        var disabled = rule
        disabled["enabled"] = false
        let fields = Array(lines.dropFirst())
        #expect(definitionLines(rule, isUserRule: true) == ["Rule definition:", Self.userSource] + fields)
        #expect(definitionLines(disabled, isUserRule: true) == ["Rule definition:", Self.userSource, Self.disabledApplied] + fields)
        #expect(definitionLines(disabled, isUserRule: true, duplicateUserRules: true)
            == Array(noted.prefix(2)) + [Self.userSource, Self.disabledIfApplied] + fields)
        #expect(definitionLines(disabled, isUserRule: true, unreadableUserRules: true)
            == Array(unreadable.prefix(2)) + [Self.userSource, Self.disabledIfApplied] + fields)
        #expect(definitionLines(disabled, isUserRule: true, duplicateUserRules: true, unreadableUserRules: true)
            == Array(both.prefix(3)) + [Self.userSource, Self.disabledIfApplied] + fields)
        #expect(definitionLines(disabled, isUserRule: false) == lines)

        // Another user rule with this id has "enabled": false. The engine may
        // apply it, so a note after the duplicate note says so as a
        // condition, whether or not the rule shown has it too and whether or
        // not part of user_rules is unreadable.
        #expect(definitionLines(rule, isUserRule: true, duplicateUserRules: true, disabledDuplicateUserRule: true)
            == Array(noted.prefix(2)) + [Self.otherDisabledNote, Self.userSource] + fields)
        #expect(definitionLines(disabled, isUserRule: true, duplicateUserRules: true, disabledDuplicateUserRule: true)
            == Array(noted.prefix(2)) + [Self.otherDisabledNote, Self.userSource, Self.disabledIfApplied] + fields)
        #expect(definitionLines(rule, isUserRule: true, duplicateUserRules: true, disabledDuplicateUserRule: true,
                                unreadableUserRules: true)
            == Array(both.prefix(2)) + [Self.otherDisabledNote, unreadableNote, Self.userSource] + fields)
        #expect(definitionLines(disabled, isUserRule: true, duplicateUserRules: true, disabledDuplicateUserRule: true,
                                unreadableUserRules: true)
            == Array(both.prefix(2)) + [Self.otherDisabledNote, unreadableNote, Self.userSource, Self.disabledIfApplied]
                + fields)
    }

    /// The lines explain_alert adds for a user rule, and for one with
    /// "enabled": false, said outright or as a condition.
    private static let userSource = "  source: user_rules"
    private static let disabledApplied =
        "  enabled: false (the engine raises no alerts for this id while it applies this rule)"
    private static let disabledIfApplied =
        "  enabled: false (if the engine applies this rule, it raises no alerts for this id)"

    /// The note explain_alert adds when several user rules have the id.
    private static let duplicateNote = "  note: several user rules have this id. The engine applies one of them, "
        + "in an order MacCrab does not define; this is the first by file name."

    /// The note explain_alert adds after that one when a user rule with the
    /// id other than the one shown has "enabled": false.
    private static let otherDisabledNote = "  note: another user rule with this id has \"enabled\": false; if the "
        + "engine applies that rule, it raises no alerts for this id."

    @Test("explain_alert's rule section marks a user rule and says when it, or another user rule with its id, has \"enabled\": false, and shows neither for a bundled rule")
    func sectionMarksUserRules() throws {
        let (root, compiled, user) = try supportDirectory()
        defer {
            chmod(user, 0o755)
            try? FileManager.default.removeItem(atPath: root)
        }
        try disabledRuleData("rule.x").write(to: URL(fileURLWithPath: compiled + "/x.json"))
        try disabledRuleData("rule.x").write(to: URL(fileURLWithPath: user + "/x.json"))
        try write("rule.y", to: compiled + "/y.json")
        try write("rule.y", to: user + "/y.json")
        let alertID = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9f0a1b32"
        let index = CompiledRuleFileIndex()
        // The section's lines before the rule's status.
        func head(_ id: String) -> [String] {
            Array(explainRuleSectionLines(ruleID: id, alertID: alertID, hasDetail: true, compiledDir: compiled, index: index)
                .prefix(while: { !$0.hasPrefix("  status: ") }))
        }
        let description = "  description: rule index fixture"
        #expect(head("rule.y") == ["Rule definition:", Self.userSource, description])
        #expect(head("rule.x") == ["Rule definition:", Self.userSource, Self.disabledApplied, description])
        // A second override with this id: the engine applies one of them.
        // x.json, the one shown, has "enabled": false; x2.json does not.
        try write("rule.x", to: user + "/x2.json")
        #expect(head("rule.x") == ["Rule definition:", Self.duplicateNote, Self.userSource, Self.disabledIfApplied, description])
        #expect(!index.hasDisabledDuplicateUserRule(id: "rule.x", in: compiled))
        // Both have it, then x2.json only, then neither.
        try disabledRuleData("rule.x").write(to: URL(fileURLWithPath: user + "/x2.json"))
        #expect(head("rule.x") == ["Rule definition:", Self.duplicateNote, Self.otherDisabledNote, Self.userSource,
                                   Self.disabledIfApplied, description])
        #expect(index.hasDisabledDuplicateUserRule(id: "rule.x", in: compiled))
        try write("rule.x", to: user + "/x.json")
        #expect(head("rule.x") == ["Rule definition:", Self.duplicateNote, Self.otherDisabledNote, Self.userSource, description])
        try write("rule.x", to: user + "/x2.json")
        #expect(head("rule.x") == ["Rule definition:", Self.duplicateNote, Self.userSource, description])
        #expect(!index.hasDisabledDuplicateUserRule(id: "rule.x", in: compiled))
        // A user_rules the engine does not trust: the bundled rule, whose
        // "enabled": false is not shown.
        #expect(chmod(user, 0o775) == 0)
        #expect(head("rule.x") == ["Rule definition:", description])
    }

    /// The note explain_alert adds when this process cannot read all of user_rules.
    private static func unreadableNote(_ alertID: String) -> String {
        "  note: this process cannot read all of user_rules (the folder cannot be listed or inspected, or a file in "
            + "it cannot be inspected or opened). The engine runs as root when installed, so it may apply a user "
            + "rule from there for this id instead of the rule shown; to check, run `sudo maccrabctl why \(alertID)` "
            + "on this Mac."
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

    // MacCrabCoreTests' UserRuleOverlayTrustParityTests runs these checks
    // against the engine's own gates.
    @Test("UserRuleOverlayTrust's folder and file decisions, and the index's calls to them")
    func trustMatchesTheEngine() {
        typealias Trust = UserRuleOverlayTrust
        #expect(Trust.trustsDirectory(owner: 0, mode: 0o40755, isSymlink: false, engineUID: 0))
        #expect(!Trust.trustsDirectory(owner: 0, mode: 0o40775, isSymlink: false, engineUID: 0))
        #expect(!Trust.trustsDirectory(owner: 0, mode: 0o40757, isSymlink: false, engineUID: 0))
        #expect(!Trust.trustsDirectory(owner: 501, mode: 0o40755, isSymlink: false, engineUID: 0))
        #expect(Trust.trustsDirectory(owner: 501, mode: 0o40755, isSymlink: false, engineUID: 501))
        #expect(Trust.trustsDirectory(owner: 0, mode: 0o40755, isSymlink: false, engineUID: 501))
        #expect(!Trust.trustsDirectory(owner: 0, mode: 0o120755, isSymlink: true, engineUID: 0))
        #expect(Trust.trustsFile(owner: 0, engineUID: 0))
        #expect(!Trust.trustsFile(owner: 501, engineUID: 0))
        #expect(Trust.engineUID(forSupportDirectory: "/Library/Application Support/MacCrab") == 0)
        #expect(Trust.engineUID(forSupportDirectory: NSTemporaryDirectory() + "x") == getuid())
        // Each user rule file is held to the engine's owner check while the
        // index is built and before a cached one is used.
        let source = (try? String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/maccrab-mcp/ReadParityTools.swift"), encoding: .utf8)) ?? ""
        #expect(source.contains(
            "for path in userFiles ?? [] {\n                guard UserRuleOverlayTrust.trustsFile(atPath: path, engineUID: engineUID) else {"))
        #expect(source.contains("UserRuleOverlayTrust.trustsFile(atPath: path, engineUID: engineUID) else { return nil }"))
    }

    @Test("on disk, a user rule file is trusted only for its owner's uid, and its folder only while no one else can write it")
    func trustReadsTheFolderAndFileWithLstat() throws {
        typealias Trust = UserRuleOverlayTrust
        let (root, _, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let file = user + "/u.json"
        try write("user.u", to: file)
        // A test cannot create a file another uid owns, so the engine's uid is
        // varied instead: an engine running as root does not load a file this
        // user wrote, as on a legacy install.
        let owner = getuid()
        let other: uid_t = owner == 0 ? 1 : 0
        #expect(Trust.trustsFile(atPath: file, engineUID: owner))
        #expect(!Trust.trustsFile(atPath: file, engineUID: other), "a file the engine's uid does not own")
        #expect(!Trust.trustsFile(atPath: user + "/missing.json", engineUID: owner))
        #expect(Trust.trustsDirectory(atPath: user, engineUID: owner))
        // The legacy root:admin 0775 folder, and a world-writable one.
        for mode: mode_t in [0o775, 0o757] {
            #expect(chmod(user, mode) == 0)
            #expect(!Trust.trustsDirectory(atPath: user, engineUID: owner), "mode \(String(mode, radix: 8))")
        }
        #expect(chmod(user, 0o755) == 0)
        #expect(Trust.trustsDirectory(atPath: user, engineUID: owner))
        try FileManager.default.createSymbolicLink(atPath: root + "/linked_rules", withDestinationPath: user)
        #expect(!Trust.trustsDirectory(atPath: root + "/linked_rules", engineUID: owner), "a symlinked folder")
        #expect(!Trust.trustsDirectory(atPath: file, engineUID: owner), "a file is not a folder")
    }

    @Test("a user rule hidden by the UF_HIDDEN flag is skipped, as the engine skips it")
    func hiddenFlagIsSkipped() async throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        try write("rule.x", to: user + "/a.json", title: "first")
        try write("rule.x", to: user + "/b.json", title: "second")
        #expect(try await RuleEngine().loadRules(from: URL(fileURLWithPath: user), requireOwnerUID: getuid()) == 2)
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "first")
        #expect(index.hasDuplicateUserRules(id: "rule.x", in: compiled))
        // chflags hidden sets the flag, and cp -p and ditto keep it on a copy.
        // The engine's .skipsHiddenFiles listing then leaves the file out.
        #expect(chflags(user + "/a.json", UInt32(UF_HIDDEN)) == 0)
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "second")
        #expect(!index.hasDuplicateUserRules(id: "rule.x", in: compiled))
        #expect(chflags(user + "/b.json", UInt32(UF_HIDDEN)) == 0)
        #expect(index.rule(id: "rule.x", in: compiled)?["title"] as? String == "bundled")
        #expect(try await RuleEngine().loadRules(from: URL(fileURLWithPath: user), requireOwnerUID: getuid()) == 0)
    }

    @Test("user rules this process cannot read are noted, not taken for rules the engine refuses",
          .enabled(if: geteuid() != 0, "root reads a mode-000 file, lists a mode-300 folder and is not held to an ACL entry"))
    func unreadableUserRulesAreNoted() throws {
        let (root, compiled, user) = try supportDirectory()
        defer {
            _ = try? chmodACL(["-N", user])
            _ = try? chmodACL(["-N", user + "/x.json"])
            chmod(user, 0o755)
            chmod(user + "/x.json", 0o644)
            try? FileManager.default.removeItem(atPath: root)
        }
        try FileManager.default.createDirectory(atPath: compiled + "/sequences", withIntermediateDirectories: true)
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        try write("seq.s", to: compiled + "/sequences/s.json", title: "sequence")
        try write("rule.x", to: user + "/x.json", title: "user override")
        let index = CompiledRuleFileIndex()
        func shown() -> String? { index.rule(id: "rule.x", in: compiled)?["title"] as? String }
        #expect(shown() == "user override")
        #expect(!index.hasUnreadableUserRules(id: "rule.x", in: compiled))

        // A file the engine's uid owns that this process may not open. An
        // engine running as root reads it, so the bundled rule shown may not be
        // the one it applies.
        #expect(chmod(user + "/x.json", 0o000) == 0)
        #expect(shown() == "bundled")
        #expect(index.hasUnreadableUserRules(id: "rule.x", in: compiled))
        // User rules do not replace a sequence rule, so its id gets no note.
        #expect(index.rule(id: "seq.s", in: compiled)?["title"] as? String == "sequence")
        #expect(!index.hasUnreadableUserRules(id: "seq.s", in: compiled))
        #expect(chmod(user + "/x.json", 0o644) == 0)
        #expect(shown() == "user override")
        #expect(!index.hasUnreadableUserRules(id: "rule.x", in: compiled))

        // A folder the engine trusts that this process cannot list. The first
        // lookup after the change is explain_alert's rule section, so the note
        // it adds comes from the build that lookup makes: present for the
        // single-event id, absent for the sequence id.
        #expect(chmod(user, 0o300) == 0)
        let alertID = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9f0a1b2d"
        func section(_ id: String) -> [String] {
            explainRuleSectionLines(ruleID: id, alertID: alertID, hasDetail: true, compiledDir: compiled, index: index)
        }
        #expect(Array(section("rule.x").prefix(2)) == ["Rule definition:", Self.unreadableNote(alertID)])
        #expect(section("seq.s").first == "Rule definition:")
        #expect(!section("seq.s").contains(Self.unreadableNote(alertID)))
        #expect(shown() == "bundled")
        #expect(index.hasUnreadableUserRules(id: "rule.x", in: compiled))
        #expect(chmod(user, 0o755) == 0)
        #expect(shown() == "user override")
        #expect(!index.hasUnreadableUserRules(id: "rule.x", in: compiled))

        // An ACL entry that denies this process readattr, on the file and then
        // on the folder: lstat fails, so this process cannot read the owner the
        // engine checks. An engine running as root is not held to the entry.
        let denyReadattr = "user:\(NSUserName()) deny readattr"
        #expect(try chmodACL(["+a", denyReadattr, user + "/x.json"]) == 0)
        #expect(shown() == "bundled")
        #expect(index.hasUnreadableUserRules(id: "rule.x", in: compiled))
        #expect(try chmodACL(["-N", user + "/x.json"]) == 0)
        #expect(shown() == "user override")
        #expect(!index.hasUnreadableUserRules(id: "rule.x", in: compiled))
        #expect(try chmodACL(["+a", denyReadattr, user]) == 0)
        #expect(shown() == "bundled")
        #expect(index.hasUnreadableUserRules(id: "rule.x", in: compiled))
        #expect(try chmodACL(["-N", user]) == 0)
        #expect(shown() == "user override")
        #expect(!index.hasUnreadableUserRules(id: "rule.x", in: compiled))

        // A user_rules that does not exist, the usual case, is not unreadable.
        try FileManager.default.removeItem(atPath: user)
        #expect(shown() == "bundled")
        #expect(!index.hasUnreadableUserRules(id: "rule.x", in: compiled))
    }

    @Test("a user_rules this process may not lstat is told from a missing one, though neither has lstat metadata",
          .enabled(if: geteuid() != 0, "root is not held to an ACL entry"))
    func refusedAndMissingUserRulesAreTold() throws {
        let (root, compiled, user) = try supportDirectory()
        defer {
            _ = try? chmodACL(["-N", user])
            try? FileManager.default.removeItem(atPath: root)
        }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        try write("rule.x", to: user + "/x.json", title: "user override")
        let denyReadattr = "user:\(NSUserName()) deny readattr"
        let alertID = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9f0a1b31"
        func noted(_ index: CompiledRuleFileIndex) -> Bool {
            explainRuleSectionLines(ruleID: "rule.x", alertID: alertID, hasDetail: true, compiledDir: compiled, index: index)
                .contains(Self.unreadableNote(alertID))
        }

        // Refused, then missing, with no lookup in between. Each transition
        // has an index of its own, built in the state before it.
        #expect(try chmodACL(["+a", denyReadattr, user]) == 0)
        #expect(UserRuleOverlayTrust.lstatIsRefused(atPath: user))
        let refusedFirst = CompiledRuleFileIndex()
        #expect(noted(refusedFirst))
        #expect(try chmodACL(["-N", user]) == 0)
        try FileManager.default.removeItem(atPath: user)
        #expect(!UserRuleOverlayTrust.lstatIsRefused(atPath: user))
        #expect(!noted(refusedFirst))
        #expect(refusedFirst.rebuildCount == 2)

        // Missing, then refused, with no lookup in between: the install
        // handler creates user_rules at 0755 and writes an override, and an
        // ACL entry then denies this process readattr.
        let missingFirst = CompiledRuleFileIndex()
        #expect(!noted(missingFirst))
        try FileManager.default.createDirectory(atPath: user, withIntermediateDirectories: false)
        #expect(chmod(user, 0o755) == 0)
        try write("rule.x", to: user + "/x.json", title: "user override")
        #expect(try chmodACL(["+a", denyReadattr, user]) == 0)
        #expect(UserRuleOverlayTrust.lstatIsRefused(atPath: user))
        #expect(noted(missingFirst))
        #expect(missingFirst.rebuildCount == 2)
    }

    @Test("an id the index maps no file to gets lines saying no rule file was found and built-in detectors have none, with no note while user_rules is readable")
    func idWithoutRuleFile() throws {
        let (root, compiled, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        try write("rule.x", to: user + "/x.json", title: "user override")
        // A user rule this process can read but the engine would not load,
        // because it does not decode.
        try JSONSerialization.data(withJSONObject: ["id": "user.refused", "title": "refused rule"])
            .write(to: URL(fileURLWithPath: user + "/y.json"))
        let alertID = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9f0a1b2f"
        let index = CompiledRuleFileIndex()
        for id in ["baseline-anomaly", "user.refused"] {
            for hasDetail in [true, false] {
                #expect(explainRuleSectionLines(ruleID: id, alertID: alertID, hasDetail: hasDetail,
                                                compiledDir: compiled, index: index)
                    == Self.noRuleFileLines(id, hasDetail: hasDetail), "\(id), detail: \(hasDetail)")
            }
        }
    }

    @Test("an id the index maps no file to also gets a note when the index's last build could not read all of user_rules",
          .enabled(if: geteuid() != 0, "root lists a mode-300 folder"))
    func idWithoutRuleFileAndUnreadableUserRules() throws {
        let (root, compiled, user) = try supportDirectory()
        defer {
            chmod(user, 0o755)
            try? FileManager.default.removeItem(atPath: root)
        }
        try write("rule.x", to: compiled + "/x.json", title: "bundled")
        try write("rule.x", to: user + "/x.json", title: "user override")
        // A folder the engine trusts that this process cannot list, from
        // before the index's first lookup, so the note comes from the build
        // that lookup makes.
        #expect(chmod(user, 0o300) == 0)
        let alertID = "6f1c2b3a-0d4e-4f5a-8b6c-7d8e9f0a1b30"
        let index = CompiledRuleFileIndex()
        func section() -> [String] {
            explainRuleSectionLines(ruleID: "baseline-anomaly", alertID: alertID, hasDetail: true,
                                    compiledDir: compiled, index: index)
        }
        let notFound = Self.noRuleFileLines("baseline-anomaly", hasDetail: true)
        #expect(section() == notFound + [Self.unreadableNotFoundNote(alertID)])
        #expect(chmod(user, 0o755) == 0)
        #expect(section() == notFound)
    }

    /// What explain_alert prints for an id the rule index maps no file to.
    private static func noRuleFileLines(_ ruleID: String, hasDetail: Bool) -> [String] {
        [
            "This process found no rule file with the id \(ruleID) in compiled_rules or among the user rules the "
                + "engine would load.",
            hasDetail
                ? "Built-in detectors, such as the process-lineage baseline (baseline-anomaly), have no rule file; "
                    + "for their alerts, the detail above is what was captured."
                : "Built-in detectors, such as the process-lineage baseline (baseline-anomaly), have no rule file.",
        ]
    }

    /// The note explain_alert adds after those lines when this process
    /// cannot read all of user_rules.
    private static func unreadableNotFoundNote(_ alertID: String) -> String {
        "Note: this process cannot read all of user_rules (the folder cannot be listed or inspected, or a file in it "
            + "cannot be inspected or opened). The engine runs as root when installed, so this alert's rule may be a "
            + "user rule there; to check, run `sudo maccrabctl why \(alertID)` on this Mac."
    }
}
