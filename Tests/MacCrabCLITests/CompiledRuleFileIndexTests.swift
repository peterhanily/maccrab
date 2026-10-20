import Foundation
import Testing
@testable import maccrab_mcp

/// get_alert_detail finds a compiled rule by id without reopening the corpus
/// for every lookup, including lookups for ids the corpus no longer has.
@Suite("Compiled rule index")
struct CompiledRuleFileIndexTests {
    private func write(_ id: String, to path: String) throws {
        let json = try JSONSerialization.data(withJSONObject: ["id": id, "title": id])
        try json.write(to: URL(fileURLWithPath: path))
    }

    @Test("rules and sequence rules resolve; an unknown id does not rebuild until the rules change")
    func lookups() throws {
        let dir = NSTemporaryDirectory() + "maccrab-rule-index-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir + "/sequences", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        try write("rule.a", to: dir + "/a.json")
        try write("seq.b", to: dir + "/sequences/b.json")
        let index = CompiledRuleFileIndex()
        #expect(index.rule(id: "rule.a", in: dir)?["id"] as? String == "rule.a")
        #expect(index.rule(id: "seq.b", in: dir)?["id"] as? String == "seq.b")

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
}
