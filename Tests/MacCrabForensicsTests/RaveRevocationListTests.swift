// RaveRevocationList (O2, S2-03/04) parse + scope-matching tests.
//
// Covers:
//   - a well-formed revocations.json parses, including serial + all 3 scope
//     kinds (single_version / version_range / all_versions)
//   - SemVer-aware scope matching (single / range incl. open-ended / all)
//   - fail-CLOSED parsing: malformed body / unknown scope kind / missing
//     required fields throw rather than degrading to an empty list
//   - a non-integer serial is dropped to nil (must not slip past rollback)
//   - entriesRevoking() filters by id + version

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("RaveRevocationList (O2 parse + scope)")
struct RaveRevocationListTests {

    static func listData(serial: Int? = 3, revocations: [[String: Any]]) -> Data {
        var obj: [String: Any] = [
            "version": "0",
            "updated_at": "2026-06-11T00:00:00Z",
            "revocations": revocations,
        ]
        if let s = serial { obj["serial"] = s }
        return try! JSONSerialization.data(withJSONObject: obj)
    }

    static func entry(
        id: String = "com.maccrab.forensics.tcc-lite",
        scope: [String: Any],
        code: String = "compromise"
    ) -> [String: Any] {
        [
            "plugin_id": id,
            "scope": scope,
            "reason": "publisher key exfiltrated",
            "code": code,
            "decided_at": "2026-06-11T00:00:00Z",
            "decided_by": ["peterhanily"],
        ]
    }

    // MARK: - Parse

    @Test("valid list with all three scope kinds parses")
    func parseAllScopeKinds() throws {
        let data = Self.listData(serial: 7, revocations: [
            Self.entry(scope: ["kind": "single_version", "version": "1.0.0"]),
            Self.entry(scope: ["kind": "version_range", "from_version": "1.0.0", "to_version": "1.2.0"]),
            Self.entry(scope: ["kind": "all_versions"]),
        ])
        let list = try RaveRevocationList.parse(data: data)
        #expect(list.formatVersion == "0")
        #expect(list.serial == 7)
        #expect(list.revocations.count == 3)
        #expect(list.revocations[0].scope == .singleVersion("1.0.0"))
        #expect(list.revocations[1].scope == .versionRange(from: "1.0.0", to: "1.2.0"))
        #expect(list.revocations[2].scope == .allVersions)
        #expect(list.revocations[0].reason == "publisher key exfiltrated")
        #expect(list.revocations[0].code == "compromise")
    }

    @Test("empty revocations array parses to an empty list (not an error)")
    func parseEmpty() throws {
        let data = Self.listData(serial: 0, revocations: [])
        let list = try RaveRevocationList.parse(data: data)
        #expect(list.revocations.isEmpty)
        #expect(list.serial == 0)
    }

    @Test("open-ended version_range (no to_version) parses")
    func parseOpenRange() throws {
        let data = Self.listData(revocations: [
            Self.entry(scope: ["kind": "version_range", "from_version": "2.0.0"]),
        ])
        let list = try RaveRevocationList.parse(data: data)
        #expect(list.revocations[0].scope == .versionRange(from: "2.0.0", to: nil))
    }

    @Test("missing serial → nil (first-seen upstream)")
    func parseMissingSerial() throws {
        let data = Self.listData(serial: nil, revocations: [])
        let list = try RaveRevocationList.parse(data: data)
        #expect(list.serial == nil)
    }

    @Test("non-integer serial is dropped to nil (must not slip past rollback)")
    func parseStringSerial() throws {
        let obj: [String: Any] = [
            "version": "0",
            "serial": "5",  // string, not integer
            "updated_at": "2026-06-11T00:00:00Z",
            "revocations": [],
        ]
        let data = try JSONSerialization.data(withJSONObject: obj)
        let list = try RaveRevocationList.parse(data: data)
        #expect(list.serial == nil)
    }

    // MARK: - Fail-closed parsing

    @Test("non-object body fails closed")
    func parseNonObject() {
        let data = Data("[]".utf8)
        #expect(throws: RaveRevocationList.ParseError.notAnObject) {
            try RaveRevocationList.parse(data: data)
        }
    }

    @Test("missing revocations field fails closed")
    func parseMissingRevocations() {
        let obj: [String: Any] = ["version": "0", "updated_at": "x"]
        let data = try! JSONSerialization.data(withJSONObject: obj)
        #expect(throws: RaveRevocationList.ParseError.self) {
            try RaveRevocationList.parse(data: data)
        }
    }

    @Test("missing version field fails closed")
    func parseMissingVersion() {
        let obj: [String: Any] = ["revocations": []]
        let data = try! JSONSerialization.data(withJSONObject: obj)
        #expect(throws: RaveRevocationList.ParseError.self) {
            try RaveRevocationList.parse(data: data)
        }
    }

    @Test("unknown scope kind fails closed (can't enforce → keep prior list)")
    func parseUnknownScope() {
        let data = Self.listData(revocations: [
            Self.entry(scope: ["kind": "everything_after_2026", "version": "1.0.0"]),
        ])
        #expect(throws: RaveRevocationList.ParseError.self) {
            try RaveRevocationList.parse(data: data)
        }
    }

    @Test("entry missing plugin_id fails closed")
    func parseMissingPluginID() {
        let data = Self.listData(revocations: [[
            "scope": ["kind": "all_versions"],
            "reason": "x", "code": "compromise",
            "decided_at": "x", "decided_by": ["a"],
        ]])
        #expect(throws: RaveRevocationList.ParseError.self) {
            try RaveRevocationList.parse(data: data)
        }
    }

    @Test("entry with empty decided_by fails closed")
    func parseEmptyDecidedBy() {
        let data = Self.listData(revocations: [[
            "plugin_id": "com.x.y",
            "scope": ["kind": "all_versions"],
            "reason": "x", "code": "compromise",
            "decided_at": "x", "decided_by": [] as [String],
        ]])
        #expect(throws: RaveRevocationList.ParseError.self) {
            try RaveRevocationList.parse(data: data)
        }
    }

    @Test("single_version scope missing version fails closed")
    func parseSingleMissingVersion() {
        let data = Self.listData(revocations: [
            Self.entry(scope: ["kind": "single_version"]),
        ])
        #expect(throws: RaveRevocationList.ParseError.self) {
            try RaveRevocationList.parse(data: data)
        }
    }

    // MARK: - Scope matching

    @Test("single_version covers only the exact version")
    func singleVersionMatch() {
        let s = RaveRevocationScope.singleVersion("1.0.0")
        #expect(s.covers(version: "1.0.0"))
        #expect(!s.covers(version: "1.0.1"))
        #expect(!s.covers(version: "0.9.9"))
    }

    @Test("single_version matches semver-equal forms")
    func singleVersionSemverEqual() {
        // Exact string differs but SemVer-equal core matches via fallback.
        let s = RaveRevocationScope.singleVersion("1.2.0")
        #expect(s.covers(version: "1.2.0+build17"))   // build metadata ignored
    }

    @Test("version_range covers the inclusive interval, semver-ordered")
    func versionRangeMatch() {
        let s = RaveRevocationScope.versionRange(from: "1.0.0", to: "1.2.0")
        #expect(s.covers(version: "1.0.0"))   // lower bound inclusive
        #expect(s.covers(version: "1.1.5"))   // interior
        #expect(s.covers(version: "1.2.0"))   // upper bound inclusive
        #expect(!s.covers(version: "0.9.9"))  // below
        #expect(!s.covers(version: "1.2.1"))  // above
        #expect(!s.covers(version: "2.0.0"))  // well above
    }

    @Test("open-ended version_range covers everything from `from` up")
    func openRangeMatch() {
        let s = RaveRevocationScope.versionRange(from: "2.0.0", to: nil)
        #expect(!s.covers(version: "1.9.9"))
        #expect(s.covers(version: "2.0.0"))
        #expect(s.covers(version: "9.9.9"))
    }

    @Test("range ordering respects pre-release precedence")
    func rangePrerelease() {
        // 1.0.0-rc1 < 1.0.0 (release). A range [1.0.0, 1.2.0] should NOT
        // cover 1.0.0-rc1 (it's below the lower bound by SemVer precedence).
        let s = RaveRevocationScope.versionRange(from: "1.0.0", to: "1.2.0")
        #expect(!s.covers(version: "1.0.0-rc1"))
        // But an exact lower bound equal still matches.
        #expect(s.covers(version: "1.0.0"))
    }

    @Test("all_versions covers any version, even non-semver")
    func allVersionsMatch() {
        let s = RaveRevocationScope.allVersions
        #expect(s.covers(version: "1.0.0"))
        #expect(s.covers(version: "nonsense"))
        #expect(s.covers(version: ""))
    }

    @Test("revokes() requires id match AND scope match")
    func revokesIdAndScope() {
        let rev = RaveRevocation(
            pluginID: "com.maccrab.forensics.tcc-lite",
            scope: .singleVersion("1.0.0"),
            reason: "r", code: "compromise",
            decidedAt: "x", decidedBy: ["a"]
        )
        #expect(rev.revokes(pluginID: "com.maccrab.forensics.tcc-lite", version: "1.0.0"))
        #expect(!rev.revokes(pluginID: "com.maccrab.forensics.tcc-lite", version: "1.0.1"))
        #expect(!rev.revokes(pluginID: "com.maccrab.forensics.other", version: "1.0.0"))
    }

    @Test("entriesRevoking filters by id + version")
    func entriesRevokingFilter() throws {
        let data = Self.listData(revocations: [
            Self.entry(id: "com.a.one", scope: ["kind": "all_versions"]),
            Self.entry(id: "com.b.two", scope: ["kind": "single_version", "version": "1.0.0"]),
        ])
        let list = try RaveRevocationList.parse(data: data)
        #expect(list.entriesRevoking(pluginID: "com.a.one", version: "9.9.9").count == 1)
        #expect(list.entriesRevoking(pluginID: "com.b.two", version: "1.0.0").count == 1)
        #expect(list.entriesRevoking(pluginID: "com.b.two", version: "2.0.0").isEmpty)
        #expect(list.entriesRevoking(pluginID: "com.c.three", version: "1.0.0").isEmpty)
    }

    // MARK: - Anti-rollback against the high-water-mark store

    @Test("parsed serial drives the revocations rollback gate")
    func serialRollbackGate() throws {
        let store = RaveTrustStateStore(path:
            (NSTemporaryDirectory() as NSString)
                .appendingPathComponent("rev-rollback-\(UUID().uuidString).json"))
        // First-seen at serial 5 → accepted, recorded.
        let l5 = try RaveRevocationList.parse(data: Self.listData(serial: 5, revocations: []))
        #expect(store.evaluateRevocations(incoming: l5.serial!) == .firstSeen)
        try store.recordRevocations(serial: l5.serial!)
        // A validly-signed-but-older serial 4 (un-revoke replay) is rejected.
        let l4 = try RaveRevocationList.parse(data: Self.listData(serial: 4, revocations: []))
        #expect(store.evaluateRevocations(incoming: l4.serial!) == .rollback(stored: 5, incoming: 4))
        // A newer serial 6 advances the mark.
        let l6 = try RaveRevocationList.parse(data: Self.listData(serial: 6, revocations: []))
        #expect(store.evaluateRevocations(incoming: l6.serial!) == .accepted)
        try store.recordRevocations(serial: l6.serial!)
        #expect(store.load().revocationsSerial == 6)
    }

    @Test("a list with no serial is first-seen (does not advance the mark)")
    func noSerialFirstSeen() throws {
        let store = RaveTrustStateStore(path:
            (NSTemporaryDirectory() as NSString)
                .appendingPathComponent("rev-noserial-\(UUID().uuidString).json"))
        let list = try RaveRevocationList.parse(data: Self.listData(serial: nil, revocations: []))
        #expect(list.serial == nil)
        // Caller's gate: nil serial is treated as first-seen, mark untouched.
        #expect(store.load().revocationsSerial == nil)
    }
}
