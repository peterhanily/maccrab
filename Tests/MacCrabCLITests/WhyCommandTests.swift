// WhyCommandTests.swift
// MacCrabCLITests
//
// `maccrabctl why`: the rule lookup reads the top level of user_rules before
// compiled_rules and its sequences/ and graph/ folders, sequence and graph
// rules are rendered, and a single-event rule shows its predicates and then
// its condition tree or flat condition.
// The fixtures are real compiled rules: the kill-chain sequence
// supply_chain_full_kill_chain.yml run through Compiler/compile_rules.py, a
// rule from Rules/graph, and the compiled single-event rules ssh_key_access.yml,
// sudoers_modification.yml and c2_azurestaticprovider_net.yml.

import Foundation
import MacCrabCore
import Testing
@testable import maccrabctl

@Suite("maccrabctl: why rule lookup and rendering")
struct WhyCommandTests {

    @Test("the lookup reads user_rules first, then compiled_rules and its sequences/ and graph/ folders, and finds nothing for an unknown id")
    func ruleLookup() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-why-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let rules = dir.appendingPathComponent("compiled_rules")
        let users = dir.appendingPathComponent("user_rules")

        func write(_ json: String, _ folder: URL, _ name: String) throws -> String {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            // As installed: the daemon refuses a group-writable user_rules,
            // which a umask of 002 would leave.
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
            let path = folder.appendingPathComponent(name).path
            try json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let single = try write(Self.flatRule, rules, "ssh_key_access.json")
        let sequence = try write(Self.sequenceRule, rules.appendingPathComponent("sequences"), "supply_chain_full_kill_chain.json")
        let graph = try write(Self.graphRule, rules.appendingPathComponent("graph"), "maccrab_agent_associated_shell_writes_to_login_item.json")
        // A support dir that does not exist is skipped.
        let dirs = MacCrabCtl.whySearchDirs(supportDirs: [dir.appendingPathComponent("missing").path, dir.path])
        #expect(Array(dirs.suffix(4)) == [users.path, rules.path, rules.path + "/sequences", rules.path + "/graph"])

        func lookup(_ id: String) -> String? { MacCrabCtl.findRuleFile(forRuleID: id, in: dirs) }

        #expect(lookup("d1a2b3c4-0032-4000-a000-000000000032") == single)
        #expect(lookup("e1f2a3b4-0023-4000-b000-000000000023") == sequence)
        #expect(lookup("maccrab_agent_associated_shell_writes_to_login_item") == graph)
        // Built-in detectors raise alerts under ids that have no rule file.
        #expect(lookup("baseline-anomaly") == nil)

        // A user rule (dashboard-authored, or an override of a bundled rule)
        // is found before the compiled rule with the same id.
        let override = try write(Self.flatRule, users, "ssh_key_access.json")
        #expect(lookup("d1a2b3c4-0032-4000-a000-000000000032") == override)
        // Like the daemon, only the top level of user_rules is read.
        _ = try write(Self.sequenceRule, users.appendingPathComponent("sequences"), "supply_chain_full_kill_chain.json")
        #expect(lookup("e1f2a3b4-0023-4000-b000-000000000023") == sequence)
    }

    @Test("user rules the daemon would not load are skipped; a user rule never stands in for a sequence or graph rule")
    func userRulesFollowTheDaemonsLoadCheck() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-why-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let rules = dir.appendingPathComponent("compiled_rules")
        let users = dir.appendingPathComponent("user_rules")
        func write(_ json: String, _ folder: URL, _ name: String) throws -> String {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            // As installed: the daemon refuses a group-writable user_rules,
            // which a umask of 002 would leave.
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
            let path = folder.appendingPathComponent(name).path
            try json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        func variant(_ change: (inout [String: Any]) -> Void) throws -> String {
            var object = try #require(JSONSerialization.jsonObject(with: Data(Self.flatRule.utf8)) as? [String: Any])
            change(&object)
            return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
        }
        let single = try write(Self.flatRule, rules, "ssh_key_access.json")
        let sequence = try write(Self.sequenceRule, rules.appendingPathComponent("sequences"), "supply_chain_full_kill_chain.json")
        let graph = try write(Self.graphRule, rules.appendingPathComponent("graph"), "maccrab_agent_associated_shell_writes_to_login_item.json")
        let dirs = MacCrabCtl.whySearchDirs(supportDirs: [dir.path])
        func lookup(_ id: String) -> String? { MacCrabCtl.findRuleFile(forRuleID: id, in: dirs) }
        let singleID = "d1a2b3c4-0032-4000-a000-000000000032"

        // Same id, but the tree names predicate 99 of 4: the daemon refuses it.
        _ = try write(try variant { $0["condition_tree"] = ["type": "predicate", "index": 99] }, users, "ssh_key_access.json")
        // A hidden copy and a symlinked copy of a valid override are not loaded either.
        _ = try write(Self.flatRule, users, ".hidden.json")
        let outside = try write(Self.flatRule, dir, "outside.json")
        try FileManager.default.createSymbolicLink(atPath: users.appendingPathComponent("linked.json").path,
                                                   withDestinationPath: outside)
        #expect(lookup(singleID) == single)
        #expect(MacCrabCtl.loadableUserRuleFiles(forRuleID: singleID, inUserRules: users.path).paths.isEmpty)

        // A loadable user rule with a sequence or graph rule's id does not replace it.
        _ = try write(try variant { $0["id"] = "e1f2a3b4-0023-4000-b000-000000000023" }, users, "seq.json")
        _ = try write(try variant { $0["id"] = "maccrab_agent_associated_shell_writes_to_login_item" }, users, "graph.json")
        #expect(lookup("e1f2a3b4-0023-4000-b000-000000000023") == sequence)
        #expect(lookup("maccrab_agent_associated_shell_writes_to_login_item") == graph)

        // Two loadable overrides: the first by name is shown, and both are listed.
        let first = try write(Self.flatRule, users, "a-override.json")
        let second = try write(Self.flatRule, users, "b-override.json")
        #expect(lookup(singleID) == first)
        #expect(MacCrabCtl.loadableUserRuleFiles(forRuleID: singleID, inUserRules: users.path).paths == [first, second])
    }

    @Test("user rules count only from a folder the daemon trusts, and the duplicate count holds only files it would load")
    func userRulesFollowTheDaemonsTrustChecks() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-why-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let rules = dir.appendingPathComponent("compiled_rules")
        let users = dir.appendingPathComponent("user_rules")
        func write(_ json: String, _ folder: URL, _ name: String) throws -> String {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
            let path = folder.appendingPathComponent(name).path
            try json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let single = try write(Self.flatRule, rules, "ssh_key_access.json")
        let singleID = "d1a2b3c4-0032-4000-a000-000000000032"
        let dirs = MacCrabCtl.whySearchDirs(supportDirs: [dir.path])
        func lookup() -> String? { MacCrabCtl.findRuleFile(forRuleID: singleID, in: dirs) }
        // What the duplicate note counts.
        func claims() -> [String] { MacCrabCtl.loadableUserRuleFiles(forRuleID: singleID, inUserRules: users.path).paths }

        let first = try write(Self.flatRule, users, "a.json")
        let second = try write(Self.flatRule, users, "b.json")
        // Copies the daemon does not load: hidden by a leading dot or by the
        // UF_HIDDEN flag (chflags hidden, or a copy made with cp -p or ditto),
        // the build manifest, and a link to a valid copy.
        _ = try write(Self.flatRule, users, ".c.json")
        let flagged = try write(Self.flatRule, users, "d.json")
        #expect(chflags(flagged, UInt32(UF_HIDDEN)) == 0)
        _ = try write(Self.flatRule, users, "manifest.json")
        let outside = try write(Self.flatRule, dir, "outside.json")
        try FileManager.default.createSymbolicLink(atPath: users.appendingPathComponent("e.json").path,
                                                   withDestinationPath: outside)
        #expect(claims() == [first, second])
        #expect(lookup() == first)

        // Files the daemon's uid does not own are skipped. A test cannot create
        // a file another uid owns, so the daemon's uid is varied instead: an
        // engine running as root, as on an installed Mac, loads neither file.
        let owner = getuid()
        #expect(MacCrabCtl.loadableUserRuleFiles(
            forRuleID: singleID, inTrustedUserRules: users.path, engineUID: owner).paths == [first, second])
        #expect(MacCrabCtl.loadableUserRuleFiles(
            forRuleID: singleID, inTrustedUserRules: users.path, engineUID: owner == 0 ? 1 : 0).paths.isEmpty)

        // The legacy root:admin 0775 folder, or a world-writable one: the
        // daemon refuses the whole overlay and applies the bundled rule.
        for mode in [0o775, 0o757] {
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: users.path)
            #expect(claims().isEmpty, "mode \(String(mode, radix: 8))")
            #expect(lookup() == single, "mode \(String(mode, radix: 8))")
        }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: users.path)
        #expect(lookup() == first)
    }

    @Test("a readable user rule the daemon refuses, with an id no bundled rule has, is not found, and the not-found lines have no note")
    func refusedUserRuleIsNotFound() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-why-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let rules = dir.appendingPathComponent("compiled_rules")
        let users = dir.appendingPathComponent("user_rules")
        func write(_ json: String, _ folder: URL, _ name: String) throws -> String {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
            let path = folder.appendingPathComponent(name).path
            try json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        _ = try write(Self.flatRule, rules, "ssh_key_access.json")
        let customID = "d1a2b3c4-0032-4000-a000-0000000000fd"
        let custom = Self.flatRule.replacingOccurrences(of: "d1a2b3c4-0032-4000-a000-000000000032", with: customID)
        let alertID = "00000000-0000-0000-0000-000000000040"
        let dirs = MacCrabCtl.whySearchDirs(supportDirs: [dir.path])
        func lookup() -> String? { MacCrabCtl.findRuleFile(forRuleID: customID, in: dirs) }
        func notFound() -> [String] {
            MacCrabCtl.whyNoRuleFileLines(forRuleID: customID, in: dirs, hasDescription: false, alertID: alertID)
        }
        let lines = [
            "No rule file with the id \(customID) was found in compiled_rules or among the user rules the daemon would load.",
            "Built-in detectors have no rule file.",
        ]

        // The custom rule with a tree that names predicate 99 of 4: this user
        // can read it, and the daemon refuses its content.
        var invalid = try #require(JSONSerialization.jsonObject(with: Data(custom.utf8)) as? [String: Any])
        invalid["condition_tree"] = ["type": "predicate", "index": 99]
        let path = try write(String(decoding: try JSONSerialization.data(withJSONObject: invalid), as: UTF8.self),
                             users, "custom.json")
        #expect(FileManager.default.isReadableFile(atPath: path))
        #expect(lookup() == nil)
        #expect(notFound() == lines)

        // The rule without that tree is found, but not from a folder at 0775,
        // the mode of the legacy root:admin user_rules: the daemon refuses a
        // group-writable folder as a whole.
        _ = try write(custom, users, "custom.json")
        #expect(lookup() == path)
        try FileManager.default.setAttributes([.posixPermissions: 0o775], ofItemAtPath: users.path)
        #expect(FileManager.default.isReadableFile(atPath: path))
        #expect(lookup() == nil)
        #expect(notFound() == lines)
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

    @Test("user rules this user cannot read are reported, not taken for rules the daemon refuses",
          .enabled(if: geteuid() != 0, "root reads a mode-000 file, lists a mode-300 folder and is not held to an ACL entry"))
    func unreadableUserRules() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-why-\(UUID().uuidString)", isDirectory: true)
        let rules = dir.appendingPathComponent("compiled_rules")
        let users = dir.appendingPathComponent("user_rules")
        let override = users.appendingPathComponent("a.json").path
        defer {
            _ = try? chmodACL(["-N", users.path])
            _ = try? chmodACL(["-N", override])
            chmod(users.path, 0o755)
            chmod(override, 0o644)
            try? FileManager.default.removeItem(at: dir)
        }
        func write(_ json: String, _ folder: URL, _ name: String) throws -> String {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
            let path = folder.appendingPathComponent(name).path
            try json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let single = try write(Self.flatRule, rules, "ssh_key_access.json")
        let sequence = try write(Self.sequenceRule, rules.appendingPathComponent("sequences"), "supply_chain_full_kill_chain.json")
        _ = try write(Self.flatRule, users, "a.json")
        let singleID = "d1a2b3c4-0032-4000-a000-000000000032"
        let alertID = "00000000-0000-0000-0000-00000000003f"
        let dirs = MacCrabCtl.whySearchDirs(supportDirs: [dir.path])
        func lookup() -> String? { MacCrabCtl.findRuleFile(forRuleID: singleID, in: dirs) }
        func scan() -> (paths: [String], disabled: [String], unreadable: Bool) {
            MacCrabCtl.loadableUserRuleFiles(forRuleID: singleID, inUserRules: users.path)
        }
        #expect(lookup() == override)
        #expect(scan().paths == [override])
        #expect(!scan().unreadable)

        // A file the daemon's uid owns that this user may not open. A daemon
        // running as root reads it, so the bundled rule shown may not be the
        // one it applies.
        #expect(chmod(override, 0o000) == 0)
        #expect(lookup() == single)
        #expect(scan().paths.isEmpty)
        #expect(scan().unreadable)
        // The same file for a daemon uid that does not own it is one the
        // daemon refuses, so nothing is unreadable.
        let otherUID: uid_t = getuid() == 0 ? 1 : 0
        #expect(!MacCrabCtl.loadableUserRuleFiles(
            forRuleID: singleID, inTrustedUserRules: users.path, engineUID: otherUID).unreadable)
        #expect(chmod(override, 0o644) == 0)
        #expect(lookup() == override)
        #expect(!scan().unreadable)

        // A folder the daemon trusts, owned by its uid and writable by no one
        // else, that this user cannot list.
        #expect(chmod(users.path, 0o300) == 0)
        #expect(UserRuleOverlayTrust.trustsDirectory(atPath: users.path, engineUID: getuid()))
        #expect(lookup() == single)
        #expect(scan().paths.isEmpty)
        #expect(scan().unreadable)
        // The notes runWhy prints after the bundled rule are the unreadable
        // note alone. A user rule does not replace a sequence rule, so one
        // gets no note, though user_rules is just as unreadable.
        let singleJSON = try #require(JSONSerialization.jsonObject(with: Data(Self.flatRule.utf8)) as? [String: Any])
        let sequenceJSON = try #require(JSONSerialization.jsonObject(with: Data(Self.sequenceRule.utf8)) as? [String: Any])
        #expect(MacCrabCtl.whyFoundRuleNoteLines(ruleID: singleID, rulePath: single, rule: singleJSON, alertID: alertID)
            == Self.unreadableNote(alertID))
        #expect(MacCrabCtl.whyFoundRuleNoteLines(
            ruleID: "e1f2a3b4-0023-4000-b000-000000000023", rulePath: sequence, rule: sequenceJSON, alertID: alertID).isEmpty)
        #expect(chmod(users.path, 0o755) == 0)
        #expect(lookup() == override)
        #expect(!scan().unreadable)

        // An ACL entry that denies this user readattr, on the file and then on
        // the folder: lstat fails, so this user cannot read the owner the
        // daemon checks. A daemon running as root is not held to the entry.
        let denyReadattr = "user:\(NSUserName()) deny readattr"
        #expect(try chmodACL(["+a", denyReadattr, override]) == 0)
        #expect(UserRuleOverlayTrust.lstatIsRefused(atPath: override))
        #expect(lookup() == single)
        #expect(scan().paths.isEmpty)
        #expect(scan().unreadable)
        #expect(try chmodACL(["-N", override]) == 0)
        #expect(lookup() == override)
        #expect(!scan().unreadable)
        #expect(try chmodACL(["+a", denyReadattr, users.path]) == 0)
        #expect(UserRuleOverlayTrust.lstatIsRefused(atPath: users.path))
        #expect(lookup() == single)
        #expect(scan().paths.isEmpty)
        #expect(scan().unreadable)
        #expect(try chmodACL(["-N", users.path]) == 0)
        #expect(lookup() == override)
        #expect(!scan().unreadable)
        // A user_rules that does not exist, the usual case, is not unreadable.
        let missing = dir.appendingPathComponent("missing/user_rules").path
        #expect(!UserRuleOverlayTrust.lstatIsRefused(atPath: missing))
        #expect(!MacCrabCtl.loadableUserRuleFiles(forRuleID: singleID, inUserRules: missing).unreadable)

        // A rule only user_rules has. When this user cannot list the folder,
        // no rule file is found, and the note says the daemon may load it.
        let newID = "d1a2b3c4-0032-4000-a000-0000000000ff"
        let newRule = try write(Self.flatRule.replacingOccurrences(of: singleID, with: newID), users, "b.json")
        func notFound(_ ruleID: String, hasDescription: Bool = false) -> [String] {
            MacCrabCtl.whyNoRuleFileLines(forRuleID: ruleID, in: dirs, hasDescription: hasDescription, alertID: alertID)
        }
        #expect(MacCrabCtl.findRuleFile(forRuleID: newID, in: dirs) == newRule)
        #expect(chmod(users.path, 0o300) == 0)
        #expect(MacCrabCtl.findRuleFile(forRuleID: newID, in: dirs) == nil)
        #expect(notFound(newID) == [
            "No rule file with the id \(newID) was found in compiled_rules or among the user rules the daemon would load.",
            "Built-in detectors have no rule file.",
            "Note: this user cannot read all of user_rules (the folder cannot be listed or inspected, or",
            "a file in it cannot be inspected or opened). The daemon runs as root when installed, so",
            "this alert's rule may be a user rule there. To check, run",
            "`sudo maccrabctl why \(alertID)`.",
        ])
        // For an alert with a description, the second line points to it.
        #expect(notFound(newID, hasDescription: true) == [
            "No rule file with the id \(newID) was found in compiled_rules or among the user rules the daemon would load.",
            "Built-in detectors have no rule file; for their alerts, the description printed above is what was captured.",
            "Note: this user cannot read all of user_rules (the folder cannot be listed or inspected, or",
            "a file in it cannot be inspected or opened). The daemon runs as root when installed, so",
            "this alert's rule may be a user rule there. To check, run",
            "`sudo maccrabctl why \(alertID)`.",
        ])
        #expect(chmod(users.path, 0o755) == 0)
        // With every file readable, an id no file has gets no note.
        #expect(notFound("unknown-id") == [
            "No rule file with the id unknown-id was found in compiled_rules or among the user rules the daemon would load.",
            "Built-in detectors have no rule file.",
        ])
        #expect(notFound("unknown-id", hasDescription: true) == [
            "No rule file with the id unknown-id was found in compiled_rules or among the user rules the daemon would load.",
            "Built-in detectors have no rule file; for their alerts, the description printed above is what was captured.",
        ])
        // Nor does it in a support dir that has no user_rules.
        #expect(MacCrabCtl.whyNoRuleFileLines(
            forRuleID: "unknown-id", in: MacCrabCtl.whySearchDirs(supportDirs: [dir.appendingPathComponent("missing").path]),
            hasDescription: false, alertID: alertID) == [
            "No rule file with the id unknown-id was found in compiled_rules or among the user rules the daemon would load.",
            "Built-in detectors have no rule file.",
        ])
    }

    @Test("the user-rule notes say the daemon applies the rule shown only for one claim with nothing unreadable, and count claims only as a lower bound when something is unreadable")
    func userRuleNotes() {
        let alertID = "00000000-0000-0000-0000-00000000003e"
        func notes(_ claimCount: Int, unreadable: Bool = false, disabled: Bool = false,
                   otherDisabled: Bool = false) -> [String] {
            MacCrabCtl.whyUserRuleNoteLines(claimCount: claimCount, unreadable: unreadable, disabled: disabled,
                                            otherClaimDisabled: otherDisabled, alertID: alertID)
        }
        // A bundled rule with nothing unreadable has no note.
        #expect(notes(0).isEmpty)
        // One claim: the daemon applies the rule shown.
        #expect(notes(1) == Self.definiteNote)
        // Two claims: the daemon applies one of them, which one is not defined.
        #expect(notes(2) == Self.hedgedNote + Self.duplicateNote)
        // Part of user_rules this user cannot read: a daemon running as root
        // may apply a user rule from there, so the rule shown is never stated
        // as the one applied, and the note does not say whether any file is
        // there.
        let unreadable = Self.unreadableNote(alertID)
        #expect(notes(0, unreadable: true) == unreadable)
        #expect(notes(1, unreadable: true) == Self.hedgedNote + unreadable)
        // Two readable claims and something unreadable: a file this user
        // cannot read may hold another claim, and the daemon may apply it.
        #expect(notes(2, unreadable: true) == Self.hedgedNote + [
            "Note: at least 2 user rules have this id. The daemon applies one of them or one this",
            "user cannot read, in an order MacCrab does not define; this is the first by file name of",
            "those this user can read.",
        ] + unreadable)

        // The user rule shown has "enabled": false. With one claim and nothing
        // unreadable, the daemon applies it and raises no alerts for the id;
        // otherwise it may apply another rule, so that is a condition.
        #expect(notes(1, disabled: true) == Self.definiteDisabledNote)
        #expect(notes(2, disabled: true) == Self.hedgedNote + Self.disabledSentence + Self.duplicateNote)
        #expect(notes(1, unreadable: true, disabled: true) == Self.hedgedNote + Self.disabledSentence + unreadable)
        #expect(notes(2, unreadable: true, disabled: true)
            == Self.hedgedNote + Self.disabledSentence + Array(notes(2, unreadable: true).dropFirst(Self.hedgedNote.count)))
        // When the bundled rule is shown, no note mentions "enabled".
        #expect(notes(0, disabled: true).isEmpty)
        #expect(notes(0, unreadable: true, disabled: true) == unreadable)

        // Another claim has "enabled": false. The daemon may apply it, so a
        // sentence after the claim count says so as a condition, whether or
        // not the rule shown has it too and whether or not something is
        // unreadable.
        #expect(notes(2, otherDisabled: true) == Self.hedgedNote + Self.duplicateNote + Self.otherDisabledSentence)
        #expect(notes(2, disabled: true, otherDisabled: true)
            == Self.hedgedNote + Self.disabledSentence + Self.duplicateNote + Self.otherDisabledSentence)
        #expect(notes(2, unreadable: true, otherDisabled: true)
            == Array(notes(2, unreadable: true).dropLast(unreadable.count)) + Self.otherDisabledSentence + unreadable)
        #expect(notes(2, unreadable: true, disabled: true, otherDisabled: true)
            == Array(notes(2, unreadable: true, disabled: true).dropLast(unreadable.count))
                + Self.otherDisabledSentence + unreadable)
    }

    @Test("the notes after a found rule come from the user rules of its support dir")
    func foundRuleNotes() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-why-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let rules = dir.appendingPathComponent("compiled_rules")
        let users = dir.appendingPathComponent("user_rules")
        func write(_ json: String, _ folder: URL, _ name: String) throws -> String {
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: folder.path)
            let path = folder.appendingPathComponent(name).path
            try json.write(toFile: path, atomically: true, encoding: .utf8)
            return path
        }
        let singleID = "d1a2b3c4-0032-4000-a000-000000000032"
        let alertID = "00000000-0000-0000-0000-00000000003d"
        let single = try write(Self.flatRule, rules, "ssh_key_access.json")
        let dirs = MacCrabCtl.whySearchDirs(supportDirs: [dir.path])
        // The rule runWhy shows, and the notes it prints after it, given the
        // rule as runWhy parses it.
        func shown() -> String? { MacCrabCtl.findRuleFile(forRuleID: singleID, in: dirs) }
        func notes(_ rulePath: String) throws -> [String] {
            let rule = try #require(JSONSerialization.jsonObject(
                with: Data(contentsOf: URL(fileURLWithPath: rulePath))) as? [String: Any])
            return MacCrabCtl.whyFoundRuleNoteLines(ruleID: singleID, rulePath: rulePath, rule: rule, alertID: alertID)
        }

        // A readable user_rules with a rule for another id only: the bundled
        // rule is shown, with no note.
        _ = try write(Self.flatRule.replacingOccurrences(of: singleID, with: "d1a2b3c4-0032-4000-a000-0000000000fe"),
                      users, "other.json")
        #expect(shown() == single)
        #expect(try notes(single).isEmpty)
        // One loadable override, shown from user_rules: the daemon applies it.
        let first = try write(Self.flatRule, users, "a.json")
        #expect(shown() == first)
        #expect(try notes(first) == Self.definiteNote)
        // Two: the first is shown, and the daemon applies one of them.
        _ = try write(Self.flatRule, users, "b.json")
        #expect(shown() == first)
        #expect(try notes(first) == Self.hedgedNote + Self.duplicateNote)

        // "enabled": false, as the dashboard's Disable writes a copy of a rule
        // into user_rules, in the one shown only: if the daemon applies it, it
        // raises no alerts for the id.
        let disabled = try Self.disabledCopy(of: Self.flatRule)
        _ = try write(disabled, users, "a.json")
        #expect(shown() == first)
        #expect(try notes(first) == Self.hedgedNote + Self.disabledSentence + Self.duplicateNote)
        // In the other one only: if the daemon applies that one, it raises none.
        _ = try write(Self.flatRule, users, "a.json")
        _ = try write(disabled, users, "b.json")
        #expect(shown() == first)
        #expect(try notes(first) == Self.hedgedNote + Self.duplicateNote + Self.otherDisabledSentence)
        // In both.
        _ = try write(disabled, users, "a.json")
        #expect(shown() == first)
        #expect(try notes(first)
            == Self.hedgedNote + Self.disabledSentence + Self.duplicateNote + Self.otherDisabledSentence)
        // One: the daemon applies it, and raises no alerts for the id.
        try FileManager.default.removeItem(atPath: users.appendingPathComponent("b.json").path)
        #expect(try notes(first) == Self.definiteDisabledNote)
        // A bundled rule's "enabled": false is not reported.
        try FileManager.default.removeItem(atPath: first)
        _ = try write(disabled, rules, "ssh_key_access.json")
        #expect(shown() == single)
        #expect(try notes(single).isEmpty)
    }

    // The notes whyUserRuleNoteLines prints, for userRuleNotes and for the
    // tests of the notes runWhy prints after a found rule.

    /// One user rule the daemon would load for the id, with all of user_rules readable.
    private static let definiteNote = [
        "Note: this is a user rule. It passes the daemon's checks on user rules (folder and",
        "file ownership, folder permissions, file type and content), so the daemon applies it in",
        "place of any bundled rule with this id; a change applies at its next rule reload.",
    ]

    /// A user rule shown when the daemon may apply another one instead.
    private static let hedgedNote = [
        "Note: this is a user rule. It passes the daemon's checks on user rules (folder and",
        "file ownership, folder permissions, file type and content), so the daemon applies it or",
        "another user rule with this id (see below) in place of any bundled rule with this id.",
    ]

    /// Two user rules the daemon would load for the id, with all of user_rules readable.
    private static let duplicateNote = [
        "Note: 2 user rules have this id. The daemon applies one of them, in an order",
        "MacCrab does not define; this is the first by file name.",
    ]

    /// One user rule the daemon would load for the id, with "enabled": false
    /// and all of user_rules readable.
    private static let definiteDisabledNote = [
        "Note: this is a user rule with \"enabled\": false. It passes the daemon's checks on user",
        "rules (folder and file ownership, folder permissions, file type and content), so the daemon",
        "applies it in place of any bundled rule with this id and raises no alerts for this id while",
        "it does; a change applies at its next rule reload.",
    ]

    /// What follows the hedged note when the user rule shown has "enabled": false.
    private static let disabledSentence = [
        "The rule shown has \"enabled\": false; if the daemon applies that rule, it raises no",
        "alerts for this id.",
    ]

    /// What follows the claim count when another user rule the daemon would
    /// load for the id has "enabled": false.
    private static let otherDisabledSentence = [
        "Another user rule with this id has \"enabled\": false; if the daemon applies that rule, it",
        "raises no alerts for this id.",
    ]

    /// A rule's JSON with "enabled" set to false, as the dashboard's Disable
    /// writes a copy of a rule into user_rules.
    private static func disabledCopy(of json: String) throws -> String {
        var object = try #require(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        object["enabled"] = false
        return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
    }

    /// Part of user_rules this user cannot read.
    private static func unreadableNote(_ alertID: String) -> [String] {
        [
            "Note: this user cannot read all of user_rules (the folder cannot be listed or inspected, or",
            "a file in it cannot be inspected or opened). The daemon runs as root when installed, so it",
            "may apply a user rule from there for this id instead of the rule shown. To check, run",
            "`sudo maccrabctl why \(alertID)`.",
        ]
    }

    @Test("a sequence rule shows its window, correlation, ordering, trigger and every step")
    func sequenceRendering() throws {
        let (lines, _) = try Self.render(
            Self.sequenceRule, path: "compiled_rules/sequences/supply_chain_full_kill_chain.json"
        )

        #expect(lines.contains("Window:      300 seconds"))
        #expect(lines.contains("Correlation: processLineage"))
        #expect(lines.contains("Ordered:     true"))
        #expect(lines.contains("Trigger:     steps [persist, exfil]"))
        #expect(lines.filter { $0.hasPrefix("Step ") } == [
            "Step 1 of 3: package_install  (process_creation)",
            "Step 2 of 3: persist  (file_event)",
            "Step 3 of 3: exfil  (network_connection)",
        ])
        // Each step's predicates use the single-event format, indented under the step.
        #expect(lines.filter { $0.hasPrefix("  Predicates (") } == [
            "  Predicates (4):", "  Predicates (6):", "  Predicates (1):",
        ])
        #expect(lines.contains(
            "     1. process.executable               endswith       /npm, /npx, /pip, … (6 total)"
        ))
        #expect(lines.filter { $0 == "  Process relation: descendant (relative to step package_install)" }.count == 2)
        #expect(lines.filter { $0 == "  " + Self.astHeader }.count == 2)
        // The exfil step has no condition tree, so its flat condition is shown.
        #expect(lines.last == "  Condition:   all_of")
    }

    @Test("a graph rule shows its nodes, edges, scope and constraints")
    func graphRendering() throws {
        let (lines, _) = try Self.render(
            Self.graphRule, path: "compiled_rules/graph/maccrab_agent_associated_shell_writes_to_login_item.json"
        )

        // A graph rule has no description, so the rule file and the bar come first.
        #expect(Array(lines.dropFirst(2)) == [
            "Nodes (3):",
            "  agent  ai_agent",
            "  login  persistence  where persistence_type in [login_item, launch_agent]",
            "  shell  process  where executable_name in [zsh, bash, sh, … (7 total)]",
            "Edges (2):",
            "  agent -associated_with_agent-> shell  (min tier: strong_inferred)",
            "  shell -created_persistence-> login  (min tier: strong_inferred)",
            "Scope:       common_ancestor=shell",
            "Constraints: min_confidence=0.7, within_seconds=600",
        ])
    }

    @Test("a single-event rule shows its predicates, then its condition tree or its flat all_of or any_of")
    func singleEventRendering() throws {
        let bar = String(repeating: "─", count: 72)

        let flatPath = "compiled_rules/ssh_key_access.json"
        let (flat, _) = try Self.render(Self.flatRule, path: flatPath)
        #expect(flat == [
            "Rule file:   \(flatPath)",
            "Summary:     Detects non-SSH processes reading SSH private key files, "
                + "which may indicate credential theft.",
            bar,
            "Predicates (4):",
            "   1. file.path                        contains       /.ssh/",
            "   2. file.path                        endswith       /id_rsa, /id_ed25519, /id_ecdsa, /id_dsa",
            "   3. process.executable               NOT endswith   /ssh, /ssh-agent, /ssh-add, … (8 total)",
            "   4. SignerType                       NOT equals     apple",
            "Condition:   all_of",
        ])

        // A flat any_of rule fires on any one predicate: here the host name or
        // the address, not both.
        let anyOfPath = "compiled_rules/c2_azurestaticprovider_net.json"
        let (anyOf, _) = try Self.render(Self.anyOfRule, path: anyOfPath)
        #expect(Array(anyOf.dropFirst(3)) == [
            "Predicates (2):",
            "   1. network.destination.hostname     contains       azurestaticprovider.net",
            "   2. network.destination.ip           equals         37.16.75.69",
            "Condition:   any_of",
        ])

        let treePath = "compiled_rules/sudoers_modification.json"
        let (tree, treeRule) = try Self.render(Self.treeRule, path: treePath)
        #expect(Array(tree.prefix(8)) == [
            "Rule file:   \(treePath)",
            "Summary:     Detects any modification to /etc/sudoers or files under /etc/sudoers.d/. Attackers modify "
                + "sudoers to grant themselves passwordless sudo access, establishing persistent privilege escalation "
                + "without needing to exploit a vulnerability.\n",
            bar,
            "Predicates (4):",
            "   1. file.path                        startswith     /etc/sudoers, /private/etc/sudoers",
            "   2. FileAction                       equals         write",
            "   3. process.executable               endswith       /visudo",
            "   4. SignerType                       equals         apple",
        ])
        // Then a header saying the tree counts predicates from 0, and the tree,
        // pretty-printed by JSONSerialization and indented two spaces.
        let conditionTree = try #require(treeRule["condition_tree"])
        let ast = String(decoding: try JSONSerialization.data(withJSONObject: conditionTree, options: .prettyPrinted),
                         as: UTF8.self)
        #expect(Array(tree.dropFirst(8)) == [Self.astHeader] + ast.split(separator: "\n").map { "  \($0)" })
        #expect(tree.contains(#"    "type" : "or","#))
    }

    @Test("a null condition_tree counts as no tree: why does not abort, and the rule or a step shows its flat condition")
    func nullConditionTree() throws {
        // The engine decodes "condition_tree": null as no tree, loads the rule
        // and evaluates its flat condition.
        var single = try #require(try JSONSerialization.jsonObject(with: Data(Self.flatRule.utf8)) as? [String: Any])
        single["condition_tree"] = NSNull()
        let data = try JSONSerialization.data(withJSONObject: single)
        #expect(try RuleEngine.decodeLoadableRule(data).conditionTree == nil)
        let (lines, _) = try Self.render(String(decoding: data, as: UTF8.self), path: "user_rules/ssh_key_access.json")
        #expect(lines.contains("Predicates (4):"))
        #expect(!lines.contains { $0.hasPrefix("Condition AST") })
        #expect(lines.last == "Condition:   all_of")

        // The package_install step's tree is null, so it shows its flat any_of.
        var sequence = try #require(try JSONSerialization.jsonObject(with: Data(Self.sequenceRule.utf8)) as? [String: Any])
        var steps = try #require(sequence["steps"] as? [[String: Any]])
        steps[0]["condition_tree"] = NSNull()
        sequence["steps"] = steps
        let (stepLines, _) = try Self.render(
            String(decoding: try JSONSerialization.data(withJSONObject: sequence), as: UTF8.self),
            path: "compiled_rules/sequences/supply_chain_full_kill_chain.json")
        #expect(stepLines.filter { $0 == "  " + Self.astHeader }.count == 1)
        #expect(stepLines.contains("  Condition:   any_of"))

        // A tree JSONSerialization cannot write prints nothing rather than raising.
        single["condition_tree"] = "any_of"
        #expect(!MacCrabCtl.whyRuleLines(single, rulePath: "x.json").contains { $0.hasPrefix("Condition AST") })
    }

    /// The line above a condition tree: its index, rangeStart and rangeEnd
    /// count predicates from 0, while the predicate list numbers them from 1.
    private static let astHeader = "Condition AST (index, rangeStart and rangeEnd count predicates from 0, "
        + "so index 0 is predicate 1; rangeEnd is not included):"

    /// Parses a fixture the way `runWhy` parses a rule file, then renders it.
    private static func render(_ json: String, path: String) throws -> (lines: [String], rule: [String: Any]) {
        let rule = try #require(try JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any])
        return (MacCrabCtl.whyRuleLines(rule, rulePath: path), rule)
    }

    // Rules/sequences/supply_chain_full_kill_chain.yml, compiled.
    private static let sequenceRule = #"""
        {
          "id": "e1f2a3b4-0023-4000-b000-000000000023",
          "title": "Full Supply Chain Kill Chain - Install to Persist to Exfiltrate",
          "description": "Detects a supply chain attack chain: a package-manager install, then persistence (a LaunchAgent or LaunchDaemon, cron, a .pth file or a shell profile) and a network connection to a public address, both from the install's descendants.\n",
          "level": "high",
          "tags": [
            "attack.initial_access",
            "attack.persistence",
            "attack.credential_access",
            "attack.exfiltration",
            "attack.t1195.001",
            "attack.t1543.001",
            "attack.t1552.001"
          ],
          "window": 300.0,
          "correlationType": "processLineage",
          "ordered": true,
          "steps": [
            {
              "id": "package_install",
              "logsourceCategory": "process_creation",
              "predicates": [
                {
                  "field": "process.executable",
                  "modifier": "endswith",
                  "values": ["/npm", "/npx", "/pip", "/pip3", "/gem", "/cargo"],
                  "negate": false
                },
                {"field": "process.commandline", "modifier": "contains", "values": ["install"], "negate": false},
                {"field": "process.executable", "modifier": "endswith", "values": ["/node"], "negate": false},
                {
                  "field": "process.commandline",
                  "modifier": "contains",
                  "values": ["/npm install", "/npm-cli.js install"],
                  "negate": false
                }
              ],
              "condition": "any_of",
              "afterStep": null,
              "processRelation": null,
              "condition_tree": {
                "type": "or",
                "operands": [
                  {"type": "group", "rangeStart": 0, "rangeEnd": 2, "mode": "all_of"},
                  {"type": "group", "rangeStart": 2, "rangeEnd": 4, "mode": "all_of"}
                ]
              }
            },
            {
              "id": "persist",
              "logsourceCategory": "file_event",
              "predicates": [
                {"field": "file.path", "modifier": "contains", "values": ["/LaunchAgents/"], "negate": false},
                {"field": "file.path", "modifier": "contains", "values": ["/LaunchDaemons/"], "negate": false},
                {"field": "file.path", "modifier": "startswith", "values": ["/private/var/at/tabs/"], "negate": false},
                {"field": "file.path", "modifier": "endswith", "values": [".pth"], "negate": false},
                {"field": "file.path", "modifier": "contains", "values": ["site-packages"], "negate": false},
                {
                  "field": "file.path",
                  "modifier": "endswith",
                  "values": ["/.zshrc", "/.bashrc", "/.bash_profile"],
                  "negate": false
                }
              ],
              "condition": "any_of",
              "afterStep": "package_install",
              "processRelation": {"relation": "descendant", "relativeToStep": "package_install"},
              "condition_tree": {
                "type": "or",
                "operands": [
                  {"type": "predicate", "index": 0},
                  {"type": "predicate", "index": 1},
                  {"type": "predicate", "index": 2},
                  {"type": "group", "rangeStart": 3, "rangeEnd": 5, "mode": "all_of"},
                  {"type": "predicate", "index": 5}
                ]
              }
            },
            {
              "id": "exfil",
              "logsourceCategory": "network_connection",
              "predicates": [
                {"field": "DestinationIsPrivate", "modifier": "equals", "values": ["false"], "negate": false}
              ],
              "condition": "all_of",
              "afterStep": "persist",
              "processRelation": {"relation": "descendant", "relativeToStep": "package_install"}
            }
          ],
          "trigger": {"type": "steps", "value": ["persist", "exfil"]},
          "enabled": true,
          "status": "stable",
          "suppressible": false
        }
        """#

    // Rules/graph/maccrab_agent_associated_shell_writes_to_login_item.json.
    private static let graphRule = #"""
        {
          "id": "maccrab_agent_associated_shell_writes_to_login_item",
          "title": "AI-associated shell wrote to a login item",
          "severity": "high",
          "type": "graph",
          "status": "stable",
          "nodes": {
            "agent": {"type": "ai_agent"},
            "shell": {
              "type": "process",
              "where": {"executable_name": {"in": ["zsh", "bash", "sh", "osascript", "python", "python3", "node"]}}
            },
            "login": {"type": "persistence", "where": {"persistence_type": {"in": ["login_item", "launch_agent"]}}}
          },
          "edges": [
            {"from": "agent", "to": "shell", "relation": "associated_with_agent", "min_tier": "strong_inferred"},
            {"from": "shell", "to": "login", "relation": "created_persistence", "min_tier": "strong_inferred"}
          ],
          "scope": {"common_ancestor": "shell"},
          "constraints": {"within_seconds": 600, "min_confidence": 0.7},
          "attack": ["T1543.001", "T1547"]
        }
        """#

    // Rules/credential_access/ssh_key_access.yml, compiled: a flat condition with negated predicates.
    private static let flatRule = #"""
        {
          "id": "d1a2b3c4-0032-4000-a000-000000000032",
          "title": "SSH Private Key Accessed by Unusual Process",
          "description": "Detects non-SSH processes reading SSH private key files, which may indicate credential theft.",
          "level": "medium",
          "suppressible": true,
          "tags": ["attack.credential_access", "attack.t1552.004"],
          "logsource": {"category": "file_event", "product": "macos"},
          "predicates": [
            {"field": "file.path", "modifier": "contains", "values": ["/.ssh/"], "negate": false},
            {
              "field": "file.path",
              "modifier": "endswith",
              "values": ["/id_rsa", "/id_ed25519", "/id_ecdsa", "/id_dsa"],
              "negate": false
            },
            {
              "field": "process.executable",
              "modifier": "endswith",
              "values": ["/ssh", "/ssh-agent", "/ssh-add", "/sshd", "/scp", "/sftp", "/git", "/ssh-keygen"],
              "negate": true
            },
            {"field": "SignerType", "modifier": "equals", "values": ["apple"], "negate": true}
          ],
          "condition": "all_of",
          "falsepositives": ["Key management tools", "IDE SSH integrations"],
          "enabled": true,
          "status": "experimental"
        }
        """#

    // Rules/command_and_control/c2_azurestaticprovider_net.yml, compiled: the
    // YAML condition `selection_host or selection_ip` becomes a flat any_of.
    private static let anyOfRule = #"""
        {
          "id": "6b2a0325-1901-48ca-9bbf-c4b45cc0d7ab",
          "title": "C2 Connection to sh.azurestaticprovider.net / 37.16.75.69 (Mini Shai-Hulud)",
          "description": "Detects a DNS resolution or outbound network connection to the literal C2 host `sh.azurestaticprovider.net` (or its parent `azurestaticprovider.net`) or the associated IP `37.16.75.69`. These are the documented C2 indicators for the Mini Shai-Hulud SAP CAP / PyTorch Lightning / Intercom / TanStack waves (Feb-May 2026). The domain typosquats Microsoft Azure Static Web Apps to evade casual review; the IP is the resolution pinned in the Feb-Mar 2026 waves. Any traffic to either is essentially diagnostic — legitimate macOS hosts have no reason to talk to this typosquat domain.\n",
          "level": "critical",
          "suppressible": false,
          "tags": [
            "attack.command_and_control",
            "attack.t1071.001",
            "attack.t1102",
            "attack.initial_access",
            "attack.t1195.001"
          ],
          "logsource": {"category": "network_connection", "product": "macos"},
          "predicates": [
            {
              "field": "network.destination.hostname",
              "modifier": "contains",
              "values": ["azurestaticprovider.net"],
              "negate": false
            },
            {"field": "network.destination.ip", "modifier": "equals", "values": ["37.16.75.69"], "negate": false}
          ],
          "condition": "any_of",
          "falsepositives": [
            "A defender or red-team operator running a controlled replay of the IOC on the monitored host — investigate parent lineage; the alert is the correct outcome",
            "A defender pinning the IP into a local DNS sinkhole for analysis (rare; the network-connection event still fires once the resolution is attempted)"
          ],
          "enabled": true,
          "status": "stable"
        }
        """#

    // Rules/defense_evasion/sudoers_modification.yml, compiled: a condition tree.
    private static let treeRule = #"""
        {
          "id": "d1a2b3c4-0439-4000-b000-000000000439",
          "title": "Sudoers File Modified",
          "description": "Detects any modification to /etc/sudoers or files under /etc/sudoers.d/. Attackers modify sudoers to grant themselves passwordless sudo access, establishing persistent privilege escalation without needing to exploit a vulnerability.\n",
          "level": "high",
          "suppressible": true,
          "tags": ["attack.defense_evasion", "attack.privilege_escalation", "attack.t1548.003"],
          "logsource": {"category": "file_event", "product": "macos"},
          "predicates": [
            {
              "field": "file.path",
              "modifier": "startswith",
              "values": ["/etc/sudoers", "/private/etc/sudoers"],
              "negate": false
            },
            {"field": "FileAction", "modifier": "equals", "values": ["write"], "negate": false},
            {"field": "process.executable", "modifier": "endswith", "values": ["/visudo"], "negate": false},
            {"field": "SignerType", "modifier": "equals", "values": ["apple"], "negate": false}
          ],
          "condition": "any_of",
          "falsepositives": [
            "Legitimate system administration via visudo",
            "MDM or configuration management tools adjusting sudo policies"
          ],
          "enabled": true,
          "status": "experimental",
          "condition_tree": {
            "type": "or",
            "operands": [
              {"type": "group", "rangeStart": 0, "rangeEnd": 2, "mode": "all_of"},
              {
                "type": "and",
                "operands": [
                  {"type": "predicate", "index": 2},
                  {"type": "not", "operands": [{"type": "predicate", "index": 3}]}
                ]
              }
            ]
          }
        }
        """#
}
