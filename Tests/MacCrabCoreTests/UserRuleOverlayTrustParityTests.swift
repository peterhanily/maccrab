import Foundation
import Testing
@testable import MacCrabAgentKit
import MacCrabCore

/// `maccrabctl why` and the MCP rule index behind explain_alert decide which
/// user rule the engine applies with UserRuleOverlayTrust, which repeats the
/// engine's own gates instead of calling them. The engine has three: the
/// user_rules folder check its reload paths call (isOverlayDirSecure), an
/// equivalent check nested in DaemonSetup.initialize() for the boot-time load
/// (isSecureDirectory), and the per-file owner check in
/// RuleEngine.loadRules(requireOwnerUID:).
///
/// The first two tests run a copy and the engine's gate on the same disk
/// state: a user_rules folder this user owns, checked with this process's uid
/// as the engine's, at 0755, 0775, 0757 and 0700, at 0755 with an ACL entry
/// that lets everyone add and delete files, and a symlink to it; and a rule
/// file this user owns, loaded with its owner's uid and with another uid as
/// the engine's. A change that flips either side's verdict for one of these
/// fails here. A test running as a normal user cannot create a folder or file
/// that root or another user owns, so in such a run a change that affects
/// only those owners does not fail here. The nested boot gate cannot be
/// called from a test, so the last test pins its source instead.
@Suite("User rule overlay trust matches the engine's gates")
struct UserRuleOverlayTrustParityTests {
    /// A support directory with an empty user_rules folder.
    private func supportDirectory() throws -> (root: String, user: String) {
        let root = NSTemporaryDirectory() + "maccrab-overlay-parity-\(UUID().uuidString)"
        let user = root + "/user_rules"
        try FileManager.default.createDirectory(atPath: user, withIntermediateDirectories: true)
        return (root, user)
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

    @Test("the folder check agrees with isOverlayDirSecure for a 0755, 0775, 0757 and 0700 user_rules, a 0755 one with an ACL entry that lets everyone add and delete files, and a symlink to it")
    func folderParity() throws {
        let (root, user) = try supportDirectory()
        defer {
            _ = try? chmodACL(["-N", user])
            try? FileManager.default.removeItem(atPath: root)
        }
        func trust(_ path: String) -> Bool { UserRuleOverlayTrust.trustsDirectory(atPath: path, engineUID: getuid()) }

        var engine: [mode_t: Bool] = [:]
        for mode: mode_t in [0o755, 0o775, 0o757, 0o700] {
            #expect(chmod(user, mode) == 0)
            engine[mode] = isOverlayDirSecure(user)
            #expect(trust(user) == isOverlayDirSecure(user), "mode \(String(mode, radix: 8))")
        }
        // The engine accepts a folder only its owner can write, so the
        // agreement above is not two checks that refuse everything.
        let ownerWritableOnly: [mode_t: Bool] = [0o755: true, 0o775: false, 0o757: false, 0o700: true]
        #expect(engine == ownerWritableOnly)

        // An ACL entry that lets everyone add and delete files leaves the mode
        // at 0755. Neither check reads ACL entries, so today both accept the
        // folder, and a change to either one that refuses it fails here.
        #expect(chmod(user, 0o755) == 0)
        #expect(try chmodACL(["+a", "group:everyone allow add_file,delete_child", user]) == 0)
        var st = stat()
        #expect(lstat(user, &st) == 0)
        let permissions = st.st_mode & 0o7777
        #expect(permissions == 0o755)
        #expect(isOverlayDirSecure(user))
        #expect(trust(user) == isOverlayDirSecure(user))
        #expect(try chmodACL(["-N", user]) == 0)

        // A symlink to a folder both accept: both refuse the link.
        let link = root + "/linked_rules"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: user)
        #expect(!isOverlayDirSecure(link))
        #expect(trust(link) == isOverlayDirSecure(link))
    }

    @Test("loadRules(requireOwnerUID:) loads a user rule exactly when trustsFile accepts its owner")
    func fileOwnerParity() async throws {
        let (root, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
        let file = user + "/u.json"
        try JSONSerialization.data(withJSONObject: [
            "id": "overlay.parity", "title": "overlay parity fixture", "description": "overlay parity fixture",
            "level": "low", "tags": ["attack.discovery"], "logsource": ["category": "file_event", "product": "macos"],
            "predicates": [["field": "file.path", "modifier": "contains",
                            "values": ["/maccrab-overlay-parity/"], "negate": false]],
            "condition": "all_of", "falsepositives": ["test fixture"], "enabled": true, "status": "stable",
        ]).write(to: URL(fileURLWithPath: file))

        // A test cannot create a file another uid owns, so the engine's uid
        // is varied instead: the file's owner, then a uid that does not own it.
        let owner = getuid()
        let other: uid_t = owner == 0 ? 1 : 0
        var loads: [uid_t: Bool] = [:]
        for engineUID in [owner, other] {
            let loaded = try await RuleEngine().loadRules(from: URL(fileURLWithPath: user), requireOwnerUID: engineUID)
            loads[engineUID] = loaded == 1
            #expect((loaded == 1) == UserRuleOverlayTrust.trustsFile(atPath: file, engineUID: engineUID), "uid \(engineUID)")
        }
        // The owner's uid loads it and the other does not, so the agreement
        // above covers both outcomes.
        let ownerOnly: [uid_t: Bool] = [owner: true, other: false]
        #expect(loads == ownerOnly)
    }

    @Test("the boot-time user_rules load is gated by the check nested in DaemonSetup.initialize(), which has isOverlayDirSecure's conditions and no other refusal")
    func bootGateSource() throws {
        let source = try String(contentsOf: URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/MacCrabAgentKit/DaemonSetup.swift"), encoding: .utf8)
        let update = "DaemonSetup's boot-time user_rules gate changed: make UserRuleOverlayTrust and these tests match it"
        func occurrences(of text: String, in haystack: String) -> Int {
            haystack.components(separatedBy: text).count - 1
        }
        // The text from `opening`, a line indented eight spaces, to the first
        // closing brace at that indentation, which ends the block it opens.
        // Found outside #require so that a failure does not print the whole
        // file.
        func block(_ opening: String) -> String? {
            guard let start = source.range(of: opening),
                  let end = source.range(of: "\n        }\n", range: start.upperBound..<source.endIndex) else { return nil }
            return String(source[start.upperBound..<end.lowerBound])
        }

        // A block's code: its lines other than whole-line comments, so that
        // commenting a line out changes it.
        func code(_ block: String) -> String {
            block.split(separator: "\n", omittingEmptySubsequences: false)
                .filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }
                .joined(separator: "\n")
        }

        // The one boot load of user_rules sits inside the block the nested
        // check gates, whose code is exactly what it was when this test was
        // written, so a refusal added in front of the load fails here.
        let gated = block("        if fm.fileExists(atPath: userOverridesDir), isSecureDirectory(userOverridesDir) {\n")
        let gate = try #require(gated, "\(update)")
        #expect(code(gate) == Self.bootGatedBlock, "\(update)")
        let bootLoads = occurrences(of: "loadRules(from: userOverridesURL", in: source)
        #expect(bootLoads == 1, "\(update)")
        // Both overlay loads in this file, the boot load and the .reload_tick
        // watcher's, pass requireOwnerUID:, so a further load that passes it
        // changes this count however it names the folder.
        #expect(occurrences(of: "requireOwnerUID:", in: source) == 2, "\(update)")

        // The nested check, declared once, with the code it had when this test
        // was written. Like isOverlayDirSecure, it refuses a symlink, a folder
        // whose attributes it cannot read, an owner other than root or
        // getuid(), and a group- or world-writable mode. Relaxing, removing or
        // commenting out a refusal, or adding one, fails here.
        let declaration = "        func isSecureDirectory(_ path: String) -> Bool {\n"
        let declarations = occurrences(of: declaration, in: source)
        #expect(declarations == 1, "\(update)")
        let nested = block(declaration)
        let body = try #require(nested, "\(update)")
        #expect(code(body) == Self.bootNestedGateBody, "\(update)")
    }

    /// The code DaemonSetup.initialize() runs when
    /// isSecureDirectory(userOverridesDir) accepts user_rules, without
    /// whole-line comments.
    private static let bootGatedBlock = #"""
                    do {
                        let userCount = try await ruleEngine.loadRules(from: userOverridesURL, requireOwnerUID: geteuid())
                        if userCount > 0 {
                            logger.info("Loaded \(userCount) user rule override(s) from \(userOverridesDir)")
                            print("Loaded \(userCount) user rule override(s)")
                        }
                    } catch {
                        logger.warning("user_rules overlay skipped: \(error.localizedDescription)")
                    }
        """#

    /// The body of the isSecureDirectory(_:) nested in
    /// DaemonSetup.initialize(), without whole-line comments.
    private static let bootNestedGateBody = #"""
                    let url = URL(fileURLWithPath: path)
                    if let resourceValues = try? url.resourceValues(forKeys: [.isSymbolicLinkKey]),
                       resourceValues.isSymbolicLink == true {
                        logger.warning("Rules directory \(path) is a symlink. Refusing to load rules to prevent symlink injection attacks.")
                        return false
                    }

                    guard let attrs = try? fm.attributesOfItem(atPath: path) else {
                        return false
                    }
                    let ownerUID = (attrs[.ownerAccountID] as? NSNumber)?.uint32Value ?? UInt32.max
                    let currentUID = getuid()
                    guard ownerUID == 0 || ownerUID == currentUID else {
                        logger.warning("Rules directory \(path) is owned by uid \(ownerUID), expected 0 or \(currentUID). Skipping.")
                        return false
                    }
                    if let posix = (attrs[.posixPermissions] as? NSNumber)?.intValue {
                        if posix & 0o022 != 0 {
                            logger.warning("Rules directory \(path) is group/world-writable (mode \(String(posix, radix: 8))). Refusing to load rules to prevent non-root rule tampering.")
                            return false
                        }
                    }
                    return true
        """#
}
