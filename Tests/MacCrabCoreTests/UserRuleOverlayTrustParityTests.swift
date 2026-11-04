import Foundation
import Testing
@testable import MacCrabAgentKit
import MacCrabCore

/// `maccrabctl why` and the MCP rule index behind explain_alert decide which
/// user rule the engine applies with UserRuleOverlayTrust, which repeats the
/// engine's own gates instead of calling them: the user_rules folder check the
/// engine's reload paths call (isOverlayDirSecure) and the per-file owner check
/// in RuleEngine.loadRules(requireOwnerUID:). These run each copy against the
/// engine's gate on the same folder and file, so a change to one that the
/// other does not follow fails here.
@Suite("User rule overlay trust matches the engine's gates")
struct UserRuleOverlayTrustParityTests {
    /// A support directory with an empty user_rules folder.
    private func supportDirectory() throws -> (root: String, user: String) {
        let root = NSTemporaryDirectory() + "maccrab-overlay-parity-\(UUID().uuidString)"
        let user = root + "/user_rules"
        try FileManager.default.createDirectory(atPath: user, withIntermediateDirectories: true)
        return (root, user)
    }

    @Test("the folder check agrees with isOverlayDirSecure for a 0755, 0775, 0757 and 0700 user_rules and a symlink to it")
    func folderParity() throws {
        let (root, user) = try supportDirectory()
        defer { try? FileManager.default.removeItem(atPath: root) }
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

        // A symlink to a folder both accept: both refuse the link.
        #expect(chmod(user, 0o755) == 0)
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
}
