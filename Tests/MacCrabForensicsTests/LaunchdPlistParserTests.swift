// LaunchdPlistParser tests — fixture plist data exercised through
// the parser. Verifies field extraction, runs-as-root derivation,
// program existence resolution, and error handling.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("LaunchdPlistParser")
struct LaunchdPlistParserTests {

    private func writePlist(_ dict: [String: Any], suffix: String = "test.plist") throws -> String {
        let path = NSTemporaryDirectory() + "maccrab-launchd-\(UUID().uuidString)-\(suffix)"
        let data = try PropertyListSerialization.data(
            fromPropertyList: dict,
            format: .xml,
            options: 0
        )
        try data.write(to: URL(fileURLWithPath: path))
        return path
    }

    @Test("Parses a minimal LaunchAgent plist with Label + ProgramArguments")
    func minimalLaunchAgent() throws {
        let plistPath = try writePlist([
            "Label": "com.example.test",
            "ProgramArguments": ["/usr/bin/true", "--foo"],
            "RunAtLoad": true,
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }

        let entry = try LaunchdPlistParser.parse(path: plistPath, domain: .userAgent)
        #expect(entry.label == "com.example.test")
        #expect(entry.programPath == "/usr/bin/true")
        #expect(entry.arguments == ["/usr/bin/true", "--foo"])
        #expect(entry.runAtLoad == true)
        #expect(entry.programExists == true)
        #expect(entry.programMissingReason == nil)
    }

    @Test("LaunchDaemon domain implies runs_as_root + effective_user=root")
    func daemonDomainRunsAsRoot() throws {
        let plistPath = try writePlist([
            "Label": "com.example.daemon",
            "Program": "/usr/bin/true",
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        let entry = try LaunchdPlistParser.parse(path: plistPath, domain: .systemWideDaemon)
        #expect(entry.runsAsRoot == true)
        #expect(entry.effectiveUser == "root")
    }

    @Test("UserName key overrides domain-derived effective user")
    func userNameKeyWins() throws {
        let plistPath = try writePlist([
            "Label": "com.example.uid_override",
            "Program": "/usr/bin/true",
            "UserName": "_spotlight",
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        let entry = try LaunchdPlistParser.parse(path: plistPath, domain: .systemWideDaemon)
        #expect(entry.effectiveUser == "_spotlight")
        #expect(entry.runsAsRoot == false)
    }

    @Test("KeepAlive dictionary is treated as keep_alive=true")
    func keepAliveDictionary() throws {
        let plistPath = try writePlist([
            "Label": "com.example.alive",
            "Program": "/usr/bin/true",
            "KeepAlive": ["NetworkState": true],
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        let entry = try LaunchdPlistParser.parse(path: plistPath, domain: .userAgent)
        #expect(entry.keepAlive == true)
    }

    @Test("StartInterval is preserved")
    func startInterval() throws {
        let plistPath = try writePlist([
            "Label": "com.example.timer",
            "Program": "/usr/bin/true",
            "StartInterval": 300,
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        let entry = try LaunchdPlistParser.parse(path: plistPath, domain: .userAgent)
        #expect(entry.startIntervalSeconds == 300)
    }

    @Test("Missing program path marks program_exists=false + reason=deleted")
    func missingProgramDeleted() throws {
        let plistPath = try writePlist([
            "Label": "com.example.gone",
            "Program": "/private/tmp/nonexistent-binary-\(UUID().uuidString)",
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        let entry = try LaunchdPlistParser.parse(path: plistPath, domain: .userAgent)
        #expect(entry.programExists == false)
        #expect(entry.programMissingReason == "deleted")
    }

    @Test("Unresolved ${VAR} substitution marks reason=unresolved")
    func unresolvedVariable() throws {
        let plistPath = try writePlist([
            "Label": "com.example.unresolved",
            "Program": "${HOME}/bin/script",
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        let entry = try LaunchdPlistParser.parse(path: plistPath, domain: .userAgent)
        #expect(entry.programExists == false)
        #expect(entry.programMissingReason == "unresolved")
    }

    @Test("WatchPaths array survives the round-trip")
    func watchPathsArray() throws {
        let plistPath = try writePlist([
            "Label": "com.example.watcher",
            "Program": "/usr/bin/true",
            "WatchPaths": ["/var/log/system.log", "/var/log/install.log"],
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        let entry = try LaunchdPlistParser.parse(path: plistPath, domain: .userAgent)
        #expect(entry.watchPaths == ["/var/log/system.log", "/var/log/install.log"])
    }

    @Test("Missing Label throws missingLabel error")
    func missingLabelErrors() throws {
        let plistPath = try writePlist([
            "Program": "/usr/bin/true",
        ])
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        #expect(throws: LaunchdPlistParser.ParseError.self) {
            _ = try LaunchdPlistParser.parse(path: plistPath, domain: .userAgent)
        }
    }

    @Test("Invalid XML throws decodeFailed")
    func invalidXMLDecodeFails() throws {
        let plistPath = NSTemporaryDirectory() + "maccrab-launchd-bad-\(UUID().uuidString).plist"
        try Data("this is not a plist".utf8).write(to: URL(fileURLWithPath: plistPath))
        defer { try? FileManager.default.removeItem(atPath: plistPath) }
        #expect(throws: LaunchdPlistParser.ParseError.self) {
            _ = try LaunchdPlistParser.parse(path: plistPath, domain: .userAgent)
        }
    }
}
