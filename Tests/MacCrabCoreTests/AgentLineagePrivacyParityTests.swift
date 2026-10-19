import Foundation
import Testing
@testable import MacCrabCore

/// Inert strings only; no path is opened. The oracles below keep the
/// pre-optimization operations verbatim (Foundation `contains`, privacy
/// classification before eligibility) so the reordered guard and the
/// single-fold privacy classifier are checked against an independent copy.
@Suite("Agent lineage privacy and eligibility parity")
struct AgentLineagePrivacyParityTests {
    private static func originalDefaultCredentialType(_ input: String) -> CredentialFence.CredentialType? {
        let path = input.lowercased()
        let filename = (path as NSString).lastPathComponent
        for fragment in ["/library/application support/maccrab/", "/.maccrab/",
                         "/decoys/", "/t/tcc-home-"] where path.contains(fragment) {
            return nil
        }
        if filename.hasPrefix(".env") {
            for suffix in [".example", ".sample", ".template", ".dist", ".tmpl"]
                where filename.hasSuffix(suffix) { return nil }
        }
        if filename.hasSuffix(".pub") { return nil }
        if path.contains("/system/library/keychains/") { return nil }
        for item in CredentialFence.defaultPaths {
            let pattern = item.pattern.lowercased()
            switch item.kind {
            case .exactFilename: if filename == pattern { return item.type }
            case .filenamePrefix: if filename.hasPrefix(pattern) { return item.type }
            case .pathFragment: if path.contains(pattern) { return item.type }
            }
        }
        return nil
    }

    private static func originalIsPrivate(_ filePath: String) -> Bool {
        if originalDefaultCredentialType(filePath) != nil { return true }
        let path = filePath.lowercased()
        return path.contains("/.aws/config")
            || path.contains("/.aws/sso/cache/")
            || path.contains("/.bw/data.json")
            || path.contains("/.config/op/")
            || path.contains("/group containers/2bua8c4s2c.com.agilebits/")
            || path.contains("/group containers/2bua8c4s2c.com.1password/")
            || path.contains("/.ssh/authorized_keys")
            || path.hasSuffix("/.gitconfig")
            || path.contains("/library/application support/google/chrome/")
            || path.contains("/library/application support/firefox/")
            || path.contains("/library/application support/bravesoftware/")
            || path.contains("/library/application support/microsoft edge/")
            || path.contains("/library/application support/arc/")
            || path.contains("/library/application support/vivaldi/")
            || path.contains("/library/application support/com.operasoftware.opera/")
            || path.contains("/library/safari/")
            || path.contains("/library/containers/com.apple.safari/")
            || path.hasSuffix("/cookies.binarycookies")
    }

    private static func originalKind(path: String, eventAction: String) -> AgentEvent.Kind? {
        guard !originalIsPrivate(path) else { return nil }
        guard FileInjectionScanner.isEligible(path: path, eventAction: eventAction) else { return nil }
        switch eventAction.lowercased() {
        case "open": return .fileRead(path: path)
        case "close_modified": return .fileWrite(path: path)
        default: return nil
        }
    }

    private static let basePaths: [String] = [
        "/Users/dev/project/README.md", "/Users/dev/project/main.py", "/Users/dev/project/app.swift",
        "/Users/dev/project/.env", "/Users/dev/project/.env.local", "/Users/dev/project/.env.example",
        "/Users/dev/project/.config", "/Users/dev/project/settings.ini", "/Users/dev/project/doc.pdf",
        "/Users/dev/project/image.png", "/Users/dev/project/Makefile", "/Users/dev/project/notes",
        "/Users/dev/.ssh/id_rsa", "/Users/dev/.ssh/id_rsa.pub", "/Users/dev/.ssh/config",
        "/Users/dev/.ssh/authorized_keys", "/Users/dev/.aws/config", "/Users/dev/.aws/credentials",
        "/Users/dev/.aws/sso/cache/token.json", "/Users/dev/.config/gh/hosts.yml",
        "/Users/dev/.config/op/config.json", "/Users/dev/.gitconfig", "/Users/dev/project/.gitconfig.txt",
        "/Users/dev/Library/Application Support/Google/Chrome/Default/Preferences.json",
        "/Users/dev/Library/Application Support/Firefox/profiles.ini",
        "/Users/dev/Library/Safari/History.txt", "/Users/dev/Library/Cookies/Cookies.binarycookies",
        "/Users/dev/Library/Group Containers/2BUA8C4S2C.com.1password/data.json",
        "/Users/dev/Library/Keychains/login.keychain-db", "/System/Library/Keychains/x.txt",
        "/Library/Application Support/MacCrab/rules.json", "/Users/dev/.maccrab/x.md",
        "/private/var/folders/x/T/tcc-home-1/.netrc.txt", "/Users/dev/decoys/.env",
        "/Users/d\u{e9}v/project/R\u{c9}SUM\u{c9}.md", "/tmp/a\r\nb.md", "", "/", "README.md",
    ]
    private static let actions = [
        "open", "OPEN", "Open", "close_modified", "CLOSE_MODIFIED", "close", "create", "write",
        "rename", "unlink", "exec", "", "open ",
    ]

    @Test("privacy classification agrees with the original two-fold classifier")
    func privacyParity() {
        for base in Self.basePaths {
            for path in [base, base.uppercased(), base.decomposedStringWithCanonicalMapping] {
                #expect(CredentialFence.isPrivateAgentLineagePath(path) == Self.originalIsPrivate(path),
                        "\(path.debugDescription)")
            }
        }
    }

    @Test("every action and path materializes exactly as before the reorder")
    func materializationParity() {
        var materialized = 0, privateRejected = 0
        for base in Self.basePaths {
            for path in [base, base.uppercased(), base.decomposedStringWithCanonicalMapping] {
                for action in Self.actions {
                    let expected = Self.originalKind(path: path, eventAction: action)
                    let actual = AgentLineageService.materializedFileEventKind(path: path, eventAction: action)
                    #expect(actual == expected, "\(path.debugDescription) \(action.debugDescription)")
                    if expected != nil { materialized += 1 }
                    if FileInjectionScanner.isEligible(path: path, eventAction: action),
                       Self.originalIsPrivate(path) { privateRejected += 1 }
                }
            }
        }
        // Both guards are exercised: some eligible paths are withheld as private.
        #expect(materialized > 50)
        #expect(privateRejected > 10)
    }
}
