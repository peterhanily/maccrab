// ProcessAncestorsBoundaryRuleTests.swift
// v1.17.4 audit DSN-1 / ABF-1 — the lineage FP filters in
// deep_shell_nesting and auth_brute_force matched ProcessAncestors with
// boundary-less substrings ('/node' matched '/node_modules/', '/screen'
// matched 'screensharingd', etc.), so an attacker could suppress detection
// by staging a payload under a colliding directory. They now use
// boundary-anchored regex. This pins the intended match/non-match behavior
// against the SAME NSRegularExpression evaluation the RuleEngine uses
// (regex .firstMatch on the raw, newline-joined ProcessAncestors field),
// reading the patterns straight from the rule YAML so the test can't drift
// from the shipped rule.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("ProcessAncestors boundary-anchored lineage filters (DSN-1 / ABF-1)")
struct ProcessAncestorsBoundaryRuleTests {

    private func repoRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // repo root
    }

    /// Every `(?i)...` regex value the rule declares (the ProcessAncestors|re
    /// patterns — the only `(?i)` strings in these rules).
    private func regexPatterns(inRuleAt relPath: String) throws -> [String] {
        let yaml = try String(contentsOf: repoRoot().appendingPathComponent(relPath), encoding: .utf8)
        var out: [String] = []
        for raw in yaml.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(raw)
            // Only real list-item values, not comment lines that happen to
            // mention "(?i)" or contain quoted tokens.
            guard line.trimmingCharacters(in: .whitespaces).hasPrefix("- '(?i)"),
                  let open = line.firstIndex(of: "'"),
                  let close = line.lastIndex(of: "'"), open < close else { continue }
            out.append(String(line[line.index(after: open)..<close]))
        }
        return out
    }

    /// Mirror RuleEngine: ProcessAncestors = each ancestor's [name, executable]
    /// flattened and joined by "\n".
    private func ancestorsBlob(_ pairs: [(name: String, exe: String)]) -> String {
        pairs.flatMap { [$0.name, $0.exe] }.joined(separator: "\n")
    }

    /// Mirror RuleEngine.evaluateModifier(.regex): any pattern firstMatch on
    /// the raw field value.
    private func anyMatch(_ patterns: [String], _ field: String) -> Bool {
        for p in patterns {
            guard let re = try? NSRegularExpression(pattern: p) else { continue }
            if re.firstMatch(in: field, options: [],
                             range: NSRange(field.startIndex..., in: field)) != nil {
                return true
            }
        }
        return false
    }

    // MARK: - deep_shell_nesting build-system / env-manager filters

    @Test("build/env filters match a genuine tool ancestor but NOT a colliding directory")
    func deepShellBoundaries() throws {
        let patterns = try regexPatterns(inRuleAt: "Rules/execution/deep_shell_nesting.yml")
        #expect(patterns.count == 2, "expected 2 ProcessAncestors|re patterns (build + env)")

        // Genuine tool ancestors → filter matches → rule SUPPRESSED (correct).
        #expect(anyMatch(patterns, ancestorsBlob([("node", "/usr/local/bin/node"), ("zsh", "/bin/zsh")])))
        #expect(anyMatch(patterns, ancestorsBlob([("make", "/usr/bin/make")])))
        #expect(anyMatch(patterns, ancestorsBlob([("Installer", "/System/Library/CoreServices/Installer.app/Contents/MacOS/Installer")])))
        #expect(anyMatch(patterns, ancestorsBlob([("pip3", "/usr/bin/pip3")])))
        #expect(anyMatch(patterns, ancestorsBlob([("direnv", "/opt/homebrew/bin/direnv")])))

        // The evasion the audit found: payload staged under a colliding dir.
        // These must NOT match → rule still FIRES.
        #expect(!anyMatch(patterns, ancestorsBlob([("evil", "/Users/x/project/node_modules/.bin/evil"), ("zsh", "/bin/zsh")])),
                "a payload under /node_modules must not be exempted by the '/node' token")
        #expect(!anyMatch(patterns, ancestorsBlob([("run.sh", "/Users/x/Downloads/installer_payload/run.sh")])),
                "'installer_payload' dir must not be exempted by the 'installer' token")
        #expect(!anyMatch(patterns, ancestorsBlob([("clang", "/Library/Developer/SDKs/MacOSX.sdk/usr/bin/clang")])),
                "'/SDKs/' must not be exempted by the 'sdk' token")
        #expect(!anyMatch(patterns, ancestorsBlob([("taskgated", "/usr/libexec/taskgated")])),
                "'taskgated' must not be exempted by the 'task' token")
    }

    // MARK: - auth_brute_force interactive-terminal filter

    @Test("terminal filter exempts real terminals/multiplexers but NOT sshd/login or screensharingd")
    func authBruteForceBoundaries() throws {
        let patterns = try regexPatterns(inRuleAt: "Rules/credential_access/auth_brute_force.yml")
        #expect(patterns.count == 1, "expected 1 ProcessAncestors|re pattern (interactive terminal)")

        // Real interactive terminals / multiplexers → exempted (correct).
        #expect(anyMatch(patterns, ancestorsBlob([("Terminal", "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal")])))
        #expect(anyMatch(patterns, ancestorsBlob([("screen", "/usr/bin/screen")])))
        #expect(anyMatch(patterns, ancestorsBlob([("tmux", "/opt/homebrew/bin/tmux")])))

        // ABF-1: SSH / login must NOT be exempted (post-compromise primitive).
        #expect(!anyMatch(patterns, ancestorsBlob([("sshd", "/usr/sbin/sshd"), ("zsh", "/bin/zsh")])),
                "an sshd ancestor must no longer exempt a keychain/sudo primitive")
        #expect(!anyMatch(patterns, ancestorsBlob([("login", "/usr/bin/login"), ("zsh", "/bin/zsh")])),
                "a login ancestor must no longer exempt the rule")
        // ABF-1: '/screen' must not collide with screensharingd / ScreenFlow.
        #expect(!anyMatch(patterns, ancestorsBlob([("screensharingd", "/usr/libexec/screensharingd")])),
                "'screensharingd' must not match the 'screen' token")
        #expect(!anyMatch(patterns, ancestorsBlob([("ScreenFlow", "/Applications/ScreenFlow.app/Contents/MacOS/ScreenFlow")])))
    }
}
