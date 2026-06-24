// CLIUsageParityTests.swift
// MacCrabCoreTests
//
// CLI-1: guards that every top-level command dispatched by maccrabctl is
// documented in `maccrabctl help`, and that the dev-only verbs (debug, mcfp,
// gated behind MACCRAB_DEV) stay OUT of the operator help. Source-derived
// (parses MacCrabCtl.swift's main() switch + Helpers.swift usageText) so it
// auto-catches drift — adding a dispatch case without a help entry fails CI.
// maccrabctl is an executable target (not importable), hence the source parse.

import Testing
import Foundation

@Suite("CLI usage parity")
struct CLIUsageParityTests {

    static func packageRoot() -> URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // package root
    }

    /// Top-level command labels in MacCrabCtl.main()'s `switch command`
    /// (exactly-8-space-indented `case "..."`), excluding nested sub-switches
    /// (which are more deeply indented).
    static func dispatchedCommands() throws -> Set<String> {
        let url = packageRoot().appendingPathComponent("Sources/maccrabctl/MacCrabCtl.swift")
        let src = try String(contentsOf: url, encoding: .utf8)
        guard let start = src.range(of: "switch command {"),
              let end = src.range(of: "// MARK: - trace dispatch") else {
            Issue.record("could not bound the main() switch in MacCrabCtl.swift")
            return []
        }
        let region = String(src[start.upperBound..<end.lowerBound])
        var cmds = Set<String>()
        for line in region.components(separatedBy: "\n") where line.hasPrefix("        case \"") {
            // pull every "quoted token" on the case line (handles `case "help", "-h":`)
            var rest = Substring(line)
            while let q1 = rest.firstIndex(of: "\"") {
                let after = rest.index(after: q1)
                guard let q2 = rest[after...].firstIndex(of: "\"") else { break }
                cmds.insert(String(rest[after..<q2]))
                rest = rest[rest.index(after: q2)...]
            }
        }
        return cmds
    }

    /// The triple-quoted help string from Helpers.usageText().
    static func usageText() throws -> String {
        let url = packageRoot().appendingPathComponent("Sources/maccrabctl/Helpers.swift")
        let src = try String(contentsOf: url, encoding: .utf8)
        guard let fn = src.range(of: "func usageText() -> String {"),
              let open = src.range(of: "\"\"\"", range: fn.upperBound..<src.endIndex),
              let close = src.range(of: "\"\"\"", range: open.upperBound..<src.endIndex) else {
            Issue.record("could not extract usageText() string from Helpers.swift")
            return ""
        }
        return String(src[open.upperBound..<close.lowerBound])
    }

    @Test("every dispatched top-level command (except dev-hidden) is documented in help")
    func allDispatchedCommandsDocumented() throws {
        let dispatched = try Self.dispatchedCommands()
        let help = try Self.usageText()
        // Token-boundary match (not raw substring): each command is listed as
        // the first word of an indented help line, so collect those leading
        // tokens. This avoids a short command (e.g. `rule`) false-passing on a
        // longer one's text (e.g. the `rules` lines).
        let helpTokens = Set(help.components(separatedBy: "\n").compactMap { line -> String? in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return nil }
            return String(trimmed.split(separator: " ").first ?? "")
        })
        let hidden: Set<String> = ["debug", "mcfp"]            // MACCRAB_DEV only (CLI-5)
        let aliasesAndMeta: Set<String> = ["case", "-h", "--help"]  // alias + flag forms of help
        #expect(!dispatched.isEmpty, "parsed zero dispatched commands — extraction broke")
        for cmd in dispatched.subtracting(hidden).subtracting(aliasesAndMeta) {
            #expect(helpTokens.contains(cmd),
                    "command '\(cmd)' is dispatched in MacCrabCtl.main() but not documented as a help line in `maccrabctl help` (CLI-1 parity — add it to Helpers.usageText)")
        }
    }

    @Test("dev-hidden commands stay out of the operator help")
    func hiddenCommandsAbsentFromHelp() throws {
        let help = try Self.usageText()
        #expect(!help.contains("debug"), "dev-only 'debug' leaked into operator help")
        #expect(!help.contains("mcfp"), "dev-only 'mcfp' leaked into operator help")
    }

    @Test("the hidden set is exactly {debug, mcfp}")
    func hiddenSetIsCanonical() throws {
        // Pins the gating decision so a new dev verb is a deliberate edit here.
        let url = Self.packageRoot().appendingPathComponent("Sources/maccrabctl/Helpers.swift")
        let src = try String(contentsOf: url, encoding: .utf8)
        #expect(src.contains("static let hiddenCommands: Set<String> = [\"debug\", \"mcfp\"]"),
                "hiddenCommands changed — update CLI-5 gating + this test deliberately")
    }
}
