// CLIFormatSafetyTests.swift
// P0-2 guard. `String(format: "…%s…", swiftString)` feeds a Swift String object
// pointer to C `strlen()` → SIGSEGV. Three shipping maccrabctl commands
// (tree-score / rules list / cdhash --all) crashed every invocation this way on
// the signed binary, with no test to catch it. The codebase convention is `%@`
// plus `.padding(toLength:withPad:startingAt:)`. This guard fails the build if a
// C `%s` specifier reappears in any maccrabctl String(format:) call.
import Testing
import Foundation

@Suite("maccrabctl format-string safety (SIGSEGV regression guard)")
struct CLIFormatSafetyTests {

    @Test("no String(format:) in maccrabctl uses a C %s specifier")
    func noCStringSpecifier() throws {
        let cliDir = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // repo root
            .appendingPathComponent("Sources/maccrabctl")
        let files = try FileManager.default
            .contentsOfDirectory(at: cliDir, includingPropertiesForKeys: nil)
            .filter { $0.pathExtension == "swift" }
        #expect(files.count > 5, "expected the maccrabctl sources")

        // %s, optionally with flags/width (e.g. %-8s, %5s). %@ / %d / %f are fine.
        let specifier = try NSRegularExpression(pattern: #"%[-+ 0-9.]*s"#)
        var offenders: [String] = []
        for f in files {
            let src = try String(contentsOf: f, encoding: .utf8)
            for (i, raw) in src.components(separatedBy: "\n").enumerated() {
                // Strip line comments so the documented footgun warning in
                // TraceCommands.swift (a `// String(format: %s) …` note) isn't flagged.
                let code = raw.components(separatedBy: "//").first ?? raw
                guard code.contains("format:") else { continue }
                let r = NSRange(code.startIndex..., in: code)
                if specifier.firstMatch(in: code, range: r) != nil {
                    offenders.append("\(f.lastPathComponent):\(i + 1)  \(raw.trimmingCharacters(in: .whitespaces))")
                }
            }
        }
        let detail = offenders.joined(separator: " | ")
        #expect(offenders.isEmpty,
                "String(format:) with a C %s specifier SIGSEGVs on a Swift String — use %@ + .padding(): \(detail)")
    }
}
