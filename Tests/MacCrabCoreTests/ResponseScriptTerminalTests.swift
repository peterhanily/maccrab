import Foundation
import Testing
@testable import MacCrabCore

/// A response script runs as `/bin/sh -- <script>`: its path is an argument,
/// never command text. A command in it that prompts on /dev/tty stops on the
/// engine's private terminal until the script's deadline; ignoring SIGTTIN and
/// SIGTTOU instead made readpassphrase(3) spin at full CPU, so it is not done.
@Suite("Response scripts run with their path as an argument")
struct ResponseScriptTerminalTests {
    @Test("a script path is passed as an argument, never as command text")
    func scriptPathIsNotParsed() throws {
        let dir = NSTemporaryDirectory() + "response-tty-\(UUID().uuidString)"
        let odd = dir + "/odd; touch injected $(echo x)"
        try FileManager.default.createDirectory(atPath: odd, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let script = odd + "/-respond.sh"
        try "echo ran\n".write(toFile: script, atomically: true, encoding: .utf8)
        let result = try #require(BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ["--", script],
            workingDirectory: dir,
            timeout: 10,
            maximumOutputBytes: 4_096
        ))
        #expect(result.terminationStatus == 0)
        #expect(String(decoding: result.output, as: UTF8.self) == "ran\n")
        #expect(!FileManager.default.fileExists(atPath: dir + "/injected"))
    }

    @Test("the engine runs response scripts with exactly those arguments, and no signal trap")
    func runScriptUsesTheArguments() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Detection/ResponseAction.swift"),
            encoding: .utf8)
        #expect(source.contains("arguments: [\"--\", trustedScript],"))
        #expect(!source.contains("trap '' TTIN TTOU"), "readpassphrase(3) spins under an ignored SIGTTIN")
    }
}
