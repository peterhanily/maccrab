import Foundation
import Testing
@testable import MacCrabCore

/// The engine holds a private controlling terminal, and a response script's
/// shell sits in a background process group on it. A command that reads or
/// configures /dev/tty there would be stopped by SIGTTIN or SIGTTOU until the
/// script's deadline; the script runs with both ignored so it fails at once.
@Suite("Response scripts are never stopped by the engine's terminal")
struct ResponseScriptTerminalTests {
    @Test("a script and the commands it starts ignore SIGTTIN and SIGTTOU")
    func scriptIgnoresTerminalStops() throws {
        let dir = NSTemporaryDirectory() + "response-tty-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let script = dir + "/respond.sh"
        // The signals a background read or tcsetattr of the terminal raises,
        // sent directly: each would stop its shell were it not ignored.
        try """
            kill -TTIN $$
            /bin/sh -c 'kill -TTOU $$; echo child-survived'
            echo script-survived

            """.write(toFile: script, atomically: true, encoding: .utf8)
        let result = try #require(BoundedPrivilegedProcessRunner.run(
            executable: "/bin/sh",
            arguments: ResponseEngine.scriptArguments(script),
            timeout: 10,
            maximumOutputBytes: 4_096
        ))
        let output = String(decoding: result.output, as: UTF8.self)
        #expect(!result.timedOut, "the script was stopped and held until its deadline")
        #expect(result.terminationStatus == 0)
        #expect(output.contains("child-survived") && output.contains("script-survived"), "\(output)")
    }

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
            arguments: ResponseEngine.scriptArguments(script),
            workingDirectory: dir,
            timeout: 10,
            maximumOutputBytes: 4_096
        ))
        #expect(result.terminationStatus == 0)
        #expect(String(decoding: result.output, as: UTF8.self) == "ran\n")
        #expect(!FileManager.default.fileExists(atPath: dir + "/injected"))
    }

    @Test("the engine runs response scripts through those arguments")
    func runScriptUsesTheArguments() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let source = try String(
            contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Detection/ResponseAction.swift"),
            encoding: .utf8)
        #expect(source.contains("arguments: Self.scriptArguments(trustedScript),"))
        #expect(!source.contains("arguments: [\"--\", trustedScript]"))
    }
}
