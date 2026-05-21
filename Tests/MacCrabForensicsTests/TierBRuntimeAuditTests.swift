// Tier B runtime + manifest validation audit tests (audit-5..8).
//
// Covers the IPC + runtime + manifest hardening:
//   audit-5: bounded stdout read (DoS via huge response)
//   audit-6: artifact count + per-artifact size caps
//   audit-7: subprocess timeout
//   audit-8: manifest field validation + SBPL injection

import Testing
import Foundation
import CryptoKit
@testable import MacCrabForensics

@Suite("Tier B runtime hardening — audit-5..7")
struct TierBRuntimeAuditTests {

    static var fixtureBinaryPath: String? {
        let candidates = [
            ".build/debug/tier-b-fixture-plugin",
            ".build/release/tier-b-fixture-plugin",
        ]
        let fm = FileManager.default
        for c in candidates where fm.isExecutableFile(atPath: c) {
            return c
        }
        return nil
    }

    /// Compile a tiny Swift program emitting `body` to stdout after
    /// reading one line from stdin. Returns the path to the
    /// compiled binary.
    static func compileBomb(body: String) throws -> String {
        let id = UUID().uuidString
        let srcPath = "/tmp/maccrab-bomb-\(id).swift"
        let binPath = "/tmp/maccrab-bomb-\(id)"
        let source = """
        import Foundation
        setbuf(stdout, nil)
        _ = readLine(strippingNewline: true)
        \(body)
        """
        try source.write(toFile: srcPath, atomically: true, encoding: .utf8)
        let compile = Process()
        compile.executableURL = URL(fileURLWithPath: "/usr/bin/swiftc")
        compile.arguments = ["-O", srcPath, "-o", binPath]
        try compile.run()
        compile.waitUntilExit()
        return binPath
    }

    @Test("audit-5: response over maxResponseLineBytes terminates with error")
    func responseTooLargeRejected() async throws {
        // Build a bomb that emits 5MB without a newline. Configure
        // a low maxResponseLineBytes (1MB) so the bomb trips it.
        let bin = try Self.compileBomb(body: """
            let chunk = String(repeating: "A", count: 1024 * 1024)
            for _ in 0..<5 { FileHandle.standardOutput.write(Data(chunk.utf8)) }
            // Then send a valid response — we expect the loader
            // to reject before reaching this.
            FileHandle.standardOutput.write(Data("\\n{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"result\\":{\\"artifacts\\":[],\\"notes\\":[],\\"status\\":\\"ok\\"}}\\n".utf8))
            """)
        defer { try? FileManager.default.removeItem(atPath: bin) }
        let loader = TierBSubprocessLoader(limits: .init(
            maxResponseLineBytes: 1 * 1024 * 1024,
            subprocessTimeoutSeconds: 30
        ))
        do {
            _ = try await loader.runCollect(
                binaryPath: bin,
                caseID: "x",
                caseName: "x",
                encryptionState: "plaintext"
            )
            Issue.record("expected responseLineTooLarge or subprocessTimedOut")
        } catch TierBSubprocessLoader.LoaderError.responseLineTooLarge {
            // expected (fast bomb fills buffer before pipe stalls)
        } catch TierBSubprocessLoader.LoaderError.subprocessTimedOut {
            // also acceptable — pipe stalls before size trips
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("audit-6: artifact count over limit terminates with error")
    func artifactCountExceeded() async throws {
        let bin = try Self.compileBomb(body: """
            var arts: [String] = []
            for _ in 0..<200 {
                arts.append("{\\"content_type\\":\\"x\\",\\"sha256\\":\\"\\",\\"summary\\":\\"a\\",\\"confidence\\":\\"observed\\",\\"privacy_class\\":\\"metadata\\",\\"data_json\\":\\"{}\\"}")
            }
            let resp = "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"result\\":{\\"artifacts\\":[" + arts.joined(separator: ",") + "],\\"notes\\":[],\\"status\\":\\"ok\\"}}\\n"
            FileHandle.standardOutput.write(Data(resp.utf8))
            """)
        defer { try? FileManager.default.removeItem(atPath: bin) }
        // Low cap: 50 artifacts.
        let loader = TierBSubprocessLoader(limits: .init(
            maxArtifactsPerResponse: 50
        ))
        do {
            _ = try await loader.runCollect(
                binaryPath: bin,
                caseID: "x",
                caseName: "x",
                encryptionState: "plaintext"
            )
            Issue.record("expected artifactCountExceeded")
        } catch TierBSubprocessLoader.LoaderError.artifactCountExceeded {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("audit-6: per-artifact data over limit rejected")
    func artifactDataTooLarge() async throws {
        let bin = try Self.compileBomb(body: """
            let big = String(repeating: "x", count: 600_000)  // 600KB
            let resp = "{\\"jsonrpc\\":\\"2.0\\",\\"id\\":1,\\"result\\":{\\"artifacts\\":[{\\"content_type\\":\\"x\\",\\"sha256\\":\\"\\",\\"summary\\":\\"a\\",\\"confidence\\":\\"observed\\",\\"privacy_class\\":\\"metadata\\",\\"data_json\\":\\"" + big + "\\"}],\\"notes\\":[],\\"status\\":\\"ok\\"}}\\n"
            FileHandle.standardOutput.write(Data(resp.utf8))
            """)
        defer { try? FileManager.default.removeItem(atPath: bin) }
        let loader = TierBSubprocessLoader(limits: .init(
            maxArtifactDataBytes: 100_000  // 100KB
        ))
        do {
            _ = try await loader.runCollect(
                binaryPath: bin,
                caseID: "x",
                caseName: "x",
                encryptionState: "plaintext"
            )
            Issue.record("expected artifactDataTooLarge")
        } catch TierBSubprocessLoader.LoaderError.artifactDataTooLarge {
            // expected
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }

    @Test("audit-7: subprocess that never responds hits timeout")
    func subprocessTimeoutFires() async throws {
        let bin = try Self.compileBomb(body: """
            // Drop into a wait-forever after reading the request.
            // Block on stdin with no further writes.
            while readLine(strippingNewline: true) != nil { /* ignore */ }
            """)
        defer { try? FileManager.default.removeItem(atPath: bin) }
        let loader = TierBSubprocessLoader(limits: .init(
            subprocessTimeoutSeconds: 2  // 2 second timeout for tests
        ))
        let start = Date()
        do {
            _ = try await loader.runCollect(
                binaryPath: bin,
                caseID: "x",
                caseName: "x",
                encryptionState: "plaintext"
            )
            Issue.record("expected subprocessTimedOut")
        } catch TierBSubprocessLoader.LoaderError.subprocessTimedOut {
            let elapsed = Date().timeIntervalSince(start)
            // Upper bound is loose because parallel test
            // execution adds scheduling jitter — the deadline
            // is 2s but the task scheduler may not fire promptly.
            // Lower bound is the real assertion: must wait at
            // least the configured timeout before throwing.
            #expect(elapsed >= 2.0)
            #expect(elapsed < 30.0)
        } catch {
            Issue.record("got unexpected error: \(error)")
        }
    }
}

@Suite("Tier B manifest hardening — audit-8")
struct TierBManifestAuditTests {

    @Test("audit-8: displayName with ANSI escape rejected")
    func ansiDisplayNameRejected() {
        let manifest: [String: Any] = [
            "id": "com.test.ansi",
            "displayName": "x\u{001B}[2J",
            "version": "1",
            "schemaVersion": 1,
            "description": "x",
        ]
        #expect(throws: PluginInstaller.InstallError.self) {
            try PluginInstaller.validateManifest(manifest)
        }
    }

    @Test("audit-8: newline in fileReadSubpaths entry rejected")
    func sbplInjectionRejected() {
        let manifest: [String: Any] = [
            "id": "com.test.sbpl",
            "displayName": "x",
            "version": "1",
            "schemaVersion": 1,
            "description": "x",
            "fileReadSubpaths": ["/tmp\n(allow file-read* (subpath \"/etc"],
        ]
        #expect(throws: PluginInstaller.InstallError.self) {
            try PluginInstaller.validateManifest(manifest)
        }
    }

    @Test("audit-8: relative path in fileReadSubpaths rejected")
    func relativePathRejected() {
        let manifest: [String: Any] = [
            "id": "com.test.rel",
            "displayName": "x",
            "version": "1",
            "schemaVersion": 1,
            "description": "x",
            "fileReadSubpaths": ["relative/path"],
        ]
        #expect(throws: PluginInstaller.InstallError.self) {
            try PluginInstaller.validateManifest(manifest)
        }
    }

    @Test("audit-8: '..' segment in fileReadSubpaths rejected")
    func dotDotPathRejected() {
        let manifest: [String: Any] = [
            "id": "com.test.dotdot",
            "displayName": "x",
            "version": "1",
            "schemaVersion": 1,
            "description": "x",
            "fileReadSubpaths": ["/usr/../etc"],
        ]
        #expect(throws: PluginInstaller.InstallError.self) {
            try PluginInstaller.validateManifest(manifest)
        }
    }

    @Test("audit-8: over-long description rejected")
    func longDescriptionRejected() {
        let manifest: [String: Any] = [
            "id": "com.test.long",
            "displayName": "x",
            "version": "1",
            "schemaVersion": 1,
            "description": String(repeating: "A", count: 2000),
        ]
        #expect(throws: PluginInstaller.InstallError.self) {
            try PluginInstaller.validateManifest(manifest)
        }
    }

    @Test("audit-8: legit manifest validates")
    func legitManifestAccepted() throws {
        let manifest: [String: Any] = [
            "id": "com.test.legit",
            "displayName": "My Plugin",
            "version": "1.0.0",
            "schemaVersion": 1,
            "description": "A normal plugin",
            "fileReadSubpaths": ["/tmp", "/private/etc"],
            "fileWriteSubpaths": [],
            "networkConnectAllowlist": [],
        ]
        try PluginInstaller.validateManifest(manifest)
    }

    @Test("audit-8: SBPL quoted() strips control chars from path strings")
    func sbplQuoteStripsControls() {
        // Even if validation is bypassed (defense in depth) the
        // SandboxProfileBuilder's quoted() helper strips control
        // chars so an injected newline can't break the literal.
        let spec = SandboxProfileSpec(
            allowAllByDefault: false,
            fileReadSubpaths: ["/tmp\")\n(allow file-read* (subpath \"/etc"]
        )
        let out = SandboxProfileBuilder.compile(spec)
        // Newline inside the literal should not survive — it'd
        // get rewritten to a space.
        #expect(!out.contains("\")\n(allow file-read* (subpath \"/etc"))
    }
}
