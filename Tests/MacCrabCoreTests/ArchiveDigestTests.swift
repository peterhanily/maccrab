// ArchiveDigestTests.swift
// v1.21.5 Phase 2c — outer-archive sidecar digest helper.
//
// The formatting + hashing lives in MacCrabCore (ArchiveDigest) so it
// is testable; `maccrabctl trace export` (executable target) only
// wires it up after tar.gz packaging.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("TraceGraph: ArchiveDigest sidecar")
struct ArchiveDigestTests {

    private func makeScratchFile(contents: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("archdig-\(UUID().uuidString).tar.gz")
        try contents.write(to: url, atomically: true, encoding: .utf8)
        return url
    }

    @Test("sha256Hex matches the NIST known-answer vector for \"abc\"")
    func knownVector() throws {
        let url = try makeScratchFile(contents: "abc")
        defer { try? FileManager.default.removeItem(at: url) }
        let hex = ArchiveDigest.sha256Hex(of: url)
        #expect(hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    }

    @Test("sha256Hex returns nil for a missing file")
    func missingFileIsNil() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("archdig-missing-\(UUID().uuidString)")
        #expect(ArchiveDigest.sha256Hex(of: url) == nil)
    }

    @Test("sidecarLine is shasum -a 256 compatible: <64-hex>  <name>\\n")
    func sidecarLineFormat() {
        let hex = String(repeating: "ab", count: 32)
        let line = ArchiveDigest.sidecarLine(hex: hex, fileName: "foo.maccrabtrace.tar.gz")
        #expect(line == "\(hex)  foo.maccrabtrace.tar.gz\n")
        // Exactly two spaces between digest and name; trailing newline.
        #expect(line.range(of: "^[0-9a-f]{64}  [^ ]+\n$", options: .regularExpression) != nil)
    }

    @Test("writeSidecar output matches /usr/bin/shasum -a 256 end-to-end")
    func sidecarMatchesShasum() throws {
        let url = try makeScratchFile(contents: "maccrab sidecar digest sanity\n")
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try #require(ArchiveDigest.writeSidecar(forArchiveAt: url))
        defer { try? FileManager.default.removeItem(at: result.sidecar) }
        #expect(result.sidecar.path == url.path + ".sha256")

        // Run the real shasum in the file's directory so its printed
        // name is the bare filename, same as the sidecar's.
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/shasum")
        proc.currentDirectoryURL = url.deletingLastPathComponent()
        proc.arguments = ["-a", "256", url.lastPathComponent]
        let pipe = Pipe()
        proc.standardOutput = pipe
        try proc.run()
        proc.waitUntilExit()
        #expect(proc.terminationStatus == 0)
        let shasumLine = String(
            data: pipe.fileHandleForReading.readDataToEndOfFile(),
            encoding: .utf8
        ) ?? ""

        let sidecarContents = try String(contentsOf: result.sidecar, encoding: .utf8)
        #expect(sidecarContents == shasumLine)
        #expect(sidecarContents.hasPrefix(result.hex + "  "))
    }
}
