import Foundation
import Testing
@testable import MacCrabCore

/// The root engine publishes metrics into world-writable /var/tmp. Every
/// such write must use the symlink-refusing atomic publisher; a fixed-name
/// temporary opened with ordinary create/truncate let any local user redirect
/// root's write onto an arbitrary file. Fixtures use a private sticky
/// directory; /var/tmp itself is never touched.
@Suite("Root metrics publication safety")
struct MetricsPublicationSafetyTests {
    @Test("the metrics publisher uses the symlink-refusing atomic writer")
    func metricsPublisherIsSymlinkSafe() throws {
        let source = try String(
            contentsOf: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift"),
            encoding: .utf8
        )
        let publisher = try #require(source.range(of: "at: \"/var/tmp/maccrab.metrics.json\""))
        let preceding = source[source.index(publisher.lowerBound, offsetBy: -200)..<publisher.lowerBound]
        #expect(preceding.contains("SecureFileIO.atomicReplace("))
        #expect(!source.contains("maccrab.metrics.json.tmp"))
        #expect(!source.contains("metricsTmp"))
    }

    @Test("a planted destination symlink in a sticky world-writable directory is refused")
    func plantedSymlinkIsRefused() throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("metrics-safety-\(UUID().uuidString)")
        let shared = root.appendingPathComponent("shared")
        try FileManager.default.createDirectory(at: shared, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try #require(chmod(shared.path, 0o1777) == 0)
        let victim = root.appendingPathComponent("victim.txt")
        try Data("original".utf8).write(to: victim)
        let destination = shared.appendingPathComponent("maccrab.metrics.json").path
        try FileManager.default.createSymbolicLink(atPath: destination, withDestinationPath: victim.path)

        #expect(throws: (any Error).self) {
            try SecureFileIO.atomicReplace(at: destination, data: Data("{}".utf8), mode: 0o644)
        }
        #expect(try String(contentsOf: victim, encoding: .utf8) == "original")
        let attributes = try FileManager.default.attributesOfItem(atPath: destination)
        #expect(attributes[.type] as? FileAttributeType == .typeSymbolicLink)

        // With no foreign entry the publication succeeds and replaces atomically.
        try FileManager.default.removeItem(atPath: destination)
        try SecureFileIO.atomicReplace(at: destination, data: Data("{\"a\":1}".utf8), mode: 0o644)
        try SecureFileIO.atomicReplace(at: destination, data: Data("{\"a\":2}".utf8), mode: 0o644)
        #expect(try String(contentsOfFile: destination, encoding: .utf8) == "{\"a\":2}")
    }
}
