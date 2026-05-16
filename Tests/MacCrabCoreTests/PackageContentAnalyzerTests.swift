// PackageContentAnalyzerTests.swift
// v1.12.0 — Walks an on-disk package tree and scores content anomalies.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.12.0: PackageContentAnalyzer")
struct PackageContentAnalyzerTests {

    // MARK: - Helpers

    private func makeTempPackage(_ name: String, files: [(String, Data)]) throws -> URL {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-content-\(UUID().uuidString)")
            .appendingPathComponent(name)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        for (relPath, data) in files {
            let full = tmp.appendingPathComponent(relPath)
            try FileManager.default.createDirectory(
                at: full.deletingLastPathComponent(), withIntermediateDirectories: true
            )
            try data.write(to: full)
        }
        return tmp
    }

    // MARK: - Tests

    @Test("Mach-O magic bytes at file head are detected")
    func machOMagicDetection() throws {
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-macho-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        // 64-bit Mach-O LE magic: 0xfeedfacf
        var bytes: [UInt8] = [0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01]
        let url = tmp.appendingPathComponent("test_macho")
        try Data(bytes).write(to: url)
        #expect(PackageContentAnalyzer.machOMagicPresent(in: url))

        // A plain text file should NOT match.
        bytes = Array("not a macho".utf8)
        let textURL = tmp.appendingPathComponent("text")
        try Data(bytes).write(to: textURL)
        #expect(!PackageContentAnalyzer.machOMagicPresent(in: textURL))
    }

    @Test("Obfuscator marker scanner finds PyArmor + Mini Shai-Hulud + obfuscator.io patterns")
    func obfuscatorMarkers() {
        let pyArmor = "__pyarmor__".data(using: .utf8)!
        let miniShaiHulud = "eval('quire'['replace'](/^/, 're'))()".data(using: .utf8)!
        let obfHex = "var _0x4a3b2c = ['secret','exfil'];".data(using: .utf8)!
        let webpackBundle = "(function(modules){__webpack_require__(0)})".data(using: .utf8)!
        let benign = "module.exports = function() { return 42; }".data(using: .utf8)!

        #expect(PackageContentAnalyzer.obfuscatorMarker(in: pyArmor) != nil)
        #expect(PackageContentAnalyzer.obfuscatorMarker(in: miniShaiHulud) != nil)
        #expect(PackageContentAnalyzer.obfuscatorMarker(in: obfHex) != nil)
        #expect(PackageContentAnalyzer.obfuscatorMarker(in: webpackBundle) != nil)
        #expect(PackageContentAnalyzer.obfuscatorMarker(in: benign) == nil)
    }

    @Test("Single-line bundle detection trips on >100KB file with no newlines")
    func singleLineBundleDetection() {
        // 4KB head with zero newlines.
        let head = Data(repeating: 0x41, count: 4096)
        #expect(PackageContentAnalyzer.isSingleLineBundle(head: head, size: 5_000_000))
        // A normal multi-line file (many newlines) is not flagged.
        var multiline = Data()
        for _ in 0..<4096 { multiline.append(contentsOf: [0x41, 0x0A]) }
        #expect(!PackageContentAnalyzer.isSingleLineBundle(head: multiline, size: 5_000_000))
        // Small file (under 100KB) is not flagged regardless.
        #expect(!PackageContentAnalyzer.isSingleLineBundle(head: head, size: 4096))
    }

    @Test("PyPI package containing .js file scores higher (Lightning PyPI pattern)")
    func pypiCrossEcosystemMismatch() async throws {
        let pkg = try makeTempPackage("lightning_canary", files: [
            ("__init__.py", "# pure python".data(using: .utf8)!),
            ("_runtime/router_runtime.js", Data(repeating: 0x41, count: 200_000)),
        ])
        defer { try? FileManager.default.removeItem(at: pkg.deletingLastPathComponent()) }
        let analyzer = PackageContentAnalyzer()
        let result = await analyzer.analyze(packagePath: pkg, ecosystem: .pypi)
        #expect(result.score >= 30, "PyPI + .js should score high; got \(result.score)")
        #expect(result.reasons.contains(where: { $0.contains("JavaScript") }))
    }

    @Test("npm package with no anomalies scores 0")
    func cleanNpmPackage() async throws {
        let pkg = try makeTempPackage("happy_path", files: [
            ("package.json", "{\"name\":\"happy_path\",\"version\":\"1.0.0\"}".data(using: .utf8)!),
            ("index.js", "module.exports = {};\n".data(using: .utf8)!),
            ("README.md", "# happy path\n\nA simple module.\n".data(using: .utf8)!),
        ])
        defer { try? FileManager.default.removeItem(at: pkg.deletingLastPathComponent()) }
        let analyzer = PackageContentAnalyzer()
        let result = await analyzer.analyze(packagePath: pkg, ecosystem: .npm)
        #expect(result.score == 0)
        #expect(result.reasons.isEmpty)
    }

    @Test("npm package containing an obfuscated single-line bundle scores high")
    func npmObfuscatedBundle() async throws {
        let bundlePayload = "var _0x4a3b2c = [" + Array(repeating: "'a',", count: 30000).joined() + "'end'];"
        let pkg = try makeTempPackage("evil_pkg", files: [
            ("package.json", "{\"name\":\"evil_pkg\",\"version\":\"99.0.0\"}".data(using: .utf8)!),
            ("dist/bundle.js", bundlePayload.data(using: .utf8)!),
        ])
        defer { try? FileManager.default.removeItem(at: pkg.deletingLastPathComponent()) }
        let analyzer = PackageContentAnalyzer()
        let result = await analyzer.analyze(packagePath: pkg, ecosystem: .npm)
        #expect(result.score >= 25, "obfuscated bundle should score moderately; got \(result.score)")
        #expect(result.obfuscatorMatches.count == 1)
    }
}
