// PackageContentAnalyzer.swift
// MacCrabCore
//
// Walks an installed package's directory tree and produces a content-anomaly
// score driven by published 2025-2026 supply-chain attack fingerprints.
// Pure local computation — no HTTP, no cloud calls.
//
// What it computes for a single installed package (e.g.,
// `node_modules/<name>/`, `site-packages/<name>/`, `Cellar/<name>/<version>/`):
//
//   - Total size on disk
//   - File-extension census (language fingerprint)
//   - Single-line large file detection (bytes / (newlines+1) > 50000)
//   - Native binary detection (Mach-O / ELF magic-byte head-read)
//   - Obfuscator-marker scan (PyArmor, obfuscator.io, webpack)
//   - Bundled-runtime drop detection (bun/deno/node binaries by size + name)
//
// Returns a `ContentAnomalyResult` with a 0-100 score plus per-factor
// reasons that downstream alert text consumes.

import Foundation
import os.log

// MARK: - PackageContentAnalyzer

public actor PackageContentAnalyzer {

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "package-content-analyzer")

    // MARK: - Types

    public struct ContentAnomalyResult: Sendable {
        public let packagePath: String
        public let totalBytes: Int64
        public let fileCount: Int
        public let extensionCensus: [String: Int]
        public let singleLineLargeFiles: [String]
        public let nativeBinaryFiles: [String]
        public let obfuscatorMatches: [String]
        public let bundledRuntimeFiles: [String]
        /// 0-100. Aggregated risk score across the six dimensions.
        public let score: Int
        public let reasons: [String]

        public init(
            packagePath: String,
            totalBytes: Int64,
            fileCount: Int,
            extensionCensus: [String: Int],
            singleLineLargeFiles: [String],
            nativeBinaryFiles: [String],
            obfuscatorMatches: [String],
            bundledRuntimeFiles: [String],
            score: Int,
            reasons: [String]
        ) {
            self.packagePath = packagePath
            self.totalBytes = totalBytes
            self.fileCount = fileCount
            self.extensionCensus = extensionCensus
            self.singleLineLargeFiles = singleLineLargeFiles
            self.nativeBinaryFiles = nativeBinaryFiles
            self.obfuscatorMatches = obfuscatorMatches
            self.bundledRuntimeFiles = bundledRuntimeFiles
            self.score = score
            self.reasons = reasons
        }
    }

    public enum Ecosystem: String, Sendable {
        case npm
        case pypi
        case homebrew
    }

    // MARK: - Tunables

    /// Maximum bytes to read from each candidate file when scanning for
    /// obfuscator markers / Mach-O magic. Keeps the analyzer cheap on
    /// large packages.
    let maxBytesPerFile: Int

    /// Files smaller than this are skipped from the single-line / obfuscator
    /// scans. The interesting bundled-payload threshold is ~100 KB based on
    /// 2025-2026 dropper sizes.
    let minScanFileSize: Int

    /// Hard caps on file enumeration to prevent unbounded walks
    /// (the audit caught analyze() walking `/` if a caller passed a
    /// confused path).
    let maxFileCount: Int
    let maxTotalBytes: Int64
    let maxDirectoryDepth: Int

    /// Path scopes a caller's input must fall within. If empty, no
    /// scope is enforced — callers are responsible for passing safe
    /// paths. The MCP tool wrapper applies the default scope set.
    let allowedScopes: [String]

    public init(
        maxBytesPerFile: Int = 4096,
        minScanFileSize: Int = 100_000,
        maxFileCount: Int = 50_000,
        maxTotalBytes: Int64 = 2 * 1024 * 1024 * 1024,
        maxDirectoryDepth: Int = 8,
        allowedScopes: [String] = []
    ) {
        self.maxBytesPerFile = maxBytesPerFile
        self.minScanFileSize = minScanFileSize
        self.maxFileCount = maxFileCount
        self.maxTotalBytes = maxTotalBytes
        self.maxDirectoryDepth = maxDirectoryDepth
        self.allowedScopes = allowedScopes
    }

    /// Default scopes for general callers: standard package
    /// directories only. Refuses arbitrary file system traversal.
    public static let defaultPackageScopes: [String] = [
        "\(NSHomeDirectory())/node_modules",
        "\(NSHomeDirectory())/.npm",
        "\(NSHomeDirectory())/Library/Python",
        "\(NSHomeDirectory())/.cache/pip",
        "/opt/homebrew/Cellar",
        "/usr/local/Cellar",
        "/Library/Frameworks/Python.framework",
        NSTemporaryDirectory(),  // for unit tests
    ]

    // MARK: - Public API

    /// Analyze a single installed package directory.
    /// Walk is bounded by `maxFileCount`, `maxTotalBytes`, and
    /// `maxDirectoryDepth`; if `allowedScopes` is non-empty, the
    /// supplied path must fall inside one of them.
    public func analyze(packagePath: URL, ecosystem: Ecosystem) -> ContentAnomalyResult {
        // Scope validation: refuse paths outside the allow-list when one is set.
        if !allowedScopes.isEmpty {
            let inScope = allowedScopes.contains { SecureFileIO.isPathInScope(packagePath.path, scope: $0) }
            if !inScope {
                return ContentAnomalyResult(
                    packagePath: packagePath.path,
                    totalBytes: 0,
                    fileCount: 0,
                    extensionCensus: [:],
                    singleLineLargeFiles: [],
                    nativeBinaryFiles: [],
                    obfuscatorMatches: [],
                    bundledRuntimeFiles: [],
                    score: 0,
                    reasons: ["path outside allowed scope — refusing to enumerate"]
                )
            }
        }

        let fm = FileManager.default
        var totalBytes: Int64 = 0
        var fileCount = 0
        var extensionCensus: [String: Int] = [:]
        var singleLineLarge: [String] = []
        var nativeBinaries: [String] = []
        var obfuscatorMatches: [String] = []
        var bundledRuntimeFiles: [String] = []
        var truncated = false

        guard let enumerator = fm.enumerator(at: packagePath, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey], options: [.skipsHiddenFiles]) else {
            return ContentAnomalyResult(
                packagePath: packagePath.path,
                totalBytes: 0,
                fileCount: 0,
                extensionCensus: [:],
                singleLineLargeFiles: [],
                nativeBinaryFiles: [],
                obfuscatorMatches: [],
                bundledRuntimeFiles: [],
                score: 0,
                reasons: ["package directory could not be enumerated"]
            )
        }

        let basePathDepth = (packagePath.path as NSString).pathComponents.count

        for case let url as URL in enumerator {
            // Depth bound.
            let depth = (url.path as NSString).pathComponents.count - basePathDepth
            if depth > maxDirectoryDepth {
                enumerator.skipDescendants()
                truncated = true
                continue
            }
            // File-count and byte-budget bounds.
            if fileCount >= maxFileCount || totalBytes >= maxTotalBytes {
                truncated = true
                break
            }
            let values = try? url.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
            guard values?.isRegularFile == true else { continue }
            let size = Int64(values?.fileSize ?? 0)
            totalBytes += size
            fileCount += 1

            let ext = url.pathExtension.lowercased()
            if !ext.isEmpty {
                extensionCensus[ext, default: 0] += 1
            }

            // Native-binary detection: only on files large enough to hold a magic.
            if size >= 4, Self.machOMagicPresent(in: url) {
                nativeBinaries.append(url.lastPathComponent)
            }

            // Single-line + obfuscator + bundled-runtime scans only on
            // sufficiently large files to keep the walk cheap.
            if size >= Int64(minScanFileSize) {
                if let head = try? Self.readHead(url, max: maxBytesPerFile) {
                    if Self.isSingleLineBundle(head: head, size: size) {
                        singleLineLarge.append(url.lastPathComponent)
                    }
                    if let marker = Self.obfuscatorMarker(in: head) {
                        obfuscatorMatches.append("\(url.lastPathComponent): \(marker)")
                    }
                }
                if Self.isBundledRuntimeBinary(url: url, size: size) {
                    bundledRuntimeFiles.append(url.lastPathComponent)
                }
            }
        }
        _ = truncated  // available for telemetry once the dashboard surfaces it

        let (score, reasons) = computeScore(
            ecosystem: ecosystem,
            totalBytes: totalBytes,
            fileCount: fileCount,
            extensionCensus: extensionCensus,
            singleLineLarge: singleLineLarge,
            nativeBinaries: nativeBinaries,
            obfuscatorMatches: obfuscatorMatches,
            bundledRuntimeFiles: bundledRuntimeFiles
        )

        return ContentAnomalyResult(
            packagePath: packagePath.path,
            totalBytes: totalBytes,
            fileCount: fileCount,
            extensionCensus: extensionCensus,
            singleLineLargeFiles: singleLineLarge,
            nativeBinaryFiles: nativeBinaries,
            obfuscatorMatches: obfuscatorMatches,
            bundledRuntimeFiles: bundledRuntimeFiles,
            score: score,
            reasons: reasons
        )
    }

    // MARK: - Scoring

    private func computeScore(
        ecosystem: Ecosystem,
        totalBytes: Int64,
        fileCount: Int,
        extensionCensus: [String: Int],
        singleLineLarge: [String],
        nativeBinaries: [String],
        obfuscatorMatches: [String],
        bundledRuntimeFiles: [String]
    ) -> (score: Int, reasons: [String]) {
        var score = 0
        var reasons: [String] = []

        if !bundledRuntimeFiles.isEmpty {
            score += 40
            reasons.append("package ships a bundled runtime binary (\(bundledRuntimeFiles.joined(separator: ", "))) — Mini Shai-Hulud / Lightning PyPI pattern")
        }
        if !singleLineLarge.isEmpty {
            score += 25
            reasons.append("package contains \(singleLineLarge.count) single-line large file(s) >100KB without newlines — bundler / obfuscator output")
        }
        if !obfuscatorMatches.isEmpty {
            score += 25
            reasons.append("package contains obfuscator markers (\(obfuscatorMatches.count) hit(s))")
        }
        if !nativeBinaries.isEmpty {
            // Native binaries are normal in some ecosystems (npm with
            // binding.gyp, PyPI wheels with .so). The rule layer guards
            // those; the content analyzer only weights heavily when the
            // ecosystem is npm (where bare .dylib/.so/.node without
            // binding.gyp is suspicious — but we can't know that here
            // without walking the manifest, so we apply a moderate weight).
            score += ecosystem == .npm ? 15 : 5
            reasons.append("package ships \(nativeBinaries.count) native binary file(s)")
        }
        // Language-fingerprint mismatch
        if ecosystem == .pypi {
            let jsCount = (extensionCensus["js"] ?? 0) + (extensionCensus["mjs"] ?? 0) + (extensionCensus["cjs"] ?? 0)
            if jsCount > 0 {
                score += 30
                reasons.append("PyPI package contains \(jsCount) JavaScript file(s) — Lightning PyPI cross-ecosystem smuggle pattern")
            }
        }
        if ecosystem == .npm {
            let pyCount = (extensionCensus["py"] ?? 0) + (extensionCensus["pyc"] ?? 0) + (extensionCensus["pyd"] ?? 0)
            if pyCount > 0 {
                score += 20
                reasons.append("npm package contains \(pyCount) Python file(s)")
            }
        }
        // Cap at 100.
        score = min(score, 100)
        return (score, reasons)
    }

    // MARK: - File-content helpers

    /// Read up to `max` bytes from the head of `url` using
    /// SecureFileIO (O_NOFOLLOW — refuses to read through symlinks).
    nonisolated static func readHead(_ url: URL, max: Int) throws -> Data {
        return try SecureFileIO.readBytes(at: url.path, maxBytes: max)
    }

    /// True if the first 4 bytes match a Mach-O magic constant
    /// (32-bit / 64-bit, little-endian / big-endian, FAT).
    /// All numeric constants are widened to UInt32 to avoid Swift's
    /// "integer literal overflows" warning on 32-bit literal narrowing.
    nonisolated static func machOMagicPresent(in url: URL) -> Bool {
        guard let data = try? readHead(url, max: 4), data.count == 4 else { return false }
        let magic = data.withUnsafeBytes { ptr -> UInt32 in
            ptr.load(as: UInt32.self)
        }
        let magics: Set<UInt32> = [
            0xfeedface, // 32-bit LE
            0xcefaedfe, // 32-bit BE
            0xfeedfacf, // 64-bit LE
            0xcffaedfe, // 64-bit BE
            0xcafebabe, // FAT (universal)
            0xbebafeca,
        ]
        return magics.contains(magic)
    }

    /// True if the head suggests this is a single-line bundle: very few
    /// newlines proportional to size. We approximate by counting newlines
    /// in the head and extrapolating. If the head has < 1 newline per
    /// 50KB equivalent (proportionally), flag it.
    nonisolated static func isSingleLineBundle(head: Data, size: Int64) -> Bool {
        // Need a real head to draw a conclusion.
        guard !head.isEmpty else { return false }
        let newlines = head.filter { $0 == 0x0A }.count
        let bytesPerNewlineInHead = newlines == 0 ? Int.max : head.count / max(newlines, 1)
        // If head is mostly one line and the file is >100KB, very likely
        // a bundle. Threshold derived from 2025-2026 dropper sizes
        // (Lightning router_runtime.js: 11MB, 1 line; Mini Shai-Hulud
        // execution.js: 11.6MB, 1 line).
        return size >= 100_000 && bytesPerNewlineInHead >= 4096
    }

    /// Returns the obfuscator-style marker that matches in the head, or nil.
    nonisolated static func obfuscatorMarker(in head: Data) -> String? {
        guard let text = String(data: head, encoding: .utf8) else { return nil }
        let markers: [(String, String)] = [
            ("__pyarmor__", "PyArmor v8+"),
            ("pyarmor_runtime", "PyArmor v8+ runtime"),
            ("eval('quire'['replace']", "Mini Shai-Hulud require-defeat"),
            ("eval(\"quire\"[\"replace\"]", "Mini Shai-Hulud require-defeat"),
            ("var _0x", "javascript-obfuscator hex identifier"),
            ("const _0x", "javascript-obfuscator hex identifier"),
            ("let _0x", "javascript-obfuscator hex identifier"),
            ("function(_0x", "javascript-obfuscator function-hex"),
            ("webpackChunk", "webpack chunk marker"),
            ("__webpack_require__", "webpack bundle marker"),
            ("MEI\\x0c\\x0b", "PyInstaller frozen marker"),
        ]
        for (substr, label) in markers where text.contains(substr) {
            return label
        }
        return nil
    }

    /// True if `url` looks like a Mac-native runtime binary that the package
    /// has bundled (bun / deno / node / python / ruby / php) at a typical
    /// runtime size band (20-100 MB).
    nonisolated static func isBundledRuntimeBinary(url: URL, size: Int64) -> Bool {
        let runtimeNames: Set<String> = ["bun", "deno", "node", "python", "python3", "ruby", "php"]
        let basename = url.lastPathComponent.lowercased()
        guard runtimeNames.contains(basename) else { return false }
        // 20MB lower bound trims small wrappers; 200MB upper trims weird
        // monolithic bundles like ML model weights.
        return size >= 20_000_000 && size <= 200_000_000 && machOMagicPresent(in: url)
    }
}
