// FileInjectionScanner.swift
// MacCrabCore
//
// Scans files for hidden prompt injection using native structural analysis.
// When an AI tool reads or writes a file, this scanner catches prompt injection
// hidden in documents BEFORE the LLM processes them — invisible unicode,
// metadata injection, hidden text, bidi overrides, and zero-width binary encoding.

import Foundation
import os.log

/// Scans files for hidden prompt injection using native structural analysis.
/// Detects invisible unicode, metadata injection, hidden text, bidi overrides,
/// and zero-width binary encoding in files that AI tools access.
public actor FileInjectionScanner {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "file-injection")

    /// File types worth scanning (documents AI tools commonly read)
    private static let scannableExtensions: Set<String> = [
        "md", "txt", "py", "js", "ts", "swift", "go", "rs", "java", "c", "cpp", "h",
        "json", "yaml", "yml", "toml", "xml", "html", "css", "csv",
        "pdf", "docx", "doc", "rtf",
        "sh", "bash", "zsh",
        "env", "config", "conf", "ini",
        "sql", "graphql",
        "jsx", "tsx", "vue", "svelte",
    ]

    /// Maximum file size to scan (5MB)
    static let maxFileSize: Int = 5 * 1024 * 1024

    /// Cache of recently scanned files (path -> timestamp) to avoid re-scanning
    private var scanCache: [String: Date] = [:]
    private let cacheDuration: TimeInterval = 300  // 5 minutes
    private let maxCacheSize = 500

    public struct ScanResult: Sendable {
        public let filePath: String
        public let isInjected: Bool
        public let confidence: Int  // 0-99
        public let threats: [String]
        public let severity: Severity
    }

    public init() {}

    /// Scan a file for hidden prompt injection.
    /// Returns nil if the file shouldn't be scanned (wrong type, too large, cached).
    public func scanFile(path: String) async -> ScanResult? {
        // Check extension
        let ext = (path as NSString).pathExtension.lowercased()
        guard Self.scannableExtensions.contains(ext) else { return nil }

        // Check cache
        if let lastScan = scanCache[path],
           Date().timeIntervalSince(lastScan) < cacheDuration {
            return nil  // Recently scanned
        }

        // Read through the same descriptor that was proven regular and within
        // the cap. A path-based attributes check followed by
        // String(contentsOfFile:) let an attacker rename a validated small file
        // and replace it with a FIFO/device/oversized carrier before the open.
        guard let data = BoundedRegularFileReader.read(
                  at: path,
                  maximumBytes: Self.maxFileSize
              ),
              !data.isEmpty,
              let content = String(data: data, encoding: .utf8) else { return nil }

        // Native structural checks. These used to sit behind a
        // `guard isAvailable else { return nil }` that probed for an external
        // `forensicate` CLI — a package that does not exist on PyPI under any
        // name — so all three of these correct, self-contained detections were
        // unreachable on every install. They are now the whole scanner.
        var quickThreats: [String] = []

        // Check for invisible unicode (zero-width chars)
        let invisibleScalars: Set<UInt32> = [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064]
        let invisibleCount = content.unicodeScalars.filter { invisibleScalars.contains($0.value) }.count
        if invisibleCount >= 3 {
            quickThreats.append("invisible-unicode: \(invisibleCount) zero-width characters detected")
        }

        // Check for bidi overrides (Trojan Source)
        let bidiScalars: Set<UInt32> = [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
        let bidiCount = content.unicodeScalars.filter { bidiScalars.contains($0.value) }.count
        if bidiCount > 0 {
            quickThreats.append("bidi-override: \(bidiCount) bidirectional control characters (Trojan Source)")
        }

        // Check for tag characters (U+E0000-E007F range for ASCII smuggling)
        let hasTagChars = content.unicodeScalars.contains { $0.value >= 0xE0000 && $0.value <= 0xE007F }
        if hasTagChars {
            quickThreats.append("tag-chars: Unicode tag characters detected (ASCII smuggling)")
        }

        // Update cache
        scanCache[path] = Date()
        if scanCache.count > maxCacheSize {
            let oldest = scanCache.sorted { $0.value < $1.value }.prefix(100).map(\.key)
            for key in oldest { scanCache.removeValue(forKey: key) }
        }

        guard !quickThreats.isEmpty else { return nil }

        // Confidence scales with how many independent structural signals agree.
        // Tag chars and bidi overrides have no legitimate use in these file types,
        // so two or more concurrent signals is a strong result.
        let confidence = quickThreats.count > 2 ? 80 : (quickThreats.count > 1 ? 65 : 50)
        let severity: Severity = confidence >= 80 ? .critical : confidence >= 50 ? .high : .medium

        logger.warning("File injection detected in \(path): \(quickThreats.joined(separator: "; "))")

        return ScanResult(
            filePath: path,
            isInjected: true,
            confidence: confidence,
            threats: quickThreats,
            severity: severity
        )
    }

}
