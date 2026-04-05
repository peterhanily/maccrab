// FileInjectionScanner.swift
// MacCrabCore
//
// Scans files for hidden prompt injection using forensicate's file analysis.
// When an AI tool reads or writes a file, this scanner catches prompt injection
// hidden in documents BEFORE the LLM processes them — invisible unicode,
// metadata injection, hidden text, bidi overrides, and zero-width binary encoding.

import Foundation
import os.log

/// Scans files for hidden prompt injection using forensicate's file analysis.
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
    private let maxFileSize: Int = 5 * 1024 * 1024

    /// Cache of recently scanned files (path -> timestamp) to avoid re-scanning
    private var scanCache: [String: Date] = [:]
    private let cacheDuration: TimeInterval = 300  // 5 minutes
    private let maxCacheSize = 500

    /// Whether forensicate is available
    public let isAvailable: Bool

    public struct ScanResult: Sendable {
        public let filePath: String
        public let isInjected: Bool
        public let confidence: Int  // 0-99
        public let threats: [String]
        public let severity: Severity
    }

    public init() {
        // Check if forensicate CLI is available
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/which")
        proc.arguments = ["forensicate"]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice
        try? proc.run()
        proc.waitUntilExit()
        self.isAvailable = proc.terminationStatus == 0
    }

    /// Scan a file for hidden prompt injection.
    /// Returns nil if file shouldn't be scanned (wrong type, too large, cached, forensicate unavailable).
    public func scanFile(path: String) async -> ScanResult? {
        guard isAvailable else { return nil }

        // Check extension
        let ext = (path as NSString).pathExtension.lowercased()
        guard Self.scannableExtensions.contains(ext) else { return nil }

        // Check cache
        if let lastScan = scanCache[path],
           Date().timeIntervalSince(lastScan) < cacheDuration {
            return nil  // Recently scanned
        }

        // Check file size
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path),
              let size = attrs[.size] as? Int,
              size > 0, size <= maxFileSize else { return nil }

        // Read file content
        guard let content = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }

        // Quick pre-checks before shelling out to forensicate
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

        // Shell out to forensicate for full scan
        let forensicateResult = await runForensicate(content: content)
        if let result = forensicateResult {
            quickThreats.append(contentsOf: result.threats)
        }

        // Update cache
        scanCache[path] = Date()
        if scanCache.count > maxCacheSize {
            let oldest = scanCache.sorted { $0.value < $1.value }.prefix(100).map(\.key)
            for key in oldest { scanCache.removeValue(forKey: key) }
        }

        guard !quickThreats.isEmpty else { return nil }

        let confidence = forensicateResult?.confidence ?? (quickThreats.count > 2 ? 80 : 50)
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

    private struct ForensicateOutput: Sendable {
        let confidence: Int
        let threats: [String]
    }

    private func runForensicate(content: String) async -> ForensicateOutput? {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        proc.arguments = ["forensicate", "--json", "--threshold", "30"]

        let inputPipe = Pipe()
        let outputPipe = Pipe()
        proc.standardInput = inputPipe
        proc.standardOutput = outputPipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            // Write content to stdin (truncate to 50KB for performance)
            let truncated = String(content.prefix(50_000))
            inputPipe.fileHandleForWriting.write(truncated.data(using: .utf8) ?? Data())
            inputPipe.fileHandleForWriting.closeFile()

            // Timeout: kill after 5 seconds
            let deadline = DispatchTime.now() + 5
            DispatchQueue.global().asyncAfter(deadline: deadline) {
                if proc.isRunning { proc.terminate() }
            }

            proc.waitUntilExit()

            let outputData = outputPipe.fileHandleForReading.readDataToEndOfFile()
            guard let json = try? JSONSerialization.jsonObject(with: outputData) as? [String: Any] else {
                return nil
            }

            let confidence = json["confidence"] as? Int ?? 0
            let matches = json["matches"] as? [[String: Any]] ?? []
            let threats = matches.compactMap { match -> String? in
                guard let rule = match["rule"] as? String,
                      let category = match["category"] as? String else { return nil }
                return "\(category): \(rule)"
            }

            guard confidence > 0 else { return nil }
            return ForensicateOutput(confidence: confidence, threats: threats)
        } catch {
            return nil
        }
    }
}
