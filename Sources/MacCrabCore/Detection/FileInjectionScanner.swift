// FileInjectionScanner.swift
// MacCrabCore
//
// Scans UTF-8 text files for hidden prompt-injection carriers using native
// structural analysis. EventLoop invokes it only after a completed write or an
// admitted read; CREATE/WRITE callbacks can observe incomplete content and must
// never poison the unchanged-file cache.

import Foundation
import os.log

/// Scans UTF-8 text files for invisible Unicode, bidi overrides, and Unicode
/// tag characters. This is not a PDF/Office parser and does not claim to find
/// image, archive, metadata, homoglyph, base64, or split-token obfuscation.
public actor FileInjectionScanner {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "file-injection")

    /// UTF-8 text types worth scanning. Binary document formats deliberately do
    /// not appear here: treating a failed UTF-8 decode of PDF/DOCX as a clean
    /// scan would be a false security claim.
    public nonisolated static let supportedExtensions: Set<String> = [
        "md", "txt", "py", "js", "ts", "swift", "go", "rs", "java", "c", "cpp", "h",
        "json", "yaml", "yml", "toml", "xml", "html", "css", "csv",
        "rtf",
        "sh", "bash", "zsh",
        "env", "config", "conf", "ini",
        "sql", "graphql",
        "jsx", "tsx", "vue", "svelte",
    ]

    /// Maximum file size to scan (5MB)
    static let maxFileSize: Int = 5 * 1024 * 1024

    /// Identity from the exact descriptor that supplied the scanned bytes.
    /// Device+inode+size+ctime means a same-path rewrite is scanned again even
    /// when it happens inside the former five-minute pathname TTL or restores
    /// the old mtime. A cache entry can suppress only the same stable snapshot.
    private struct SnapshotIdentity: Sendable, Equatable {
        let deviceID: UInt64
        let inodeNumber: UInt64
        let sizeBytes: Int64
        let statusChangeSeconds: Int64
        let statusChangeNanoseconds: Int64
    }

    private struct CacheEntry: Sendable {
        let identity: SnapshotIdentity
        let accessSequence: UInt64
    }

    private var scanCache: [String: CacheEntry] = [:]
    private var cacheAccessSequence: UInt64 = 0
    private let maxCacheSize = 500

    public struct ScanResult: Sendable {
        public let filePath: String
        public let isInjected: Bool
        public let confidence: Int  // 0-99
        public let threats: [String]
        public let severity: Severity
    }

    public init() {}

    /// Event-level contract shared with callback admission. `open` is the read
    /// event that reaches EventLoop; `close_modified` is the first callback that
    /// proves a write completed. Earlier CREATE/WRITE callbacks are ineligible.
    public nonisolated static func isEligible(path: String, eventAction: String) -> Bool {
        let action = eventAction.lowercased()
        guard action == "open" || action == "close_modified" else { return false }
        return isSupportedTextPath(path)
    }

    public nonisolated static func isSupportedTextPath(_ path: String) -> Bool {
        let name = (path as NSString).lastPathComponent.lowercased()
        let normalExtension = (name as NSString).pathExtension.lowercased()
        if supportedExtensions.contains(normalExtension) { return true }

        // NSString intentionally reports no extension for a leading-dot file.
        // Treat `.env` / `.config` / `.ini` as their declared text type.
        if name.first == ".", name.dropFirst().contains(".") == false {
            return supportedExtensions.contains(String(name.dropFirst()))
        }
        return false
    }

    /// Event-aware entry point used by the daemon. An ineligible callback does
    /// no filesystem work and, critically, cannot create a clean cache entry.
    public func scanFile(path: String, eventAction: String) async -> ScanResult? {
        guard Self.isEligible(path: path, eventAction: eventAction) else { return nil }
        return scanEligibleFile(path: path)
    }

    /// Scan a file for hidden prompt injection.
    /// Direct/manual entry point. Returns nil if the file should not be scanned,
    /// is unchanged since its last complete scan, or carries no supported signal.
    public func scanFile(path: String) async -> ScanResult? {
        guard Self.isSupportedTextPath(path) else { return nil }
        return scanEligibleFile(path: path)
    }

    private func scanEligibleFile(path: String) -> ScanResult? {
        // Read through the same descriptor that was proven regular and within
        // the cap. A path-based attributes check followed by
        // String(contentsOfFile:) let an attacker rename a validated small file
        // and replace it with a FIFO/device/oversized carrier before the open.
        guard case .success(let snapshot) = BoundedRegularFileReader.readOutcome(
                  at: path, maximumBytes: Self.maxFileSize
              ) else { return nil }

        let identity = SnapshotIdentity(
            deviceID: snapshot.deviceID,
            inodeNumber: snapshot.inodeNumber,
            sizeBytes: snapshot.sizeBytes,
            statusChangeSeconds: snapshot.statusChangeSeconds,
            statusChangeNanoseconds: snapshot.statusChangeNanoseconds
        )
        if scanCache[path]?.identity == identity {
            touchCache(path: path, identity: identity)
            return nil
        }

        guard !snapshot.data.isEmpty,
              let content = String(data: snapshot.data, encoding: .utf8) else { return nil }

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

        // Cache only after a complete, stable, UTF-8 snapshot was evaluated.
        // Carrier rejection and partial/failed reads remain eligible to retry.
        touchCache(path: path, identity: identity)

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

    private func touchCache(path: String, identity: SnapshotIdentity) {
        if cacheAccessSequence < UInt64.max {
            cacheAccessSequence += 1
        } else {
            // A lifetime boundary, not an ordinary hot-path case. Rebase the
            // tiny bounded cache instead of allowing LRU ordering to wrap.
            scanCache.removeAll(keepingCapacity: true)
            cacheAccessSequence = 1
        }
        scanCache[path] = CacheEntry(
            identity: identity,
            accessSequence: cacheAccessSequence
        )
        if scanCache.count > maxCacheSize {
            let oldest = scanCache.min { $0.value.accessSequence < $1.value.accessSequence }?.key
            if let oldest { scanCache.removeValue(forKey: oldest) }
        }
    }

}
