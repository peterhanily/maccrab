// FileInjectionScanner.swift
// MacCrabCore
//
// Scans UTF-8 text files for hidden prompt-injection carriers using native
// structural analysis. EventLoop invokes it only after a completed write or an
// admitted read; CREATE/WRITE callbacks can observe incomplete content and must
// never poison the unchanged-file cache.

import Foundation
import os.log

/// Scans UTF-8 text files for suspicious invisible Unicode, bidi overrides, and
/// Unicode tags outside supported emoji sequences. Findings identify structural
/// carriers, not malicious intent. This is not a PDF/Office parser or a detector of
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
        /// Compatibility name: true means suspicious structure was found, not
        /// that prompt injection or malicious intent has been confirmed.
        public let isInjected: Bool
        public let confidence: Int  // Uncalibrated heuristic score, not a probability.
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

    /// Scan a file for possible hidden-text carriers.
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

        // Unicode controls also carry ordinary emoji and multilingual text.
        // Exempt their bounded, recognized contexts before counting signals.
        var quickThreats: [String] = []
        let scalars = content.unicodeScalars
        var invisibleCount = 0
        var bidiCount = 0
        var tagCount = 0
        // false = embedding, true = isolate. This is a bounded pairing check,
        // not an implementation of the Unicode bidirectional display algorithm.
        var bidiStack: [Bool] = []
        var index = scalars.startIndex
        while index < scalars.endIndex {
            let value = scalars[index].value
            if value == 0x1F3F4, let end = Self.flagTagEnd(in: scalars, at: index) {
                index = end
                continue
            }
            switch value {
            case 0x200C, 0x200D:
                if !(value == 0x200D && Self.isEmojiJoiner(in: scalars, at: index)),
                   !Self.isShapingJoiner(in: scalars, at: index) {
                    invisibleCount += 1
                }
            case 0xFEFF:
                if index != scalars.startIndex { invisibleCount += 1 }
            case 0x200B, 0x2060...0x2064:
                invisibleCount += 1
            case 0x202A, 0x202B, 0x202D, 0x202E, 0x2066...0x2068:
                if value == 0x202D || value == 0x202E { bidiCount += 1 }
                if bidiStack.count < 125 {
                    bidiStack.append(value >= 0x2066)
                } else {
                    bidiCount += 1
                }
            case 0x202C:
                if bidiStack.last == false { bidiStack.removeLast() }
                else { bidiCount += 1 }
            case 0x2069:
                if let isolate = bidiStack.lastIndex(of: true) {
                    bidiStack.removeSubrange(isolate...)
                } else { bidiCount += 1 }
            case 0x0A, 0x0D, 0x2029:
                bidiCount += bidiStack.count
                bidiStack.removeAll(keepingCapacity: true)
            case 0xE0000...0xE007F:
                tagCount += 1
            default:
                break
            }
            scalars.formIndex(after: &index)
        }
        bidiCount += bidiStack.count
        if invisibleCount >= 3 {
            quickThreats.append("invisible-unicode: \(invisibleCount) zero-width characters outside recognized text contexts")
        }
        if bidiCount > 0 {
            quickThreats.append("bidi-override: \(bidiCount) override or unbalanced directional controls")
        }
        if tagCount > 0 {
            quickThreats.append("tag-chars: \(tagCount) Unicode tags outside supported emoji flags")
        }

        // Cache only after a complete, stable, UTF-8 snapshot was evaluated.
        // Carrier rejection and partial/failed reads remain eligible to retry.
        touchCache(path: path, identity: identity)

        guard !quickThreats.isEmpty else { return nil }

        // Co-occurring structural signals raise an uncalibrated score; neither
        // scalar presence nor this score establishes an instruction or intent.
        let confidence = quickThreats.count > 2 ? 65 : (quickThreats.count > 1 ? 50 : 35)
        let severity: Severity = quickThreats.count > 1 ? .high : .medium

        logger.warning("Possible hidden-text carrier in \(path): \(quickThreats.joined(separator: "; "))")

        return ScanResult(
            filePath: path,
            isInjected: true,
            confidence: confidence,
            threats: quickThreats,
            severity: severity
        )
    }

    /// UTS #51 ED-16: a ZWJ joins emoji elements. Recognize native Unicode
    /// emoji properties, optional VS16, and valid modifier bases, with constant
    /// lookaround. This checks element syntax, not the full RGI sequence list;
    /// ASCII keycap bases, regional indicators, and tags are not exempted here.
    private static func isEmojiJoiner(in scalars: String.UnicodeScalarView, at index: String.Index) -> Bool {
        let after = scalars.index(after: index)
        guard index > scalars.startIndex, after < scalars.endIndex else { return false }
        func isBase(_ scalar: Unicode.Scalar) -> Bool {
            scalar.value > 0x7F && scalar.properties.isEmoji && !scalar.properties.isEmojiModifier
                && !(0x1F1E6...0x1F1FF).contains(scalar.value)
        }
        guard isBase(scalars[after]) else { return false }
        var before = scalars.index(before: index)
        let suffix = scalars[before]
        if suffix.value == 0xFE0F || suffix.properties.isEmojiModifier {
            guard before > scalars.startIndex else { return false }
            scalars.formIndex(before: &before)
            if suffix.properties.isEmojiModifier {
                return scalars[before].properties.isEmojiModifierBase
            }
        }
        return isBase(scalars[before])
    }

    /// Joiners within common shaping scripts are typography, not evidence of
    /// injection. Support Arabic/Syriac, Indic, Myanmar, Khmer, and Mongolian
    /// letters, with at most eight combining marks on either side. Isolated,
    /// repeated, and ASCII-interleaved joiners still contribute to the signal.
    private static func isShapingJoiner(in scalars: String.UnicodeScalarView, at index: String.Index) -> Bool {
        func hasLetter(direction: Int) -> Bool {
            var cursor = index
            for _ in 0...8 {
                if direction < 0 {
                    guard cursor > scalars.startIndex else { return false }
                    scalars.formIndex(before: &cursor)
                } else {
                    scalars.formIndex(after: &cursor)
                    guard cursor < scalars.endIndex else { return false }
                }
                let scalar = scalars[cursor]
                switch scalar.properties.generalCategory {
                case .nonspacingMark, .spacingMark, .enclosingMark:
                    continue
                default:
                    let value = scalar.value
                    return scalar.properties.isAlphabetic && (
                        (0x0600...0x0DFF).contains(value) || (0x1000...0x109F).contains(value)
                        || (0x1780...0x18AF).contains(value)
                    )
                }
            }
            return false
        }
        return hasLetter(direction: -1) && hasLetter(direction: 1)
    }

    /// Unicode 17 RGI_Emoji_Tag_Sequence contains exactly gbeng, gbsct, gbwls:
    /// https://www.unicode.org/Public/17.0.0/emoji/emoji-sequences.txt
    /// Consume only BLACK FLAG + five exact tag letters + CANCEL TAG. A flag
    /// prefix never grants an exemption to an arbitrary hidden tag payload.
    private static func flagTagEnd(in scalars: String.UnicodeScalarView, at index: String.Index) -> String.Index? {
        var cursor = scalars.index(after: index)
        var word: UInt64 = 0
        for _ in 0..<5 {
            guard cursor < scalars.endIndex, (0xE0061...0xE007A).contains(scalars[cursor].value) else { return nil }
            word = (word << 8) | UInt64(scalars[cursor].value - 0xE0000)
            scalars.formIndex(after: &cursor)
        }
        guard word == 0x6762656E67 || word == 0x6762736374 || word == 0x6762776C73,
              cursor < scalars.endIndex, scalars[cursor].value == 0xE007F else { return nil }
        return scalars.index(after: cursor)
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
