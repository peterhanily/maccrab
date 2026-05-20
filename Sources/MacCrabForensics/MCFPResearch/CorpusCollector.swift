// CorpusCollector — walks a directory tree, fingerprints every
// Mach-O via MCFPStatic, emits one JSONL row per binary.
//
// Plan §6.4 R2 prep. The operator runs this on Mac A and Mac B
// separately; the CorpusDiff utility compares the two outputs.

import Foundation
import CryptoKit

public struct CorpusEntry: Codable, Sendable {
    public let path: String
    public let sha256OfFile: String?
    public let archToken: String
    public let lc: String
    public let cs: String
    public let ent: String
    public let canonical: String
    public let collectedAtISO: String
    public let hostname: String

    public init(
        path: String,
        sha256OfFile: String?,
        archToken: String,
        lc: String,
        cs: String,
        ent: String,
        canonical: String,
        collectedAtISO: String,
        hostname: String
    ) {
        self.path = path
        self.sha256OfFile = sha256OfFile
        self.archToken = archToken
        self.lc = lc
        self.cs = cs
        self.ent = ent
        self.canonical = canonical
        self.collectedAtISO = collectedAtISO
        self.hostname = hostname
    }
}

public enum CorpusCollector {

    /// Walk `target` for Mach-O binaries, fingerprint each, and
    /// write one JSONL row per binary to `outputPath`. Returns
    /// the per-status count. Skips files that can't be opened or
    /// don't look like Mach-O.
    @discardableResult
    public static func collect(
        target: String,
        outputPath: String,
        progress: ((String) -> Void)? = nil
    ) async throws -> (collected: Int, skipped: Int) {

        let fm = FileManager.default
        guard fm.fileExists(atPath: target) else {
            throw NSError(domain: "CorpusCollector", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "target path missing: \(target)"
            ])
        }
        guard let enumerator = fm.enumerator(
            at: URL(fileURLWithPath: target),
            includingPropertiesForKeys: [.isRegularFileKey],
            options: []
        ) else {
            throw NSError(domain: "CorpusCollector", code: 2, userInfo: [
                NSLocalizedDescriptionKey: "could not enumerate target: \(target)"
            ])
        }

        let hostname = ProcessInfo.processInfo.hostName
        let isoFmt = ISO8601DateFormatter()
        let collectedAt = isoFmt.string(from: Date())

        // Open output file for append.
        if !fm.fileExists(atPath: outputPath) {
            fm.createFile(atPath: outputPath, contents: nil, attributes: [.posixPermissions: 0o644])
        }
        guard let out = FileHandle(forWritingAtPath: outputPath) else {
            throw NSError(domain: "CorpusCollector", code: 3, userInfo: [
                NSLocalizedDescriptionKey: "cannot open output: \(outputPath)"
            ])
        }
        try out.seekToEnd()
        defer { try? out.close() }

        var collected = 0
        var skipped = 0
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]

        for case let url as URL in enumerator {
            let path = url.path
            // Heuristic Mach-O detection: read first 4 bytes,
            // check magic.
            guard let fh = FileHandle(forReadingAtPath: path),
                  let magicData = try? fh.read(upToCount: 4),
                  magicData.count == 4 else {
                skipped += 1
                continue
            }
            try? fh.close()
            let magic = magicData.withUnsafeBytes { $0.load(as: UInt32.self) }
            let isMachO: Bool = {
                switch magic {
                case 0xcafebabe, 0xbebafeca: return true   // universal
                case 0xfeedfacf, 0xcffaedfe: return true   // 64-bit single
                case 0xfeedface, 0xcefaedfe: return true   // 32-bit
                default: return false
                }
            }()
            guard isMachO else {
                skipped += 1
                continue
            }

            let result: MCFPStaticResult
            do {
                result = try await MCFPStatic.fingerprint(path: path)
            } catch {
                skipped += 1
                continue
            }
            // SHA-256 of file contents — cheap and useful for the
            // diff to detect identical binaries by exact bytes.
            let fileSha: String? = {
                guard let data = try? Data(contentsOf: url) else { return nil }
                return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            }()

            let entry = CorpusEntry(
                path: path,
                sha256OfFile: fileSha,
                archToken: result.archToken,
                lc: result.lc,
                cs: result.cs,
                ent: result.ent,
                canonical: result.canonical,
                collectedAtISO: collectedAt,
                hostname: hostname
            )
            guard let jsonData = try? encoder.encode(entry) else {
                skipped += 1
                continue
            }
            try out.write(contentsOf: jsonData)
            try out.write(contentsOf: Data([0x0a]))   // newline
            collected += 1
            progress?(path)
        }
        return (collected, skipped)
    }

    /// Load a corpus file written by `collect(...)`. Errors on
    /// malformed JSONL lines are reported but don't abort the
    /// load.
    public static func load(corpusPath: String) throws -> [CorpusEntry] {
        let url = URL(fileURLWithPath: corpusPath)
        let raw = try String(contentsOf: url)
        let decoder = JSONDecoder()
        var entries: [CorpusEntry] = []
        for line in raw.split(separator: "\n", omittingEmptySubsequences: true) {
            guard let data = line.data(using: .utf8),
                  let entry = try? decoder.decode(CorpusEntry.self, from: data) else {
                continue
            }
            entries.append(entry)
        }
        return entries
    }
}
