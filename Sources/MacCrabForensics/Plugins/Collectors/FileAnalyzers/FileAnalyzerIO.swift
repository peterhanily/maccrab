// FileAnalyzerIO.swift
//
// SEC-DELTA-1 / SEC-DELTA-2: shared bounded, symlink-safe file IO for the
// Tier-A FileAnalyzer collectors. Previously each analyzer did
// `Data(contentsOf:)` over an arbitrary path and SHA-256'd the whole buffer —
// an unbounded in-process read (memory-exhaustion on a huge or agent-chosen
// file) that also followed symlinks. This centralizes:
//   - a regular-file + size-cap gate (lstat: rejects symlinks, dirs, fifos,
//     and files over the cap → the analyzer skips them), and
//   - a streaming SHA-256 that never loads the whole file into RAM.
//
// The MachO analyzer's `FileHandle.read(upToCount:)` is the reference idiom;
// this generalizes it.

import Foundation
import CryptoKit

enum FileAnalyzerIO {

    /// Files larger than this are skipped by the analyzers (advisory triage
    /// tools — no value in slurping a multi-GB file into the in-process host).
    static let maxFileSizeBytes: Int = 256 * 1024 * 1024   // 256 MB

    /// Size of a REGULAR file via `lstat`, or nil to skip. Returns nil when the
    /// path is a symlink (SEC-DELTA-2 — never follow an operator/agent-supplied
    /// link), is not a regular file (dir / fifo / device), is unreadable, or
    /// exceeds `cap` (SEC-DELTA-1 — bound the read).
    static func regularFileSize(_ url: URL, cap: Int = maxFileSizeBytes) -> Int? {
        var st = stat()
        guard lstat(url.path, &st) == 0 else { return nil }
        guard (st.st_mode & S_IFMT) == S_IFREG else { return nil }   // not a regular file (symlink/dir/…)
        let size = Int(st.st_size)
        return size <= cap ? size : nil
    }

    /// Streaming SHA-256 (lowercase hex) over a file, 1 MB chunks — never loads
    /// the whole file into memory. nil if the file can't be opened.
    static func streamingSHA256(_ url: URL) -> String? {
        guard let fh = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? fh.close() }
        var hasher = SHA256()
        while let chunk = try? fh.read(upToCount: 1 << 20), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
