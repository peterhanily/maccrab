// ArchiveDigest.swift
// MacCrabCore
//
// v1.21.5 Phase 2c — sidecar digest for the packaged `.tar.gz` archive.
//
// Replaces the pre-v1.21.5 `integrity/bundle_sha256.txt` in-bundle
// placeholder, which could only ever contain the literal string
// "PLACEHOLDER": a file inside a tar.gz can never contain that
// archive's own hash (fixed-point impossibility). The digest is
// therefore computed AFTER packaging and written NEXT TO the archive
// as `<archive>.sha256` in `shasum -a 256` output format, so
// `shasum -a 256 -c foo.maccrabtrace.tar.gz.sha256` just works.
//
// Transport-integrity convenience only — NOT part of the signed
// Merkle root; recompressing the bundle changes it. Tamper evidence
// remains the in-bundle hash chain + chain-head signature (spec §6).

import Foundation

public enum ArchiveDigest {

    /// SHA-256 of the file at `url` as lowercase hex, streamed in
    /// 64 KB chunks via `FileHasher.computeSHA256`. `nil` when the
    /// file cannot be opened or read.
    public static func sha256Hex(of url: URL) -> String? {
        FileHasher.computeSHA256(path: url.path)
    }

    /// One `shasum -a 256`-compatible line: `"<hex>  <fileName>\n"`
    /// (two spaces — the second is shasum's "text mode" marker).
    public static func sidecarLine(hex: String, fileName: String) -> String {
        "\(hex)  \(fileName)\n"
    }

    /// Sidecar path for an archive: `<archive>.sha256` alongside it.
    public static func sidecarURL(forArchiveAt archive: URL) -> URL {
        URL(fileURLWithPath: archive.path + ".sha256")
    }

    /// Hash the archive and write the shasum-compatible sidecar next
    /// to it. Returns the hex digest and sidecar URL, or `nil` when
    /// hashing or writing fails — callers treat that as a warning,
    /// never a failure of the export itself.
    public static func writeSidecar(forArchiveAt archive: URL) -> (hex: String, sidecar: URL)? {
        guard let hex = sha256Hex(of: archive) else { return nil }
        let sidecar = sidecarURL(forArchiveAt: archive)
        let line = sidecarLine(hex: hex, fileName: archive.lastPathComponent)
        do {
            try line.write(to: sidecar, atomically: true, encoding: .utf8)
        } catch {
            return nil
        }
        return (hex, sidecar)
    }
}
