// BundleMerkle.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10c) — shared Merkle-root helper used by both
// the BundleExporter (writes the chain) and the BundleVerifier
// (recomputes it on read). Per §19.2 of the v1.10.0 spec, the
// signature commits to a canonical Merkle root over the bundle's
// internal artifacts, NOT the outer .tar.gz bytes.
//
// Canonical reduction:
//   1. List every regular file under the bundle root, EXCLUDING the
//      `integrity/` subdirectory (those are the integrity artifacts
//      themselves — they're computed FROM this list).
//   2. Compute SHA-256 over each file.
//   3. Sort by canonical relative path.
//   4. Reduce pairwise via SHA-256 pairwise concatenation. On odd
//      levels the last hash is duplicated (Bitcoin-style merkle).
//   5. Single-leaf trees return the leaf itself; the empty tree
//      returns SHA-256("").
//
// This lives outside BundleExporter so BundleVerifier can recompute
// the same root deterministically on a bundle written by any
// implementation that follows the spec.

import Foundation
import CryptoKit

public enum BundleMerkle {

    /// Result of computing the Merkle root for a bundle directory.
    public struct Computation: Sendable, Equatable {
        public let merkleRoot: String          // lowercase hex
        public let artifacts: [HashChainArtifact.ArtifactHash]
    }

    /// Walk the bundle directory and produce the canonical artifact
    /// hash list + the resulting Merkle root.
    public static func compute(forBundleAt directory: URL) throws -> Computation {
        var artifacts: [HashChainArtifact.ArtifactHash] = []
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return Computation(merkleRoot: emptyMerkle(), artifacts: [])
        }

        for case let url as URL in enumerator {
            let resources = try url.resourceValues(forKeys: [.isRegularFileKey])
            guard resources.isRegularFile == true else { continue }
            // Skip integrity/* artifacts — they are derived FROM this list.
            if url.pathComponents.contains("integrity") {
                continue
            }
            let data = try Data(contentsOf: url)
            let digest = SHA256.hash(data: data)
            let hex = digest.map { String(format: "%02x", $0) }.joined()
            let relative = relativePath(of: url, under: directory)
            artifacts.append(HashChainArtifact.ArtifactHash(path: relative, sha256: hex))
        }

        artifacts.sort { $0.path < $1.path }
        let root = reduce(artifacts.map { $0.sha256 })
        return Computation(merkleRoot: root, artifacts: artifacts)
    }

    /// Pairwise SHA-256 reduction. Public so tests can exercise the
    /// reduction in isolation from disk IO.
    public static func reduce(_ leaves: [String]) -> String {
        if leaves.isEmpty { return emptyMerkle() }
        var current = leaves.compactMap { hex -> Data? in
            return Data(merkleHex: hex)
        }
        if current.isEmpty { return emptyMerkle() }
        while current.count > 1 {
            var next: [Data] = []
            var i = 0
            while i < current.count {
                let left = current[i]
                let right = (i + 1 < current.count) ? current[i + 1] : current[i]
                let combined = SHA256.hash(data: left + right)
                next.append(Data(combined))
                i += 2
            }
            current = next
        }
        return current[0].map { String(format: "%02x", $0) }.joined()
    }

    private static func emptyMerkle() -> String {
        SHA256.hash(data: Data()).map { String(format: "%02x", $0) }.joined()
    }

    private static func relativePath(of url: URL, under root: URL) -> String {
        // Use URL.standardizedFileURL to dodge /var ↔ /private/var
        // symlink resolution differences on macOS.
        let standardizedURL = url.standardizedFileURL.path
        let standardizedRoot = root.standardizedFileURL.path
        let rootPath = standardizedRoot.hasSuffix("/") ? standardizedRoot : standardizedRoot + "/"
        if standardizedURL.hasPrefix(rootPath) {
            return String(standardizedURL.dropFirst(rootPath.count))
        }
        return url.lastPathComponent
    }
}

// MARK: - Hex helper (file-private to avoid clashing with the one in BundleExporter)

private extension Data {
    init?(merkleHex: String) {
        guard merkleHex.count % 2 == 0 else { return nil }
        var data = Data(capacity: merkleHex.count / 2)
        var idx = merkleHex.startIndex
        while idx < merkleHex.endIndex {
            let next = merkleHex.index(idx, offsetBy: 2)
            guard let byte = UInt8(merkleHex[idx..<next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        self = data
    }
}
