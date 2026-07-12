// BundleMerkle.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-10c) — shared Merkle-root helper used by both
// the BundleExporter (writes the chain) and the BundleVerifier
// (recomputes it on read). Per §19.2 of the v1.10.0 spec, the
// signature commits to a canonical Merkle root over the bundle's
// internal artifacts, NOT the outer .tar.gz bytes.
//
// Canonical reduction (v2 — A3-06(a) hardening):
//   1. List every regular file under the bundle root, EXCLUDING the
//      `integrity/` subdirectory (those are the integrity artifacts
//      themselves — they're computed FROM this list).
//   2. Compute SHA-256 over each file.
//   3. Sort by canonical relative path.
//   4. Domain-separate each leaf: leaf node = SHA-256(0x00 || leafHash).
//      Reduce pairwise with an internal-node tag: parent =
//      SHA-256(0x01 || left || right). On odd levels the last node is
//      still duplicated as its own right sibling.
//   5. Bind the exact leaf COUNT into the final root:
//      root = SHA-256(DOMAIN || uint64_be(leafCount) || treeRoot),
//      where treeRoot is the reduced tree (or SHA-256("") when empty).
//
// Steps 4–5 close the CVE-2012-2459 duplicate-last-leaf malleability:
// duplicating the tail changes the leaf count, so two distinct artifact
// lists (e.g. [A,B,C] vs [A,B,C,C]) can no longer collapse to the same
// root. The 0x00/0x01 tags also remove the leaf/internal-node ambiguity
// (an internal digest can't be re-presented as a leaf). This is a
// deliberate format change from the v1 Bitcoin-style reduction; both the
// exporter and the verifier recompute through THIS function, so bundles
// stay internally consistent — a third-party verifier must mirror the
// v2 reduction below.
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
            return Computation(merkleRoot: reduce([]), artifacts: [])
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

    /// Domain-separated, leaf-count-bound SHA-256 reduction (v2). Public
    /// so tests can exercise the reduction in isolation from disk IO.
    ///
    /// See the file header for the canonical definition. The count bound
    /// + node tags close the CVE-2012-2459 duplicate-last-leaf
    /// malleability: the root commits to the exact leaf set, not just its
    /// tree shape.
    public static func reduce(_ leaves: [String]) -> String {
        // Leaf nodes: SHA-256(0x00 || leafHash). Leaves that aren't valid
        // hex are dropped from the tree (same as v1) but still counted in
        // the leaf-count bind so the root commits to the requested set.
        var current: [Data] = leaves.compactMap { hex -> Data? in
            guard let raw = Data(merkleHex: hex) else { return nil }
            return Data(SHA256.hash(data: leafPrefixed(raw)))
        }
        let treeRoot: Data
        if current.isEmpty {
            treeRoot = Data(SHA256.hash(data: Data()))
        } else {
            while current.count > 1 {
                var next: [Data] = []
                var i = 0
                while i < current.count {
                    let left = current[i]
                    let right = (i + 1 < current.count) ? current[i + 1] : current[i]
                    // Internal node: SHA-256(0x01 || left || right).
                    var combined = Data([nodeTag])
                    combined.append(left)
                    combined.append(right)
                    next.append(Data(SHA256.hash(data: combined)))
                    i += 2
                }
                current = next
            }
            treeRoot = current[0]
        }
        // Final root binds the domain tag + the exact leaf count.
        var rootInput = Data(rootDomain.utf8)
        var countBE = UInt64(leaves.count).bigEndian
        withUnsafeBytes(of: &countBE) { rootInput.append(contentsOf: $0) }
        rootInput.append(treeRoot)
        return SHA256.hash(data: rootInput).map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - v2 domain-separation constants

    private static let leafTag: UInt8 = 0x00
    private static let nodeTag: UInt8 = 0x01
    /// Domain-separation prefix for the final root. Any change to the
    /// reduction MUST bump this so roots from different formats never alias.
    private static let rootDomain = "maccrab.bundle.merkle.v2\u{0}"

    private static func leafPrefixed(_ raw: Data) -> Data {
        var d = Data([leafTag])
        d.append(raw)
        return d
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
