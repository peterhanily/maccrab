// BundleArtifactPathPolicy.swift
// MacCrabCore
//
// One root-relative definition of the bundle integrity namespace.  Absolute
// path components are not bundle semantics: a bundle may legitimately live
// below an ancestor named `integrity`, and a nested payload directory with that
// name is still signed/redacted content.

import Foundation

enum BundleArtifactPathPolicy {
    enum PathError: Error, LocalizedError {
        case outsideBundleRoot(path: String, root: String)

        var errorDescription: String? {
            switch self {
            case .outsideBundleRoot(let path, let root):
                return "bundle artifact \(path) is outside bundle root \(root)"
            }
        }
    }

    /// Return a canonical path relative to `bundleRoot`, or fail closed if an
    /// enumerator ever yields a path outside that root (for example after a
    /// concurrent symlink swap).
    static func relativePath(of artifact: URL, under bundleRoot: URL) throws -> String {
        let artifactPath = artifact.standardizedFileURL.path
        let rootPath = bundleRoot.standardizedFileURL.path
        let prefix = rootPath.hasSuffix("/") ? rootPath : rootPath + "/"
        guard artifactPath.hasPrefix(prefix) else {
            throw PathError.outsideBundleRoot(path: artifactPath, root: rootPath)
        }
        return String(artifactPath.dropFirst(prefix.count))
    }

    /// Integrity metadata is excluded only when `integrity` is the first
    /// component *inside the bundle*.  Ancestor components and nested payload
    /// names such as `evidence/integrity/note.json` must not match.
    static func isRootIntegrityArtifact(relativePath: String) -> Bool {
        relativePath == "integrity" || relativePath.hasPrefix("integrity/")
    }
}
