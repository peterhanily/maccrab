// SecurityEvaluationPrecheck.swift
// MacCrabCore
//
// Opens a path the engine's way before Security.framework opens it itself.

import Darwin

/// Security.framework opens the paths it evaluates itself, without O_NOCTTY,
/// and blocks on a FIFO until a writer appears. Callers open the path first in
/// a way that can neither block nor adopt a terminal, and evaluate only the
/// object they expected; what remains is the short gap to Security's own open.
enum SecurityEvaluationPrecheck {
    enum Expected: Sendable {
        case regularFile
        case directory
        case regularFileOrDirectory
    }

    /// Metadata of what `path` names now, or nil when that is not `expected`
    /// or cannot be opened. A canonical path (one the kernel reported, or one
    /// below a no-follow listing) is also refused if any component is a
    /// symlink; /var and /tmp are rewritten to /private first.
    static func metadata(of path: String, expected: Expected, canonical: Bool) -> stat? {
        var target = path
        var flags = O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC
        if canonical {
            guard let normalized = BoundedRegularFileReader.normalizedAbsolutePath(path) else { return nil }
            target = normalized
            flags |= O_NOFOLLOW_ANY
        }
        let descriptor = Darwin.open(target, flags)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { return nil }
        switch (metadata.st_mode & S_IFMT, expected) {
        case (S_IFREG, .regularFile), (S_IFREG, .regularFileOrDirectory),
             (S_IFDIR, .directory), (S_IFDIR, .regularFileOrDirectory):
            return metadata
        default:
            return nil
        }
    }
}
