import Foundation
import Darwin

/// SHA-256 digests reused while a file's identity is unchanged.
///
/// Self-defense re-reads the engine binary and every compiled rule file on a
/// 15 s tick. Hashing is only needed when one of them changed, and every
/// write changes the change time, which an unprivileged writer cannot
/// restore. Root can, with exact control of the clock, so a digest is reused
/// at most `maximumReuses` times before the file is hashed again. Bounded; a
/// full cache is cleared, which only costs re-hashing.
final class FileIdentityDigestCache: @unchecked Sendable {
    struct Identity: Equatable {
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let modifiedSeconds: Int
        let modifiedNanoseconds: Int
        let changedSeconds: Int
        let changedNanoseconds: Int
    }

    private let lock = NSLock()
    private var entries: [String: (identity: Identity, digest: String, reuses: Int)] = [:]
    private let capacity: Int
    private let maximumReuses: Int

    init(capacity: Int = 4_096, maximumReuses: Int = 20) {
        self.capacity = max(1, capacity)
        self.maximumReuses = max(0, maximumReuses)
    }

    /// The file's current identity, following symlinks like the hashing read.
    static func identity(of path: String) -> Identity? {
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        return Identity(
            device: UInt64(st.st_dev),
            inode: UInt64(st.st_ino),
            size: Int64(st.st_size),
            modifiedSeconds: st.st_mtimespec.tv_sec,
            modifiedNanoseconds: st.st_mtimespec.tv_nsec,
            changedSeconds: st.st_ctimespec.tv_sec,
            changedNanoseconds: st.st_ctimespec.tv_nsec
        )
    }

    /// The digest of the bytes now at `path`: reused when the identity is
    /// unchanged, otherwise computed and cached if the file held still.
    func sha256(of path: String, compute: (String) -> String?) -> String? {
        guard let before = Self.identity(of: path) else { return nil }
        lock.lock()
        if let entry = entries[path], entry.identity == before, entry.reuses < maximumReuses {
            entries[path]?.reuses += 1
            lock.unlock()
            return entry.digest
        }
        lock.unlock()
        guard let digest = compute(path) else { return nil }
        if Self.identity(of: path) == before {
            lock.lock()
            if entries.count >= capacity, entries[path] == nil {
                entries.removeAll(keepingCapacity: true)
            }
            entries[path] = (before, digest, 0)
            lock.unlock()
        }
        return digest
    }
}
