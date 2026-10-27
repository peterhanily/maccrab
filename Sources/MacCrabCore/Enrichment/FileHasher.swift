// FileHasher.swift
// MacCrabCore
//
// SHA-256 file hashing with an LRU cache keyed on path + mtime + size.
// Skips network-mounted filesystems and files larger than a configurable cap.

import Foundation
import CryptoKit
import os.log

/// Actor-isolated file hasher used by enrichment.
///
/// Cache semantics: a file's SHA-256 is cached under `(path, mtime, size)`.
/// If any of those change, the entry is effectively invalidated and the file
/// is rehashed on next request. This avoids serving stale hashes for files
/// rewritten in place.
///
/// Files are skipped (return `nil`) under any of:
/// - Path does not exist or is not a regular file
/// - Size exceeds `maxFileBytes` (default 256 MB)
/// - Path resides on a network filesystem (NFS, SMB, AFP, WebDAV, FUSE)
/// - I/O error opening or reading the file
public actor FileHasher {

    // MARK: - Stats

    /// Hit/miss/skip counters for observability.
    public struct Stats: Sendable, Equatable {
        public var hits: Int = 0
        public var misses: Int = 0
        public var skippedSize: Int = 0
        public var skippedNetwork: Int = 0
        public var skippedMissing: Int = 0
        public var errors: Int = 0

        public var total: Int {
            hits + misses + skippedSize + skippedNetwork + skippedMissing + errors
        }
    }

    // MARK: - Private state

    /// Device, inode and change time join size and mtime: a same-size
    /// rewrite with a restored mtime must not keep serving the old digest,
    /// which would hide the new bytes from hash IOCs.
    struct CacheKey: Hashable {
        let path: String
        let device: UInt64
        let inode: UInt64
        let size: Int64
        let mtimeSeconds: Int
        let mtimeNanoseconds: Int
        let ctimeSeconds: Int
        let ctimeNanoseconds: Int

        /// The key without its path: the file the digest is of.
        var fileIdentity: HeavyEnrichmentFileIdentity {
            HeavyEnrichmentFileIdentity(
                deviceID: device, inodeNumber: inode, sizeBytes: size,
                modificationSeconds: Int64(mtimeSeconds), modificationNanoseconds: Int64(mtimeNanoseconds),
                statusChangeSeconds: Int64(ctimeSeconds), statusChangeNanoseconds: Int64(ctimeNanoseconds))
        }
    }

    /// A digest with the identity of the file whose bytes it is.
    public struct HashedFile: Sendable, Equatable {
        public let sha256: String
        public let identity: HeavyEnrichmentFileIdentity
        /// Whether this digest may stand for an exec'd image whose identity is
        /// `identity`: true only when the bytes were read from an APFS volume
        /// the system mounted (`volumeBindsImage`) and, for a digest served
        /// from the cache or from a read another call started, only while the
        /// file is still on such a volume. A volume a user mounted, a disk
        /// image or a removable drive, can be detached, edited offline and
        /// attached again with every file's device, inode, size and times
        /// intact; HFS+, FAT and exFAT keep times too coarse to tell a
        /// same-size rewrite apart. Even then the identity is evidence, not
        /// proof: a write through a shared mapping keeps it until flushed.
        public let imageBindable: Bool
    }

    /// A cached digest, with whether its volume lets it stand for an image.
    private struct CachedDigest: Sendable {
        let sha256: String
        let imageBindable: Bool
    }

    private let logger = Logger(subsystem: "com.maccrab.enrichment", category: "file-hasher")
    private let capacity: Int
    private let maxFileBytes: Int64

    private var cache: [CacheKey: CachedDigest] = [:]
    /// Front of the list is most recently used.
    private var lru: [CacheKey] = []
    /// The hash in flight for each (path, identity). The actor suspends
    /// while hashing, so N processes exec'ing one new binary would otherwise
    /// read it N times; later misses for the same bytes wait for this one.
    private var inFlight: [CacheKey: Task<Computed, Never>] = [:]
    private var statsStore = Stats()
    /// The digest computation; a seam so tests can hold or fail the hash
    /// that concurrent misses share.
    private let computeDigest: @Sendable (String, CacheKey) -> Computed
    /// Whether the file a key names is, now, on a volume that may bind a
    /// digest to an image; asked before a cached or shared digest is handed
    /// out as bindable. A seam so tests can stand in for a volume that was
    /// detached and another attached on its device number.
    private let currentVolumeBinds: @Sendable (String, CacheKey) -> Bool
    /// Told when a call joins the read in flight, so a test can release the
    /// read only once the join is waiting. Production callers never set it.
    private let joinObserverForTesting: (@Sendable () -> Void)?

    /// What one miss's hash found.
    enum Computed: Equatable, Sendable {
        /// The key's bytes, whether the path still named them afterwards, and
        /// whether the volume they were read from may bind them to an image
        /// (see `volumeBindsImage`). Unknown is not bindable.
        case digest(String, stillInPlace: Bool, imageBindable: Bool = false)
        /// On a network volume (NFS, SMB, AFP, WebDAV, FUSE): not hashed.
        case network
        /// Missing, swapped, rewritten while read, or an I/O error.
        case unavailable
    }

    // MARK: - Init

    /// Creates a file hasher.
    ///
    /// - Parameters:
    ///   - capacity: Max cache entries before LRU eviction (default 4096).
    ///   - maxFileBytes: Files larger than this are skipped (default 256 MB).
    public init(capacity: Int = 4096, maxFileBytes: Int64 = 256 * 1024 * 1024) {
        self.init(capacity: capacity, maxFileBytes: maxFileBytes,
                  computeDigest: { FileHasher.hashAndRecheck(path: $0, matching: $1) })
    }

    init(
        capacity: Int,
        maxFileBytes: Int64,
        currentVolumeBinds: @escaping @Sendable (String, CacheKey) -> Bool = {
            FileHasher.currentVolumeBindsImage(path: $0, matching: $1)
        },
        joinObserverForTesting: (@Sendable () -> Void)? = nil,
        computeDigest: @escaping @Sendable (String, CacheKey) -> Computed
    ) {
        precondition(capacity > 0, "capacity must be > 0")
        precondition(maxFileBytes > 0, "maxFileBytes must be > 0")
        self.capacity = capacity
        self.maxFileBytes = maxFileBytes
        self.currentVolumeBinds = currentVolumeBinds
        self.joinObserverForTesting = joinObserverForTesting
        self.computeDigest = computeDigest
    }

    // MARK: - Public API

    /// Returns the SHA-256 hex digest of `path`, or `nil` if the file is
    /// unavailable, too large, on a network mount, or errors during I/O.
    public func hash(path: String) async -> String? {
        await hashWithIdentity(path: path)?.sha256
    }

    /// `hash(path:)` with the identity (device, inode, size, mtime, ctime) of
    /// the file the digest is of: the one the probe found at `path`, whose
    /// identity the read checked before and after. A digest stands for a
    /// particular image only when that image's identity equals this one and
    /// `imageBindable` is true, and even then the identity is evidence, not
    /// proof. Compare this identity, not a stat of the path, which can name
    /// another file by the time it is taken.
    public func hashWithIdentity(path: String) async -> HashedFile? {
        // Type, size and identity, off the actor: a probe that walks into a
        // stalled network volume must not hold every other hash.
        let key: CacheKey
        switch await HeavyEnrichmentBlockingWork.run({ Self.probe(path: path) }) {
        case .unavailable:
            statsStore.skippedMissing += 1
            return nil
        case .file(let probed):
            key = probed
        }

        // Size cap.
        if key.size > maxFileBytes {
            statsStore.skippedSize += 1
            return nil
        }

        if let cached = cache[key] {
            statsStore.hits += 1
            touch(key)
            return HashedFile(sha256: cached.sha256, identity: key.fileIdentity,
                              imageBindable: await stillBindable(cached.imageBindable, path: path, key: key))
        }

        if let pending = inFlight[key] {
            joinObserverForTesting?()
            switch await pending.value {
            case .digest(let digest, _, let imageBindable):
                statsStore.hits += 1
                return HashedFile(sha256: digest, identity: key.fileIdentity,
                                  imageBindable: await stillBindable(imageBindable, path: path, key: key))
            case .network:
                statsStore.skippedNetwork += 1
                return nil
            case .unavailable:
                statsStore.errors += 1
                return nil
            }
        }

        // Cache miss: compute off the actor and the cooperative pool. Up to
        // 256 MiB is read; concurrent misses for other files proceed. Every
        // later miss for this key waits on this one, so it must always end:
        // the hash reads only the file the key names, never what a swapped
        // path now resolves to (a FIFO that never opens, a device that never
        // ends). The recheck of the path runs in the same hop, and the digest
        // is cached before the in-flight entry ends, so no later miss for
        // these bytes can start a second read.
        let compute = computeDigest
        let task = Task<Computed, Never> {
            await HeavyEnrichmentBlockingWork.run({ compute(path, key) })
        }
        inFlight[key] = task
        let computed = await task.value
        defer { inFlight.removeValue(forKey: key) }
        switch computed {
        case .digest(let digest, let stillInPlace, let imageBindable):
            statsStore.misses += 1
            // Cache only a digest of bytes that stayed in place while hashing.
            if stillInPlace { insert(key, digest: digest, imageBindable: imageBindable) }
            return HashedFile(sha256: digest, identity: key.fileIdentity, imageBindable: imageBindable)
        case .network:
            statsStore.skippedNetwork += 1
            return nil
        case .unavailable:
            statsStore.errors += 1
            return nil
        }
    }

    /// What one look at a path found.
    enum Probe: Equatable, Sendable {
        /// Missing, not a regular file, or reached through a symlink.
        case unavailable
        case file(CacheKey)
    }

    /// Type, size and identity from one `fstatat` that refuses a symlink in
    /// any component: a swapped parent fails here at once instead of walking
    /// into a tty, an automount trigger or another volume. Nothing is opened,
    /// so an unbindable cache hit costs this one call; a bindable hit or join
    /// also opens the file once more to ask its volume again
    /// (`stillBindable`). Network-ness comes from the hash's own
    /// descriptor, and only local digests are cached. Exec paths are
    /// canonical; /var and /tmp are rewritten to /private first.
    nonisolated static func probe(path: String) -> Probe {
        guard let resolved = BoundedRegularFileReader.normalizedAbsolutePath(path) else { return .unavailable }
        var st = stat()
        guard fstatat(AT_FDCWD, resolved, &st, AT_SYMLINK_NOFOLLOW_ANY) == 0,
              (st.st_mode & S_IFMT) == S_IFREG else { return .unavailable }
        return .file(CacheKey(
            path: path,
            device: HeavyEnrichmentFileIdentity.deviceID(fromStatDevice: st.st_dev),
            inode: UInt64(st.st_ino),
            size: Int64(st.st_size),
            mtimeSeconds: st.st_mtimespec.tv_sec,
            mtimeNanoseconds: st.st_mtimespec.tv_nsec,
            ctimeSeconds: st.st_ctimespec.tv_sec,
            ctimeNanoseconds: st.st_ctimespec.tv_nsec
        ))
    }

    nonisolated static func cacheKey(path: String) -> CacheKey? {
        guard case .file(let key) = probe(path: path) else { return nil }
        return key
    }

    /// The miss path's one blocking hop: the key's bytes, hashed from a
    /// descriptor that also answers network-ness, then whether the path
    /// still names them.
    nonisolated static func hashAndRecheck(path: String, matching key: CacheKey) -> Computed {
        let computed = hashFile(path: path, matching: key)
        guard case .digest(let digest, _, let imageBindable) = computed else { return computed }
        return .digest(digest, stillInPlace: cacheKey(path: path) == key, imageBindable: imageBindable)
    }

    /// The volume's file-system type name (`apfs`, `hfs`, `msdos`, `exfat`),
    /// read only within its fixed-size field.
    nonisolated static func fileSystemTypeName(of volume: statfs) -> String {
        withUnsafeBytes(of: volume.f_fstypename) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
    }

    /// Whether a digest read from a volume may be bound to an exec'd image:
    /// only on APFS that the system mounted (owned by root), such as the
    /// startup disk. A volume a user mounted, a disk image or a removable
    /// drive, can be detached, edited offline and attached again on the same
    /// device number with every file's inode, size and times intact. HFS+,
    /// FAT and exFAT keep times too coarse to tell a same-size rewrite apart,
    /// and App Translocation's nullfs is not APFS. A volume that could not be
    /// asked (nil) is not bindable.
    nonisolated static func volumeBindsImage(fileSystemTypeName: String?, owner: uid_t?) -> Bool {
        fileSystemTypeName == "apfs" && owner == 0
    }

    /// Whether the file `key` names is, now, on a volume that may bind (see
    /// `volumeBindsImage`). Asked of a descriptor opened as the hash opens
    /// one and holding the key's identity, never of the path by name: a swap
    /// between the probe and the question could answer for another volume.
    /// Anything that cannot be asked is not bindable.
    nonisolated static func currentVolumeBindsImage(path: String, matching key: CacheKey) -> Bool {
        guard let resolved = BoundedRegularFileReader.normalizedAbsolutePath(path) else { return false }
        let descriptor = open(resolved, O_RDONLY | O_NONBLOCK | O_NOFOLLOW_ANY | O_CLOEXEC | O_NOCTTY)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0, identity(of: opened, matches: key) else { return false }
        var volume = statfs()
        guard fstatfs(descriptor, &volume) == 0 else { return false }
        return volumeBindsImage(fileSystemTypeName: fileSystemTypeName(of: volume), owner: volume.f_owner)
    }

    /// A cached or shared digest keeps its binding only while the file its
    /// key names is still on a volume that may bind: the volume it was read
    /// from may since have been detached, and another one, or the same one
    /// edited offline, attached on its device number. Asked off the actor,
    /// like the probe, and only for a digest that was bindable.
    private func stillBindable(_ bindable: Bool, path: String, key: CacheKey) async -> Bool {
        guard bindable else { return false }
        let check = currentVolumeBinds
        return await HeavyEnrichmentBlockingWork.run({ check(path, key) })
    }

    /// Current observability counters (copy).
    public func stats() -> Stats { statsStore }

    /// Remove any cached entries for `path` (all mtime/size variants).
    public func invalidate(path: String) {
        cache = cache.filter { $0.key.path != path }
        lru.removeAll { $0.path == path }
    }

    /// Clear the entire cache and reset stats.
    public func reset() {
        cache.removeAll()
        lru.removeAll()
        statsStore = Stats()
    }

    /// Current cache population (for tests + diagnostics).
    public func cacheCount() -> Int { cache.count }

    // MARK: - Private LRU

    private func touch(_ key: CacheKey) {
        if let idx = lru.firstIndex(of: key) {
            lru.remove(at: idx)
        }
        lru.insert(key, at: 0)
    }

    private func insert(_ key: CacheKey, digest: String, imageBindable: Bool) {
        // Idempotent: a duplicate key in `lru` would later evict the live
        // entry and leave the other copy dangling.
        if cache.updateValue(CachedDigest(sha256: digest, imageBindable: imageBindable), forKey: key) != nil {
            touch(key)
            return
        }
        lru.insert(key, at: 0)
        while lru.count > capacity {
            let evicted = lru.removeLast()
            cache.removeValue(forKey: evicted)
        }
    }

    // MARK: - Hashing

    /// SHA-256 of exactly the file `key` names. The descriptor is opened
    /// without blocking and without following a symlink in any component,
    /// and must be a regular file with the key's device, inode, size, mtime
    /// and ctime, before and after the read; the read stops at the key's
    /// size. Anything else, a path swapped since the lstat that made the key,
    /// a file rewritten while it was read, is unavailable (nil) rather than
    /// hashed.
    nonisolated static func computeSHA256(
        path: String,
        matching key: CacheKey,
        afterIdentityCheckForTesting: ((Int32) -> Void)? = nil
    ) -> String? {
        guard case .digest(let digest, _, _) = hashFile(
            path: path, matching: key, afterIdentityCheckForTesting: afterIdentityCheckForTesting
        ) else { return nil }
        return digest
    }

    /// `computeSHA256(path:matching:)`, telling a network volume apart from
    /// a failure. `stillInPlace` is always false here.
    nonisolated static func hashFile(
        path: String,
        matching key: CacheKey,
        afterIdentityCheckForTesting: ((Int32) -> Void)? = nil
    ) -> Computed {
        // A swapped parent symlink would otherwise aim this root open at a
        // tty, an automount trigger that blocks, or /dev/fd before the
        // identity check: refuse a symlink anywhere in the path. Exec paths
        // are canonical; /var and /tmp are rewritten to /private first.
        guard let resolved = BoundedRegularFileReader.normalizedAbsolutePath(path) else { return .unavailable }
        let descriptor = open(resolved, O_RDONLY | O_NONBLOCK | O_NOFOLLOW_ANY | O_CLOEXEC | O_NOCTTY)
        guard descriptor >= 0 else { return .unavailable }
        defer { close(descriptor) }
        var opened = stat()
        guard fstat(descriptor, &opened) == 0, identity(of: opened, matches: key) else { return .unavailable }
        // Network volumes are skipped (NFS, SMB, AFP, WebDAV, FUSE). A volume
        // that cannot be asked counts as local, as before.
        var volume = statfs()
        let volumeKnown = fstatfs(descriptor, &volume) == 0
        if volumeKnown, volume.f_flags & UInt32(MNT_LOCAL) == 0 {
            return .network
        }
        // Asked of the descriptor the bytes come from: only a digest read from
        // APFS the system mounted may be bound to an exec'd image (see
        // `volumeBindsImage`). Its identity tells apart a rewrite made through
        // the mounted file system, but proves no more: a write through a
        // shared mapping keeps it until flushed. A volume that could not be
        // asked is not bindable.
        let imageBindable = volumeKnown
            && Self.volumeBindsImage(fileSystemTypeName: Self.fileSystemTypeName(of: volume), owner: volume.f_owner)
        // Test seam: a fixture can change the file between the check and the
        // read. Production callers never supply it.
        afterIdentityCheckForTesting?(descriptor)

        var hasher = SHA256()
        let chunkSize = 64 * 1024
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        var remaining = Int(key.size)
        while remaining > 0 {
            let count = buffer.withUnsafeMutableBytes { bytes in
                read(descriptor, bytes.baseAddress, min(chunkSize, remaining))
            }
            if count < 0 {
                if errno == EINTR { continue }
                return .unavailable
            }
            if count == 0 { return .unavailable }   // shorter than the key says
            buffer.withUnsafeBytes { bytes in
                hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: bytes[..<count]))
            }
            remaining -= count
        }
        var after = stat()
        guard fstat(descriptor, &after) == 0, identity(of: after, matches: key) else { return .unavailable }
        return .digest(hasher.finalize().map { String(format: "%02x", $0) }.joined(), stillInPlace: false,
                       imageBindable: imageBindable)
    }

    private nonisolated static func identity(of info: stat, matches key: CacheKey) -> Bool {
        (info.st_mode & S_IFMT) == S_IFREG
            && HeavyEnrichmentFileIdentity.deviceID(fromStatDevice: info.st_dev) == key.device
            && UInt64(info.st_ino) == key.inode
            && Int64(info.st_size) == key.size
            && info.st_mtimespec.tv_sec == key.mtimeSeconds
            && info.st_mtimespec.tv_nsec == key.mtimeNanoseconds
            && info.st_ctimespec.tv_sec == key.ctimeSeconds
            && info.st_ctimespec.tv_nsec == key.ctimeNanoseconds
    }

    /// Compute SHA-256 of file contents via streaming 64 KB chunks.
    ///
    /// Nonisolated + public: pure I/O + CryptoKit, no actor state touched.
    /// Exposed so callers that don't need actor-level LRU caching (e.g.
    /// `SelfDefense`'s integrity checks, which compute hashes at startup
    /// and on a 15 s periodic tick) can hash in-process without spawning
    /// per-file `/usr/bin/shasum` subprocesses. The cached `hash(path:)`
    /// instance method remains the preferred entry point for enrichment.
    nonisolated public static func computeSHA256(path: String) -> String? {
        // A final symlink is still followed, as before. The open never waits
        // on a FIFO and never makes a terminal the root engine's controlling
        // tty (a session leader adopts the first tty it opens without
        // O_NOCTTY), and only a regular file is read.
        let descriptor = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }

        var hasher = SHA256()
        let chunkSize = 64 * 1024
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                read(descriptor, bytes.baseAddress, chunkSize)
            }
            if count < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if count == 0 { break }
            buffer.withUnsafeBytes { bytes in
                hasher.update(bufferPointer: UnsafeRawBufferPointer(rebasing: bytes[..<count]))
            }
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
