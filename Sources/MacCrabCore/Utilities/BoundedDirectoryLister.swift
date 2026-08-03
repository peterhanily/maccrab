// BoundedDirectoryLister.swift
// MacCrabCore
//
// Descriptor-pinned, no-follow directory enumeration for paths controlled by
// a logged-in user but inspected by the privileged daemon.

import Foundation
import Darwin

public enum BoundedDirectoryLister {
    public enum EntryKind: Sendable, Hashable {
        case directory
        case regularFile
        case symbolicLink
        case other
    }

    public struct Entry: Sendable, Equatable {
        public let name: String
        public let kind: EntryKind
        public let ownerUID: UInt32

        public init(name: String, kind: EntryKind, ownerUID: UInt32) {
            self.name = name
            self.kind = kind
            self.ownerUID = ownerUID
        }
    }

    public struct Snapshot: Sendable, Equatable {
        public let entries: [Entry]
        /// True when the inspection boundary was reached. This is conservative:
        /// a directory with exactly the limit is also marked truncated because
        /// the lister never consumes an extra attacker-controlled dirent to
        /// distinguish equality from overflow.
        public let wasTruncated: Bool
        /// Raw non-dot dirents consumed, including names whose fstatat metadata
        /// lookup failed during a concurrent mutation.
        public let inspectedEntryCount: Int

        public init(
            entries: [Entry],
            wasTruncated: Bool,
            inspectedEntryCount: Int? = nil
        ) {
            self.entries = entries
            self.wasTruncated = wasTruncated
            self.inspectedEntryCount = inspectedEntryCount ?? entries.count
        }
    }

    /// List at most `maximumEntries` immediate children. Every path component
    /// is opened from a pinned parent with O_DIRECTORY|O_NOFOLLOW, so a symlink
    /// carrier, FIFO or device can neither redirect nor block the daemon.
    /// Child metadata comes from fstatat on that pinned directory descriptor.
    public static func list(
        at path: String,
        maximumEntries: Int,
        expectedOwnerUID: UInt32? = nil
    ) -> Snapshot? {
        guard maximumEntries > 0,
              maximumEntries <= 1_000_000,
              let descriptor = openDirectoryNoFollow(path) else {
            return nil
        }

        var directoryMetadata = stat()
        guard Darwin.fstat(descriptor, &directoryMetadata) == 0,
              expectedOwnerUID.map({ directoryMetadata.st_uid == $0 }) ?? true else {
            Darwin.close(descriptor)
            return nil
        }

        guard let stream = Darwin.fdopendir(descriptor) else {
            Darwin.close(descriptor)
            return nil
        }
        // fdopendir takes ownership of descriptor.
        defer { Darwin.closedir(stream) }

        var entries: [Entry] = []
        entries.reserveCapacity(min(maximumEntries, 4_096))
        var inspectedEntries = 0
        Darwin.errno = 0
        while let rawEntry = Darwin.readdir(stream) {
            let name = withUnsafePointer(to: &rawEntry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
                    String(cString: $0)
                }
            }
            guard name != ".", name != "..", !name.isEmpty else { continue }
            // Count raw dirents, not only successful metadata reads. An attacker
            // concurrently unlinking names can make fstatat fail; tying the cap
            // to appended entries would then permit an unbounded readdir loop.
            inspectedEntries += 1
            let reachedInspectionLimit = inspectedEntries == maximumEntries

            var metadata = stat()
            let status = name.withCString {
                Darwin.fstatat(
                    Darwin.dirfd(stream),
                    $0,
                    &metadata,
                    AT_SYMLINK_NOFOLLOW
                )
            }
            guard status == 0 else {
                Darwin.errno = 0
                if reachedInspectionLimit {
                    return Snapshot(
                        entries: entries.sorted { $0.name < $1.name },
                        wasTruncated: true,
                        inspectedEntryCount: inspectedEntries
                    )
                }
                continue
            }
            let fileType = metadata.st_mode & S_IFMT
            let kind: EntryKind
            switch fileType {
            case S_IFDIR: kind = .directory
            case S_IFREG: kind = .regularFile
            case S_IFLNK: kind = .symbolicLink
            default: kind = .other
            }
            entries.append(Entry(name: name, kind: kind, ownerUID: metadata.st_uid))
            if reachedInspectionLimit {
                // Conservative: exactly-at-limit directories are reported as
                // truncated rather than reading one extra attacker-controlled
                // dirent merely to distinguish equality from overflow.
                return Snapshot(
                    entries: entries.sorted { $0.name < $1.name },
                    wasTruncated: true,
                    inspectedEntryCount: inspectedEntries
                )
            }
            Darwin.errno = 0
        }
        guard Darwin.errno == 0 else { return nil }
        return Snapshot(
            entries: entries.sorted { $0.name < $1.name },
            wasTruncated: false,
            inspectedEntryCount: inspectedEntries
        )
    }

    /// Validate a directory without enumerating it. Useful when the next level
    /// will be listed later but the current caller only needs a no-follow
    /// existence/ownership check.
    public static func isDirectory(
        at path: String,
        expectedOwnerUID: UInt32? = nil
    ) -> Bool {
        guard let descriptor = openDirectoryNoFollow(path) else { return false }
        defer { Darwin.close(descriptor) }
        var metadata = stat()
        return Darwin.fstat(descriptor, &metadata) == 0
            && (expectedOwnerUID.map { metadata.st_uid == $0 } ?? true)
    }

    private static func openDirectoryNoFollow(_ path: String) -> Int32? {
        // Use the same strict lexical normalization as the descriptor reader
        // and writer. In particular, macOS exposes /var and /tmp as trusted
        // aliases into /private; walking them literally with O_NOFOLLOW rejects
        // real DiagnosticReports and temporary fixtures at the alias itself.
        // Foundation.standardizingPath is not suitable here because it also
        // silently accepts dot, parent and repeated-separator components.
        // A single terminal slash is an ordinary directory spelling (and is
        // used by the DiagnosticReports scopes). Strip only that delimiter;
        // repeated separators still reach the shared validator and fail.
        let directoryPath = path.count > 1 && path.hasSuffix("/")
            ? String(path.dropLast())
            : path
        guard let normalized = BoundedRegularFileReader.normalizedAbsolutePath(directoryPath),
              normalized != "/" else { return nil }
        let components = normalized.dropFirst().split(separator: "/").map(String.init)
        guard !components.isEmpty else { return nil }

        var descriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        )
        guard descriptor >= 0 else { return nil }

        for component in components {
            let next = component.withCString {
                Darwin.openat(
                    descriptor,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
                )
            }
            guard next >= 0 else {
                Darwin.close(descriptor)
                return nil
            }
            Darwin.close(descriptor)
            descriptor = next
        }
        return descriptor
    }
}
