// RealUserHomeResolver.swift
// MacCrabCore
//
// A privileged daemon's process home is /var/root.  User-facing sensors must
// never use NSHomeDirectory() to find browser, TCC, quarantine, LaunchAgent, or
// other per-login-user state.  This is the single contract for resolving a
// local user's real home without trusting a bare /Users directory walk.

import Foundation
import Darwin

public struct RealUserHome: Sendable, Hashable {
    public let path: String
    public let userID: UInt32
    public let userName: String

    public init(path: String, userID: UInt32, userName: String) {
        self.path = path
        self.userID = userID
        self.userName = userName
    }

    public func appending(_ relativePath: String) -> String {
        let suffix = relativePath.hasPrefix("/")
            ? String(relativePath.dropFirst())
            : relativePath
        return (path as NSString).appendingPathComponent(suffix)
    }
}

public enum RealUserHomeResolver {
    /// Enumerate every validated local home.  A candidate is accepted only when
    /// all of the following agree:
    ///   * the directory is reached component-by-component with O_NOFOLLOW;
    ///   * the final descriptor is a directory owned by a non-root uid; and
    ///   * getpwuid(3) maps that uid and user name back to this exact home.
    ///
    /// `/Users/Shared`, hidden entries, symlink homes, stale/deleted accounts,
    /// and a directory merely named like another user all fail closed.
    public static func all() -> [RealUserHome] {
        guard let snapshot = BoundedDirectoryLister.list(
            at: "/Users",
            maximumEntries: 65_536,
            expectedOwnerUID: 0
        ) else {
            return []
        }

        var homes: [RealUserHome] = []
        var seenUIDs: Set<UInt32> = []
        for directoryEntry in snapshot.entries where directoryEntry.kind == .directory {
            let entry = directoryEntry.name
            guard entry != "Shared", !entry.hasPrefix(".") else { continue }
            let candidate = "/Users/\(entry)"
            guard let metadata = descriptorMetadata(forDirectory: candidate),
                  metadata.st_uid != 0,
                  metadata.st_uid != UInt32.max,
                  let account = passwdRecord(for: metadata.st_uid),
                  validateCandidate(
                      path: candidate,
                      expectedUID: metadata.st_uid,
                      expectedUserName: account.name,
                      passwdHome: account.home,
                      passwdUserName: account.name
                  ),
                  seenUIDs.insert(metadata.st_uid).inserted else {
                continue
            }
            homes.append(RealUserHome(
                path: candidate,
                userID: metadata.st_uid,
                userName: account.name
            ))
        }
        return homes
    }

    /// Resolve one explicit event/process uid.  This is preferred over global
    /// enumeration for provenance: on a fast-user-switched Mac it prevents an
    /// event from Alice being joined to Bob's quarantine or browser database.
    public static func home(forUserID userID: UInt32) -> RealUserHome? {
        guard userID != 0, userID != UInt32.max,
              let account = passwdRecord(for: userID),
              let normalizedHome = normalizedAbsolutePath(account.home),
              normalizedHome.hasPrefix("/Users/"),
              normalizedHome != "/Users/Shared",
              let metadata = descriptorMetadata(forDirectory: normalizedHome),
              metadata.st_uid == userID,
              validateCandidate(
                  path: normalizedHome,
                  expectedUID: userID,
                  expectedUserName: account.name,
                  passwdHome: account.home,
                  passwdUserName: account.name
              ) else {
            return nil
        }
        return RealUserHome(path: normalizedHome, userID: userID, userName: account.name)
    }

    /// Return the validated home that lexically contains `path`.  This does not
    /// guess from an arbitrary `/Users/<token>` prefix: only `all()` candidates
    /// whose uid/passwd/directory identities agree participate.
    public static func home(containingPath path: String) -> RealUserHome? {
        guard let normalized = normalizedAbsolutePath(path) else { return nil }
        return all().first { home in
            normalized == home.path || normalized.hasPrefix(home.path + "/")
        }
    }

    /// Bind a path to an explicit event uid.  If the path lies in a user home,
    /// both sources must identify the same user.  Paths outside user homes
    /// (for example /Applications or /Volumes) may use the event uid alone.
    /// Root/unknown uids are never converted into a guessed console user.
    public static func provenanceHome(
        forPath path: String,
        userID: UInt32
    ) -> RealUserHome? {
        guard let uidHome = home(forUserID: userID) else { return nil }
        return reconcileProvenance(
            path: path,
            pathHome: home(containingPath: path),
            uidHome: uidHome
        )
    }

    /// Path-only provenance is valid only for an existing object inside one
    /// validated home whose no-follow lstat owner is that home's uid.  There is
    /// deliberately no "only user on the Mac" fallback for /Applications or
    /// /Volumes: without an event uid that association is ambiguous.
    public static func provenanceHome(forPath path: String) -> RealUserHome? {
        guard let home = home(containingPath: path),
              let owner = noFollowOwner(of: path),
              owner == home.userID else {
            return nil
        }
        return home
    }

    /// A global single-user choice is safe only when exactly one validated
    /// local account exists.  Callers should prefer path/uid association.
    public static func uniqueHome() -> RealUserHome? {
        uniqueHome(from: all())
    }

    // MARK: - Validation seams

    /// Internal pure-ish seam for adversarial tests.  Production obtains the
    /// passwd values from getpwuid_r; tests can prove every identity mismatch
    /// and symlink carrier is rejected without creating OS accounts.
    static func validateCandidate(
        path: String,
        expectedUID: UInt32,
        expectedUserName: String,
        passwdHome: String,
        passwdUserName: String
    ) -> Bool {
        guard expectedUID != 0, expectedUID != UInt32.max,
              !expectedUserName.isEmpty,
              expectedUserName == passwdUserName,
              let normalized = normalizedAbsolutePath(path),
              let normalizedPasswdHome = normalizedAbsolutePath(passwdHome),
              normalized == normalizedPasswdHome,
              let metadata = descriptorMetadata(forDirectory: normalized),
              metadata.st_uid == expectedUID else {
            return false
        }
        return true
    }

    static func uniqueHome(from homes: [RealUserHome]) -> RealUserHome? {
        homes.count == 1 ? homes[0] : nil
    }

    static func reconcile(
        pathHome: RealUserHome?,
        uidHome: RealUserHome?
    ) -> RealUserHome? {
        guard let uidHome else { return nil }
        guard pathHome == nil || pathHome?.userID == uidHome.userID else {
            return nil
        }
        return uidHome
    }

    /// Path-aware identity join used by event provenance. A path lexically
    /// under an unvalidated `/Users/<name>` must not be treated like a neutral
    /// system or volume path: doing so would let the event uid silently select
    /// a different account's databases. `/Users/Shared` is the explicit
    /// exception because it is intentionally not an account home and the event
    /// uid remains the only user identity attached to an object stored there.
    static func reconcileProvenance(
        path: String,
        pathHome: RealUserHome?,
        uidHome: RealUserHome?
    ) -> RealUserHome? {
        guard let normalized = normalizedAbsolutePath(path) else { return nil }
        if pathHome == nil,
           (normalized == "/Users" || normalized.hasPrefix("/Users/")),
           normalized != "/Users/Shared",
           !normalized.hasPrefix("/Users/Shared/") {
            return nil
        }
        return reconcile(pathHome: pathHome, uidHome: uidHome)
    }

    private struct PasswdRecord {
        let name: String
        let home: String
    }

    private static func passwdRecord(for userID: UInt32) -> PasswdRecord? {
        var record = passwd()
        var result: UnsafeMutablePointer<passwd>?
        let configured = sysconf(_SC_GETPW_R_SIZE_MAX)
        let size = configured > 0 ? Int(configured) : 16 * 1024
        var buffer = [CChar](repeating: 0, count: max(size, 1024))
        let rc = buffer.withUnsafeMutableBufferPointer { storage in
            getpwuid_r(
                userID,
                &record,
                storage.baseAddress,
                storage.count,
                &result
            )
        }
        guard rc == 0, result != nil,
              let namePointer = record.pw_name,
              let homePointer = record.pw_dir else {
            return nil
        }
        let name = String(cString: namePointer)
        let home = String(cString: homePointer)
        guard !name.isEmpty, !home.isEmpty else { return nil }
        return PasswdRecord(name: name, home: home)
    }

    /// Resolve every component from a pinned parent descriptor.  A path-based
    /// lstat/open sequence still follows or can race an intermediate symlink.
    private static func descriptorMetadata(forDirectory path: String) -> stat? {
        guard let normalized = normalizedAbsolutePath(path), normalized != "/" else {
            return nil
        }
        let components = normalized.dropFirst().split(separator: "/").map(String.init)
        guard !components.isEmpty else { return nil }

        var descriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        )
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }

        for component in components {
            let next = component.withCString {
                Darwin.openat(
                    descriptor,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
                )
            }
            guard next >= 0 else { return nil }
            Darwin.close(descriptor)
            descriptor = next
        }

        var metadata = stat()
        guard Darwin.fstat(descriptor, &metadata) == 0,
              (metadata.st_mode & S_IFMT) == S_IFDIR else {
            return nil
        }
        return metadata
    }

    static func noFollowOwner(of path: String) -> UInt32? {
        guard let normalized = normalizedAbsolutePath(path), normalized != "/" else {
            return nil
        }
        let components = normalized.dropFirst().split(separator: "/").map(String.init)
        guard !components.isEmpty else { return nil }

        var descriptor = Darwin.open(
            "/",
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        )
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }

        for component in components.dropLast() {
            let next = component.withCString {
                Darwin.openat(
                    descriptor,
                    $0,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
                )
            }
            guard next >= 0 else { return nil }
            Darwin.close(descriptor)
            descriptor = next
        }

        var metadata = stat()
        guard let leaf = components.last,
              leaf.withCString({
                  Darwin.fstatat(descriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
              }) == 0,
              (metadata.st_mode & S_IFMT) != S_IFLNK else {
            return nil
        }
        return metadata.st_uid
    }

    private static func normalizedAbsolutePath(_ path: String) -> String? {
        guard !path.isEmpty, !path.utf8.contains(0), path.hasPrefix("/") else {
            return nil
        }
        let normalized = (path as NSString).standardizingPath
        guard normalized.hasPrefix("/"), normalized != "/", !normalized.contains("/../") else {
            return nil
        }
        return normalized
    }
}
