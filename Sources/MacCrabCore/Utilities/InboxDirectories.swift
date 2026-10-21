import Darwin
import Foundation

/// Where control-plane requests are dropped for the engine. Anyone can create
/// a file in the public inbox (mode 1777), and a root-owned file there proves
/// nothing: a user can keep a hard link to an inode the engine later replaces,
/// then rename it in. Root-authored requests therefore go to a root-only
/// inbox, and the engine accepts root ownership from nowhere else.
public enum InboxDirectories {
    public static let publicName = "inbox"
    public static let rootName = "inbox-root"

    /// The inbox a request written with `effectiveUID` belongs in.
    public static func requestDirectory(dataDir: String, effectiveUID: uid_t = geteuid()) -> String {
        dataDir + "/" + (effectiveUID == 0 ? rootName : publicName)
    }

    /// The inbox for this process's requests, created if missing. The
    /// root-only inbox must be a private directory (see `isPrivateDirectory`);
    /// anything else is refused rather than written into.
    public static func preparedRequestDirectory(
        dataDir: String, effectiveUID: uid_t = geteuid()
    ) throws -> String {
        let directory = requestDirectory(dataDir: dataDir, effectiveUID: effectiveUID)
        guard effectiveUID == 0 else {
            try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
            return directory
        }
        if mkdir(directory, 0o700) != 0, errno != EEXIST {
            throw RuntimeConfigContractError("Cannot create the root-only request inbox (errno \(errno))")
        }
        guard isPrivateDirectory(at: directory) else {
            throw RuntimeConfigContractError(
                "Refusing the root-only request inbox: it is not a private directory owned by this user")
        }
        return directory
    }

    /// A real directory (not a link) owned by this process's user, mode 0700,
    /// with no extended ACL: an access-control entry would let another user
    /// add or rename a request in despite the mode.
    public static func isPrivateDirectory(at path: String) -> Bool {
        var pathInfo = stat()
        guard lstat(path, &pathInfo) == 0,
              (pathInfo.st_mode & S_IFMT) == S_IFDIR,
              pathInfo.st_uid == geteuid(),
              (pathInfo.st_mode & 0o7777) == 0o700 else { return false }
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return false }
        defer { close(descriptor) }
        var openedInfo = stat()
        guard fstat(descriptor, &openedInfo) == 0,
              openedInfo.st_dev == pathInfo.st_dev,
              openedInfo.st_ino == pathInfo.st_ino else { return false }
        return TraceBundlePrivateFilePolicy.hasNoExtendedACL(descriptor)
    }
}
