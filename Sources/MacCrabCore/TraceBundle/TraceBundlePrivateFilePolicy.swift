// TraceBundlePrivateFilePolicy.swift
//
// Exact descriptor-level privacy contract for trace evidence staged below a
// temporary or caller-selected directory. POSIX creation modes are filtered by
// umask and macOS can inherit extended ACLs independently of those bits, so a
// successful open/mkdir is not enough before sensitive bytes are written.

import Darwin
import Foundation

enum TraceBundlePrivateFilePolicy {
    static func enforceDirectory(_ descriptor: Int32) -> Bool {
        guard Darwin.fchmod(descriptor, mode_t(0o700)) == 0 else {
            return false
        }
        return validateDirectory(descriptor)
    }

    static func enforceRegularFile(_ descriptor: Int32) -> Bool {
        guard Darwin.fchmod(descriptor, mode_t(0o600)) == 0 else {
            return false
        }
        return validateRegularFile(descriptor)
    }

    static func validateDirectory(_ descriptor: Int32) -> Bool {
        var metadata = stat()
        return Darwin.fstat(descriptor, &metadata) == 0
            && (metadata.st_mode & S_IFMT) == S_IFDIR
            && (metadata.st_mode & mode_t(0o7777)) == mode_t(0o700)
            && metadata.st_uid == Darwin.geteuid()
            && hasNoExtendedACL(descriptor)
    }

    static func validateRegularFile(_ descriptor: Int32) -> Bool {
        var metadata = stat()
        return Darwin.fstat(descriptor, &metadata) == 0
            && (metadata.st_mode & S_IFMT) == S_IFREG
            && (metadata.st_mode & mode_t(0o7777)) == mode_t(0o600)
            && metadata.st_nlink == 1
            && metadata.st_uid == Darwin.geteuid()
            && metadata.st_size >= 0
            && hasNoExtendedACL(descriptor)
    }

    static func hasNoExtendedACL(_ descriptor: Int32) -> Bool {
        errno = 0
        guard let acl = Darwin.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
            return errno == ENOENT || errno == ENOTSUP || errno == EOPNOTSUPP
        }
        Darwin.acl_free(UnsafeMutableRawPointer(acl))
        return false
    }
}
