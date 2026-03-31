// FileInfo.swift
// HawkEyeCore
//
// File event metadata.
// Field names follow the Elastic Common Schema (ECS) for Sigma compatibility.

import Foundation

// MARK: - FileInfo

/// Describes a file operation that triggered an event.
///
/// Maps to ECS `file.*` fields and Sigma `TargetFilename`, etc.
public struct FileInfo: Codable, Sendable, Hashable {

    /// Full path to the target file (ECS `file.path`, Sigma `TargetFilename`).
    public let path: String

    /// Base name of the file (ECS `file.name`).
    public let name: String

    /// Directory containing the file (ECS `file.directory`).
    public let directory: String

    /// File extension without the leading dot, if any (ECS `file.extension`).
    /// Named with a trailing underscore to avoid colliding with the Swift keyword.
    public let extension_: String?

    /// File size in bytes at the time of the event, if known.
    public let size: UInt64?

    /// The specific file operation that occurred.
    public let action: FileAction

    /// Original path before a rename operation. `nil` for non-rename actions.
    public let sourcePath: String?

    // MARK: CodingKeys

    private enum CodingKeys: String, CodingKey {
        case path
        case name
        case directory
        case extension_ = "extension"
        case size
        case action
        case sourcePath
    }

    // MARK: Initializer

    public init(
        path: String,
        name: String,
        directory: String,
        extension_: String? = nil,
        size: UInt64? = nil,
        action: FileAction,
        sourcePath: String? = nil
    ) {
        self.path = path
        self.name = name
        self.directory = directory
        self.extension_ = extension_
        self.size = size
        self.action = action
        self.sourcePath = sourcePath
    }
}

// MARK: - Convenience initializer

extension FileInfo {

    /// Creates a `FileInfo` by automatically deriving `name`, `directory`, and
    /// `extension_` from the supplied `path`.
    public init(
        path: String,
        size: UInt64? = nil,
        action: FileAction,
        sourcePath: String? = nil
    ) {
        let url = URL(fileURLWithPath: path)
        self.path = path
        self.name = url.lastPathComponent
        self.directory = url.deletingLastPathComponent().path
        self.extension_ = url.pathExtension.isEmpty ? nil : url.pathExtension
        self.size = size
        self.action = action
        self.sourcePath = sourcePath
    }
}
