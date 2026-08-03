// AgentCapabilitiesCommands.swift
//
// Human authorization path for MCP mutation tiers. A request that grants a
// tier must be owned by root; a file dropped by the uid-501 app or MCP process
// is deliberately revoke-only. `sudo maccrabctl agent-capabilities ...` is the
// explicit user-presence boundary until MacCrab has an Authorization Services
// helper.

import Foundation
import Darwin

struct AgentCapabilitiesDocument: Equatable {
    static let tierNames = ["config", "authoring", "response"]

    var config = false
    var authoring = false
    var response = false

    init(dictionary: [String: Any] = [:]) {
        config = dictionary["config"] as? Bool ?? false
        authoring = dictionary["authoring"] as? Bool ?? false
        response = dictionary["response"] as? Bool ?? false
    }

    mutating func set(tier: String, enabled: Bool) -> Bool {
        switch tier {
        case "config": config = enabled
        case "authoring": authoring = enabled
        case "response": response = enabled
        default: return false
        }
        return true
    }

    var dictionary: [String: Any] {
        ["config": config, "authoring": authoring, "response": response]
    }
}

private enum AgentCapabilitiesCLIError: Error, LocalizedError {
    case unsafePath(String)
    case invalidState(String)
    case io(String)

    var errorDescription: String? {
        switch self {
        case .unsafePath(let message), .invalidState(let message), .io(let message):
            return message
        }
    }
}

func dispatchAgentCapabilities(args: [String]) {
    guard let subcommand = args.first else {
        printAgentCapabilitiesUsage()
        return
    }

    do {
        switch subcommand {
        case "show", "status":
            let current = try readInstalledAgentCapabilities()
            print("MCP agent capabilities (root-owned engine state):")
            print("  config:    \(current.config ? "ON" : "off")")
            print("  authoring: \(current.authoring ? "ON" : "off")")
            print("  response:  \(current.response ? "ON" : "off")")

        case "set":
            guard args.count == 3,
                  AgentCapabilitiesDocument.tierNames.contains(args[1]),
                  let enabled = parseCapabilityBoolean(args[2])
            else {
                throw AgentCapabilitiesCLIError.invalidState(
                    "Usage: maccrabctl agent-capabilities set <config|authoring|response> <on|off>")
            }
            guard geteuid() == 0 else {
                throw AgentCapabilitiesCLIError.invalidState(
                    "Capability grants require root authorization. Re-run as: sudo maccrabctl agent-capabilities set \(args[1]) \(enabled ? "on" : "off")")
            }
            var next = try readInstalledAgentCapabilities()
            _ = next.set(tier: args[1], enabled: enabled)
            try queueRootOwnedAgentCapabilities(next)
            print("Queued root-authorized MCP capability update: \(args[1])=\(enabled ? "on" : "off").")
            print("The running detection engine applies and audit-logs it on the next inbox poll.")

        case "disable-all":
            guard geteuid() == 0 else {
                throw AgentCapabilitiesCLIError.invalidState(
                    "Disabling all tiers through this command requires: sudo maccrabctl agent-capabilities disable-all")
            }
            try queueRootOwnedAgentCapabilities(AgentCapabilitiesDocument())
            print("Queued root-authorized revocation of all MCP mutation tiers.")

        case "help", "-h", "--help":
            printAgentCapabilitiesUsage()

        default:
            throw AgentCapabilitiesCLIError.invalidState(
                "Unknown agent-capabilities subcommand: \(subcommand)")
        }
    } catch {
        FileHandle.standardError.write(Data("agent-capabilities: \(error.localizedDescription)\n".utf8))
        exit(1)
    }
}

func parseCapabilityBoolean(_ raw: String) -> Bool? {
    switch raw.lowercased() {
    case "on", "true", "1", "yes": return true
    case "off", "false", "0", "no": return false
    default: return nil
    }
}

private func printAgentCapabilitiesUsage() {
    print("""
    Usage: maccrabctl agent-capabilities <subcommand>

      show
          Show the root-owned MCP mutation tiers.
      set <config|authoring|response> <on|off>
          Queue one tier change. Requires `sudo`; the engine applies and audits it.
      disable-all
          Revoke every mutation tier. Requires `sudo` on this explicit authority path.

    An app/MCP process running as the console user cannot grant itself a tier.
    """)
}

private let installedCapabilitiesPath =
    "/Library/Application Support/MacCrab/mcp_capabilities.json"
private let installedInboxPath =
    "/Library/Application Support/MacCrab/inbox"
private let maximumCapabilitiesBytes: off_t = 64 * 1024

/// Read only a regular, singly-linked, root-owned, non-writable-by-others file.
/// Missing state is the secure all-off default; malformed or unsafe existing
/// state is an error so a one-tier edit cannot silently reset unrelated grants.
private func readInstalledAgentCapabilities() throws -> AgentCapabilitiesDocument {
    var pathInfo = stat()
    if lstat(installedCapabilitiesPath, &pathInfo) != 0 {
        if errno == ENOENT { return AgentCapabilitiesDocument() }
        throw AgentCapabilitiesCLIError.io(
            "cannot inspect \(installedCapabilitiesPath): errno \(errno)")
    }
    guard (pathInfo.st_mode & S_IFMT) == S_IFREG,
          pathInfo.st_uid == 0,
          pathInfo.st_nlink == 1,
          (pathInfo.st_mode & (S_IWGRP | S_IWOTH)) == 0
    else {
        throw AgentCapabilitiesCLIError.unsafePath(
            "refusing unsafe capabilities file (must be regular, root-owned, single-link, and not group/world-writable): \(installedCapabilitiesPath)")
    }

    let fd = open(installedCapabilitiesPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else {
        throw AgentCapabilitiesCLIError.io(
            "cannot open \(installedCapabilitiesPath): errno \(errno)")
    }
    defer { close(fd) }

    var openedInfo = stat()
    guard fstat(fd, &openedInfo) == 0,
          (openedInfo.st_mode & S_IFMT) == S_IFREG,
          openedInfo.st_uid == 0,
          openedInfo.st_nlink == 1,
          openedInfo.st_dev == pathInfo.st_dev,
          openedInfo.st_ino == pathInfo.st_ino,
          openedInfo.st_size >= 0,
          openedInfo.st_size <= maximumCapabilitiesBytes,
          (openedInfo.st_mode & (S_IWGRP | S_IWOTH)) == 0
    else {
        throw AgentCapabilitiesCLIError.unsafePath(
            "capabilities file changed or failed validation while opening")
    }

    let data = try readBoundedFileDescriptor(fd, maximumBytes: maximumCapabilitiesBytes)
    guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          AgentCapabilitiesDocument.tierNames.allSatisfy({ json[$0] is Bool })
    else {
        throw AgentCapabilitiesCLIError.invalidState(
            "installed capabilities state is malformed; refusing to overwrite it")
    }
    return AgentCapabilitiesDocument(dictionary: json)
}

private func readBoundedFileDescriptor(_ fd: Int32, maximumBytes: off_t) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 4 * 1024)
    while true {
        let remaining = Int(maximumBytes) - result.count + 1
        guard remaining > 0 else {
            throw AgentCapabilitiesCLIError.invalidState("capabilities file exceeds size limit")
        }
        let requested = min(buffer.count, remaining)
        let count = buffer.withUnsafeMutableBytes {
            Darwin.read(fd, $0.baseAddress, requested)
        }
        if count == 0 { return result }
        if count < 0 {
            if errno == EINTR { continue }
            throw AgentCapabilitiesCLIError.io("capabilities read failed: errno \(errno)")
        }
        result.append(contentsOf: buffer[0..<count])
        if result.count > Int(maximumBytes) {
            throw AgentCapabilitiesCLIError.invalidState("capabilities file exceeds size limit")
        }
    }
}

private func queueRootOwnedAgentCapabilities(_ document: AgentCapabilitiesDocument) throws {
    guard geteuid() == 0 else {
        throw AgentCapabilitiesCLIError.invalidState("root authorization is required")
    }
    try validateOrCreateInstalledInbox()

    let payload = try JSONSerialization.data(
        withJSONObject: document.dictionary,
        options: [.sortedKeys]
    )
    let token = "\(getpid())-\(UUID().uuidString)"
    let temporaryPath = installedInboxPath + "/.set-agent-capabilities-\(token).tmp"
    let finalPath = installedInboxPath + "/set-agent-capabilities-\(token).json"
    let fd = open(
        temporaryPath,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        mode_t(0o600)
    )
    guard fd >= 0 else {
        throw AgentCapabilitiesCLIError.io(
            "cannot create root-owned capability request: errno \(errno)")
    }

    var writeSucceeded = false
    defer {
        close(fd)
        if !writeSucceeded { unlink(temporaryPath) }
    }
    var offset = 0
    while offset < payload.count {
        let count = payload.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return Darwin.write(fd, base.advanced(by: offset), payload.count - offset)
        }
        if count < 0 {
            if errno == EINTR { continue }
            throw AgentCapabilitiesCLIError.io("capability request write failed: errno \(errno)")
        }
        guard count > 0 else {
            throw AgentCapabilitiesCLIError.io("capability request write made no progress")
        }
        offset += count
    }
    guard fsync(fd) == 0 else {
        throw AgentCapabilitiesCLIError.io("capability request fsync failed: errno \(errno)")
    }
    guard rename(temporaryPath, finalPath) == 0 else {
        throw AgentCapabilitiesCLIError.io("capability request publish failed: errno \(errno)")
    }
    writeSucceeded = true
}

private func validateOrCreateInstalledInbox() throws {
    var info = stat()
    if lstat(installedInboxPath, &info) != 0 {
        guard errno == ENOENT else {
            throw AgentCapabilitiesCLIError.io(
                "cannot inspect capability inbox: errno \(errno)")
        }
        try FileManager.default.createDirectory(
            atPath: installedInboxPath,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o1777]
        )
        guard lstat(installedInboxPath, &info) == 0 else {
            throw AgentCapabilitiesCLIError.io(
                "cannot verify newly-created capability inbox: errno \(errno)")
        }
    }
    guard (info.st_mode & S_IFMT) == S_IFDIR, info.st_uid == 0 else {
        throw AgentCapabilitiesCLIError.unsafePath(
            "refusing capability inbox that is not a root-owned directory: \(installedInboxPath)")
    }
    guard chmod(installedInboxPath, 0o1777) == 0,
          lstat(installedInboxPath, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFDIR,
          info.st_uid == 0,
          (info.st_mode & S_ISVTX) != 0,
          (info.st_mode & S_IWOTH) != 0
    else {
        throw AgentCapabilitiesCLIError.unsafePath(
            "cannot establish the root-owned sticky capability inbox")
    }
}
