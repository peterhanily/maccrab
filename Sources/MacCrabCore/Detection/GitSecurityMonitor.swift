// GitSecurityMonitor.swift
// MacCrabCore
//
// Monitors git credential access, SSH agent usage, and git hook execution.
// Detects credential theft via git, SSH agent forwarding hijack, and
// malicious git hooks from untrusted locations.

import Foundation
import os.log

/// Monitors git credential access, SSH agent usage, and git hook execution.
/// Detects credential theft via git, SSH agent forwarding hijack, and
/// malicious git hooks.
public actor GitSecurityMonitor {
    private let logger = Logger(subsystem: "com.maccrab.detection", category: "git-security")

    public enum GitThreatType: String, Sendable {
        case credentialHelperAbuse = "git_credential_abuse"
        case sshAgentHijack = "ssh_agent_hijack"
        case maliciousGitHook = "malicious_git_hook"
        case gitConfigModified = "git_config_modified"
        case gitCredentialStored = "git_credential_stored"
    }

    public struct GitSecurityEvent: Sendable {
        public let type: GitThreatType
        public let processName: String
        public let processPath: String
        public let pid: Int32
        public let detail: String
        public let severity: Severity
    }

    public init() {}

    /// Check a process event for git security threats.
    public func checkProcess(
        name: String,
        path: String,
        pid: Int32,
        commandLine: String,
        filePath: String?,
        envVars: [String: String]?
    ) -> GitSecurityEvent? {

        // 1. Git credential helper abuse
        if commandLine.contains("git credential") &&
           (commandLine.contains("fill") || commandLine.contains("approve")) {
            // Non-git process invoking credential helper
            if !path.hasSuffix("/git") && !path.hasSuffix("/git-credential-osxkeychain") {
                return GitSecurityEvent(
                    type: .credentialHelperAbuse,
                    processName: name, processPath: path, pid: pid,
                    detail: "Non-git process invoking git credential helper: \(commandLine.prefix(200))",
                    severity: .critical
                )
            }
        }

        // 2. SSH agent socket access by suspicious process
        if let envVars = envVars,
           let authSock = envVars["SSH_AUTH_SOCK"],
           !authSock.isEmpty {
            let suspiciousSSHUsers: Set<String> = [
                "curl", "wget", "python", "python3", "ruby", "node", "nc", "ncat",
            ]
            if suspiciousSSHUsers.contains(name) {
                return GitSecurityEvent(
                    type: .sshAgentHijack,
                    processName: name, processPath: path, pid: pid,
                    detail: "Suspicious process has SSH_AUTH_SOCK=\(authSock)",
                    severity: .high
                )
            }
        }

        // 3. Git hook execution from untrusted location
        if let filePath = filePath,
           filePath.contains(".git/hooks/"),
           commandLine.contains("/sh") || commandLine.contains("/bash") || commandLine.contains("/zsh") {
            // Check if the hook is in a temp or downloads directory
            if filePath.contains("/tmp/") || filePath.contains("/Downloads/") || filePath.contains("/Users/Shared/") {
                return GitSecurityEvent(
                    type: .maliciousGitHook,
                    processName: name, processPath: path, pid: pid,
                    detail: "Git hook executing from suspicious location: \(filePath)",
                    severity: .high
                )
            }
        }

        // 4. .gitconfig modification by non-git process
        if let filePath = filePath,
           filePath.hasSuffix("/.gitconfig") || filePath.hasSuffix("/.git/config") {
            if !path.hasSuffix("/git") && !path.hasSuffix("/git-config") {
                return GitSecurityEvent(
                    type: .gitConfigModified,
                    processName: name, processPath: path, pid: pid,
                    detail: "Non-git process modifying git config: \(filePath)",
                    severity: .medium
                )
            }
        }

        // 5. Git credential stored in plaintext
        if let filePath = filePath,
           filePath.hasSuffix("/.git-credentials") || filePath.hasSuffix("/.git-credential-store") {
            return GitSecurityEvent(
                type: .gitCredentialStored,
                processName: name, processPath: path, pid: pid,
                detail: "Git credentials being stored in plaintext file: \(filePath)",
                severity: .high
            )
        }

        return nil
    }
}
