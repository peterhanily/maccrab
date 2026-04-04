// CredentialFence.swift
// MacCrabCore
//
// Monitors sensitive file access by AI coding tool child processes.
// Alerts when AI tools read SSH keys, environment files, AWS credentials,
// API tokens, or other secrets that should not be accessed during normal
// code generation.

import Foundation
import os.log

/// Detects when AI coding tool processes access sensitive credential files.
///
/// Maintains a list of sensitive file paths/patterns and checks every file
/// event from AI tool children. Generates critical alerts for credential
/// access and feeds into behavioral scoring.
public struct CredentialFence: Sendable {

    private static let logger = Logger(subsystem: "com.maccrab", category: "credential-fence")

    // MARK: - Sensitive Path Definitions

    /// Categories of sensitive files with their path patterns.
    public enum CredentialType: String, Sendable {
        case sshKey = "SSH Private Key"
        case gpgKey = "GPG Key"
        case awsCredential = "AWS Credential"
        case githubToken = "GitHub Token"
        case netrc = "Network Credentials (.netrc)"
        case npmToken = "npm Token"
        case pypiToken = "PyPI Token"
        case dockerAuth = "Docker Registry Auth"
        case envFile = "Environment File (.env)"
        case keychain = "Keychain Database"
        case passwordManager = "Password Manager Data"
        case kubeConfig = "Kubernetes Config"
        case gcpCredential = "GCP Service Account"
        case azureCredential = "Azure Credential"
        case slackToken = "Slack Token"
        case browserCredential = "Browser Credential Store"
    }

    /// A sensitive path pattern and its credential type.
    public struct SensitivePath: Sendable {
        public let pattern: String
        public let type: CredentialType
        public let isPrefix: Bool // true = matches prefix, false = matches contains

        public init(_ pattern: String, type: CredentialType, isPrefix: Bool = false) {
            self.pattern = pattern
            self.type = type
            self.isPrefix = isPrefix
        }
    }

    /// Default sensitive paths to monitor.
    public static let defaultPaths: [SensitivePath] = [
        // SSH
        SensitivePath("/.ssh/id_", type: .sshKey),
        SensitivePath("/.ssh/config", type: .sshKey),
        SensitivePath("/.ssh/known_hosts", type: .sshKey),

        // GPG
        SensitivePath("/.gnupg/private-keys", type: .gpgKey),
        SensitivePath("/.gnupg/secring", type: .gpgKey),

        // AWS
        SensitivePath("/.aws/credentials", type: .awsCredential),
        SensitivePath("/.aws/config", type: .awsCredential),

        // GitHub
        SensitivePath("/.config/gh/hosts.yml", type: .githubToken),
        SensitivePath("/.config/gh/config.yml", type: .githubToken),

        // Network auth
        SensitivePath("/.netrc", type: .netrc),

        // Package manager tokens
        SensitivePath("/.npmrc", type: .npmToken),
        SensitivePath("/.pypirc", type: .pypiToken),
        SensitivePath("/.cargo/credentials", type: .npmToken),

        // Docker
        SensitivePath("/.docker/config.json", type: .dockerAuth),

        // Environment files
        SensitivePath("/.env", type: .envFile),
        SensitivePath(".env.local", type: .envFile),
        SensitivePath(".env.production", type: .envFile),
        SensitivePath(".env.staging", type: .envFile),

        // Kubernetes
        SensitivePath("/.kube/config", type: .kubeConfig),

        // GCP
        SensitivePath("/gcloud/credentials", type: .gcpCredential),
        SensitivePath("/gcloud/application_default_credentials", type: .gcpCredential),

        // Azure
        SensitivePath("/.azure/", type: .azureCredential),

        // Keychain
        SensitivePath("/Library/Keychains/", type: .keychain),

        // Password managers
        SensitivePath("/1Password/", type: .passwordManager),
        SensitivePath("/Bitwarden/", type: .passwordManager),

        // Browser credentials
        SensitivePath("/Login Data", type: .browserCredential),
        SensitivePath("/Cookies", type: .browserCredential),
        SensitivePath("/logins.json", type: .browserCredential),
    ]

    /// Custom additional paths (user-configurable).
    private let customPaths: [SensitivePath]

    /// All paths to check (default + custom).
    private var allPaths: [SensitivePath] {
        Self.defaultPaths + customPaths
    }

    // MARK: - Initialization

    public init(customPaths: [SensitivePath] = []) {
        self.customPaths = customPaths
    }

    // MARK: - Public API

    /// Check if a file path accesses sensitive credentials.
    /// Returns the credential type if it matches, nil if safe.
    public func checkAccess(filePath: String) -> CredentialType? {
        let path = filePath.lowercased()
        let homePath = NSHomeDirectory().lowercased()

        for sensitive in allPaths {
            let pattern = sensitive.pattern.lowercased()

            if sensitive.isPrefix {
                if path.hasPrefix(pattern) || path.hasPrefix(homePath + pattern) {
                    return sensitive.type
                }
            } else {
                if path.contains(pattern) {
                    return sensitive.type
                }
            }
        }

        return nil
    }

    /// Check a file path and return a detailed description for alerting.
    public func checkAccessDetailed(filePath: String, aiToolName: String) -> (type: CredentialType, description: String)? {
        guard let credType = checkAccess(filePath: filePath) else { return nil }

        let filename = (filePath as NSString).lastPathComponent
        let description = "\(aiToolName) child process accessed \(credType.rawValue): \(filename) at \(filePath). " +
            "AI coding tools should not need to read credential files during normal code generation. " +
            "This may indicate prompt injection causing the AI to exfiltrate secrets."

        return (credType, description)
    }

    /// Get all sensitive path patterns (for UI display).
    public static var allPatterns: [(String, String)] {
        defaultPaths.map { ($0.pattern, $0.type.rawValue) }
    }
}
