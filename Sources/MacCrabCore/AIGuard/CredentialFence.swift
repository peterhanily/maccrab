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

    /// How a `SensitivePath` pattern is matched against a file path.
    ///
    /// v1.17.2: replaced the old unanchored `contains` with anchored kinds.
    /// The substring match caused the dominant AI-Guard credential false
    /// positives — `.env` matched `.env.example`/`environment.ts`, `/Cookies`
    /// matched `src/Cookies.tsx`, `/Login Data` matched any path containing
    /// that text. Anchoring on real path boundaries fixes that while keeping
    /// the genuine credential files matched.
    public enum MatchKind: Sendable {
        /// The path's LAST component equals the pattern exactly (case-insensitive).
        /// e.g. `.env`, `.netrc`, `Login Data`, `logins.json`, `Cookies`.
        case exactFilename
        /// The path's last component STARTS WITH the pattern. For families like
        /// `.env.local`/`.env.production` (pattern `.env.`) and `id_rsa`/`id_ed25519`.
        case filenamePrefix
        /// The pattern appears as a full slash-bounded path fragment, e.g.
        /// `/.ssh/id_`, `/.aws/credentials`, `/Library/Keychains/`. Anchored so
        /// it can't match mid-component (a dir literally named that, not a
        /// substring of an unrelated path).
        case pathFragment
    }

    /// A sensitive path pattern and its credential type.
    public struct SensitivePath: Sendable {
        public let pattern: String
        public let type: CredentialType
        public let kind: MatchKind

        public init(_ pattern: String, type: CredentialType, kind: MatchKind = .pathFragment) {
            self.pattern = pattern
            self.type = type
            self.kind = kind
        }
    }

    /// Default sensitive paths to monitor. Each carries an anchored MatchKind
    /// (v1.17.2) so a credential file is matched precisely without snagging
    /// look-alike source files (`.env.example`, `Cookies.tsx`, `config.ts`).
    public static let defaultPaths: [SensitivePath] = [
        // SSH private keys — anchored to the ~/.ssh/ dir (a bare `id_` filename
        // prefix matched any file named id_* anywhere, e.g. id_token.ts). The
        // public-key sibling id_*.pub is excluded in checkAccess (not a secret).
        SensitivePath("/.ssh/id_rsa", type: .sshKey, kind: .pathFragment),
        SensitivePath("/.ssh/id_ed25519", type: .sshKey, kind: .pathFragment),
        SensitivePath("/.ssh/id_ecdsa", type: .sshKey, kind: .pathFragment),
        SensitivePath("/.ssh/id_dsa", type: .sshKey, kind: .pathFragment),
        SensitivePath("/.ssh/config", type: .sshKey, kind: .pathFragment),
        // AI-07: `~/.ssh/known_hosts` removed. It holds HASHED remote host
        // PUBLIC keys — it is not key material and reading it leaks no secret,
        // yet it is touched by every git/ssh operation and was a steady
        // contributor to this rule's ~60-70% live FP rate. `~/.ssh/config`
        // is kept: it is also not key material, but it enumerates internal
        // hosts, IdentityFile locations and ProxyCommand, which is genuine
        // recon value for an agent that has no business reading it.

        // GPG
        SensitivePath("/.gnupg/private-keys", type: .gpgKey, kind: .pathFragment),
        SensitivePath("/.gnupg/secring", type: .gpgKey, kind: .pathFragment),

        // AWS — anchored to the ~/.aws/ dir so a project `config` file is safe.
        SensitivePath("/.aws/credentials", type: .awsCredential, kind: .pathFragment),
        // AI-07: `~/.aws/config` removed — it holds region / profile / role-arn
        // and SSO start URLs, not access keys. The keys live in the
        // `~/.aws/credentials` entry above, which is retained. Every `aws` CLI
        // invocation reads config, so matching it produced steady FPs while
        // adding no credential-theft signal the credentials entry doesn't give.

        // GitHub
        SensitivePath("/.config/gh/hosts.yml", type: .githubToken, kind: .pathFragment),
        SensitivePath("/.config/gh/config.yml", type: .githubToken, kind: .pathFragment),

        // Network auth
        SensitivePath(".netrc", type: .netrc, kind: .exactFilename),

        // Package manager tokens
        SensitivePath(".npmrc", type: .npmToken, kind: .exactFilename),
        SensitivePath(".pypirc", type: .pypiToken, kind: .exactFilename),
        SensitivePath("/.cargo/credentials", type: .npmToken, kind: .pathFragment),

        // Docker
        SensitivePath("/.docker/config.json", type: .dockerAuth, kind: .pathFragment),

        // Environment files — `.env` and the `.env.<stage>` family, but NOT
        // `.env.example` / `.env.sample` / `.env.template` (committed templates
        // with no secrets — the single biggest source of the old FP). Those are
        // excluded explicitly in checkAccess.
        SensitivePath(".env", type: .envFile, kind: .exactFilename),
        SensitivePath(".env.", type: .envFile, kind: .filenamePrefix),

        // Kubernetes
        SensitivePath("/.kube/config", type: .kubeConfig, kind: .pathFragment),

        // GCP
        SensitivePath("/gcloud/credentials", type: .gcpCredential, kind: .pathFragment),
        SensitivePath("/gcloud/application_default_credentials", type: .gcpCredential, kind: .pathFragment),

        // Azure
        SensitivePath("/.azure/", type: .azureCredential, kind: .pathFragment),

        // Keychain
        SensitivePath("/Library/Keychains/", type: .keychain, kind: .pathFragment),

        // Password managers
        SensitivePath("/1Password/", type: .passwordManager, kind: .pathFragment),
        SensitivePath("/Bitwarden/", type: .passwordManager, kind: .pathFragment),

        // Browser credentials — exact filenames (Chrome "Login Data"/"Cookies",
        // Firefox logins.json) so a project file named Cookies.tsx is safe.
        SensitivePath("Login Data", type: .browserCredential, kind: .exactFilename),
        SensitivePath("Cookies", type: .browserCredential, kind: .exactFilename),
        SensitivePath("logins.json", type: .browserCredential, kind: .exactFilename),
    ]

    /// Filenames that look like env files but are committed, secret-free
    /// templates — never credential reads. The dominant historical FP.
    private static let envTemplateSuffixes = [
        ".example", ".sample", ".template", ".dist", ".tmpl",
    ]

    /// Path fragments that are MacCrab's own / deception assets — reading these
    /// is never an exfil signal and must not self-trip the fence.
    private static let selfExclusionFragments = [
        "/library/application support/maccrab/",
        "/.maccrab/",
        "/decoys/",            // honey-prompt bait dir
        // AI-07: MacCrab's OWN test fixtures were tripping MacCrab's own fence.
        // TierBBrokeredTCCTests builds fake homes at `NSTemporaryDirectory() +
        // "tcc-home-<uuid>"` containing credentials.bak / id_rsa.old /
        // hosts.yml.bak / .netrc.backup, and `swiftpm-testing-helper` reading
        // them produced 194 live `ai-guard.credential-access` alerts — i.e.
        // every `swift test` run generated AI-credential-theft alerts about
        // MacCrab. Anchored under the per-user temp dir component (`/T/` in
        // NSTemporaryDirectory, lowercased to `/t/` before this is matched) so
        // a directory merely NAMED `tcc-home-` elsewhere on disk can't be used
        // to hide credential reads from the fence.
        "/t/tcc-home-",
    ]

    /// Credential stores that a given binary legitimately OWNS, keyed on the
    /// ACCESSING binary's basename (lowercased) → the slash-bounded path
    /// fragments it owns. Fragments are matched against the lowercased path.
    ///
    /// AI-07: the fence had no notion of ownership at all, so on a developer
    /// Mac the flagship AI-Guard detection was majority noise — of 777 live
    /// alerts, `gh` reading its OWN `~/.config/gh/hosts.yml` was 218, and
    /// Chrome + its helpers reading their OWN cookie store / login keychain
    /// was ~98. A tool reading the store it owns is the tool working. A tool
    /// reading SOMEONE ELSE'S store (gh touching ~/.aws, node touching ~/.ssh)
    /// still alerts — that cross-store read is the signal this fence exists to
    /// give, and it is untouched by this table.
    ///
    /// Known limitation, deliberately accepted for now: this keys on basename,
    /// not on signing identity, so a binary that renames itself `gh` can read
    /// `~/.config/gh/` unflagged. That is a narrow win (one store, and only the
    /// store matching the assumed name) against a large, sustained noise cost.
    /// Upgrading the key to the accessor's Team ID / signing identifier is the
    /// right follow-up and needs the caller to pass the code signature.
    private static let credentialOwners: [String: [String]] = [
        "gh":               ["/.config/gh/"],
        "git":              ["/.ssh/", ".netrc"],
        "git-credential-osxkeychain": ["/library/keychains/", ".netrc"],
        "ssh":              ["/.ssh/"],
        "ssh-add":          ["/.ssh/"],
        "ssh-keygen":       ["/.ssh/"],
        "scp":              ["/.ssh/"],
        "sftp":             ["/.ssh/"],
        "aws":              ["/.aws/"],
        "docker":           ["/.docker/"],
        "kubectl":          ["/.kube/"],
        "gcloud":           ["/gcloud/"],
        "az":               ["/.azure/"],
        "npm":              [".npmrc"],
        "pnpm":             [".npmrc"],
        "yarn":             [".npmrc"],
        "twine":            [".pypirc"],
        "cargo":            ["/.cargo/"],
        "google chrome":        ["/google/chrome/", "/library/keychains/"],
        "google chrome helper": ["/google/chrome/", "/library/keychains/"],
        "chrome-headless-shell": ["/google/chrome/", "/chrome-headless-shell/"],
        "firefox":          ["/firefox/profiles/"],
        "safari":           ["/safari/"],
        "brave browser":    ["/bravesoftware/", "/library/keychains/"],
    ]

    /// True when `binary` (a lowercased basename) is the legitimate owner of
    /// the credential store at `path` (already lowercased).
    private static func isOwnCredentialStore(binary: String, path: String) -> Bool {
        guard let owned = credentialOwners[binary] else { return false }
        return owned.contains { path.contains($0) }
    }

    /// Custom additional paths (user-configurable).
    private let customPaths: [SensitivePath]

    // MARK: - Initialization

    public init(customPaths: [SensitivePath] = []) {
        self.customPaths = customPaths
    }

    // MARK: - Public API

    /// Check if a file path accesses sensitive credentials.
    /// Returns the credential type if it matches, nil if safe.
    public func checkAccess(filePath: String) -> CredentialType? {
        if customPaths.isEmpty {
            return Self.defaultCredentialType(filePath: filePath)
        }
        return Self.matchCredential(
            filePath: filePath,
            sensitivePaths: Self.defaultPaths + customPaths
        )
    }

    /// Canonical built-in classifier shared by downstream consumers that need
    /// the fence's exact path semantics but do not have user-supplied patterns.
    /// Keeping this as the one implementation prevents a second credential
    /// allowlist from drifting as the built-in corpus evolves.
    static func defaultCredentialType(filePath: String) -> CredentialType? {
        matchCredential(filePath: filePath, sensitivePaths: defaultPaths)
    }

    /// Broader privacy boundary for path-bearing AgentLineage snapshots.
    /// Some files are inappropriate to persist even when reading them is not
    /// itself an alert-worthy credential event (AWS region config, SSO cache,
    /// browser profiles, public SSH authorization metadata). Keep this as one
    /// owner-side classifier; EventLoop and AgentLineage must delegate here
    /// rather than maintaining parallel substring lists.
    public static func isPrivateAgentLineagePath(_ filePath: String) -> Bool {
        if defaultCredentialType(filePath: filePath) != nil { return true }
        let path = filePath.lowercased()
        return path.contains("/.aws/config")
            || path.contains("/.aws/sso/cache/")
            || path.contains("/.bw/data.json")
            || path.contains("/.config/op/")
            || path.contains("/group containers/2bua8c4s2c.com.agilebits/")
            || path.contains("/group containers/2bua8c4s2c.com.1password/")
            || path.contains("/.ssh/authorized_keys")
            || path.hasSuffix("/.gitconfig")
            || path.contains("/library/application support/google/chrome/")
            || path.contains("/library/application support/firefox/")
            || path.contains("/library/application support/bravesoftware/")
            || path.contains("/library/application support/microsoft edge/")
            || path.contains("/library/application support/arc/")
            || path.contains("/library/application support/vivaldi/")
            || path.contains("/library/application support/com.operasoftware.opera/")
            || path.contains("/library/safari/")
            || path.contains("/library/containers/com.apple.safari/")
            || path.hasSuffix("/cookies.binarycookies")
    }

    private static func matchCredential(
        filePath: String,
        sensitivePaths: [SensitivePath]
    ) -> CredentialType? {
        let path = filePath.lowercased()
        let filename = (path as NSString).lastPathComponent

        // Self / deception exclusion — reading MacCrab's own files or the
        // honey-prompt bait is never a credential-exfil signal. (Honeyfile
        // hits are handled by the dedicated honeyfile_accessed rule.)
        for frag in Self.selfExclusionFragments where path.contains(frag) {
            return nil
        }

        // Committed env templates (.env.example / .sample / .template / …) are
        // secret-free and the dominant historical false positive.
        if filename.hasPrefix(".env") {
            for suffix in Self.envTemplateSuffixes where filename.hasSuffix(suffix) {
                return nil
            }
        }

        // SSH PUBLIC keys (id_rsa.pub etc.) are not secrets — reading them is
        // benign and must not trip the SSH-key match below.
        if filename.hasSuffix(".pub") { return nil }

        // The OS PUBLIC trust store (/System/Library/Keychains/ — SystemTrust
        // Settings.plist, SystemCACertificates.keychain, SystemRootCertificates)
        // is public cert-trust config, NOT a credential database. Reading it is
        // not credential theft, yet the `/Library/Keychains/` fragment below
        // matches it as a substring (audit: codesign/security flagged for it).
        if path.contains("/system/library/keychains/") { return nil }

        for sensitive in sensitivePaths {
            let pattern = sensitive.pattern.lowercased()
            switch sensitive.kind {
            case .exactFilename:
                if filename == pattern { return sensitive.type }
            case .filenamePrefix:
                // Anchored to the filename, not the whole path, so `id_` only
                // matches a file named id_* (not a dir or mid-path substring).
                if filename.hasPrefix(pattern) { return sensitive.type }
            case .pathFragment:
                // Slash-bounded fragment match — the pattern already carries
                // its own leading/trailing slashes where boundary-anchoring is
                // needed, so a plain contains here is anchored by construction
                // and can't match mid-component the way a bare token did.
                if path.contains(pattern) { return sensitive.type }
            }
        }

        return nil
    }

    /// Check a file path and return a detailed description for alerting.
    ///
    /// When `aiToolType` is supplied and the path lies inside THAT tool's own
    /// config/state dir, the read is the tool using its own auth (not exfil)
    /// and is down-weighted by returning nil. Hard guard: only the tool's own
    /// dirs count — shared/system stores (~/.aws, ~/.ssh, ~/.npmrc, .env,
    /// login.keychain-db, browser logins) are never "own", so cross-credential
    /// reads still alert, and the Sigma cred-theft rules (NoiseFilter Gate-8)
    /// are unaffected by this advisory path entirely.
    public func checkAccessDetailed(filePath: String, aiToolName: String, aiToolType: AIToolType? = nil,
                                    accessingBinary: String? = nil) -> (type: CredentialType, description: String)? {
        guard let credType = checkAccess(filePath: filePath) else { return nil }

        // AI-07: a NON-AI tool reading the credential store it owns is that
        // tool working, not credential theft — the same principle the
        // `isOwnedByTool` check below already applies to AI tools. Runtime:
        // `gh` → ~/.config/gh/hosts.yml was 218 of this rule's 777 alerts.
        // `accessingBinary` is a basename and is defaulted, so callers that
        // don't know the accessor keep the previous (stricter) behaviour.
        if let accessingBinary,
           Self.isOwnCredentialStore(binary: accessingBinary.lowercased(),
                                     path: filePath.lowercased()) {
            return nil
        }

        // v1.19.0 (D1 FP tuning): AI tool reading a credential file inside its
        // OWN store (e.g. Claude → ~/.claude/.credentials.json) is benign.
        if let aiToolType, AIToolRegistry.isOwnedByTool(filePath: filePath, toolType: aiToolType) {
            return nil
        }

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
