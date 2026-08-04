// TraceGraphFileObservationPolicy.swift
// MacCrabCore
//
// One canonical, synchronous path classifier shared by raw callback interest
// admission and RollingCausalGraph ingestion.  Keeping this outside the actor
// prevents the two high-rate boundaries from growing drift-prone copies.

import Foundation

public enum TraceGraphFileObservationPolicy {
    public enum CallbackAction: Sendable, Equatable {
        case read
        case write
        case create
        case rename
        case delete

        public var canCreatePersistence: Bool {
            self == .write || self == .create
        }
    }

    public struct Classification: Sendable, Equatable {
        public let fileKind: FileKind
        public let persistenceType: PersistenceType?

        public init(fileKind: FileKind, persistenceType: PersistenceType?) {
            self.fileKind = fileKind
            self.persistenceType = persistenceType
        }
    }

    /// Classify graph substrate without turning the broader sensitive-OPEN
    /// admission set into fake `credential_file` entities. CredentialFence is
    /// the semantic credential authority; persistence/path kinds follow.
    public nonisolated static func classify(path: String) -> Classification {
        let kind: FileKind
        if CredentialFence.defaultCredentialType(filePath: path) != nil {
            kind = .credentialFile
        } else if path.contains("/Library/LaunchAgents/") {
            kind = .launchAgent
        } else if path.contains("/Library/LaunchDaemons/") {
            kind = .launchDaemon
        } else if path.contains("/Library/LoginItems/") {
            kind = .loginItem
        } else if path.hasSuffix("/.zshrc") || path.hasSuffix("/.bashrc")
                    || path.hasSuffix("/.bash_profile") || path.hasSuffix("/.zprofile") {
            kind = .shellProfile
        } else if path.hasSuffix(".plist") {
            kind = .plist
        } else if path.hasSuffix(".sh") || path.hasSuffix(".py") || path.hasSuffix(".rb") {
            kind = .script
        } else if path.contains("/Downloads/") {
            kind = .browserDownload
        } else if path.contains("/node_modules/") {
            kind = .packageFile
        } else {
            kind = .unknown
        }
        return Classification(fileKind: kind, persistenceType: persistenceType(for: kind))
    }

    public nonisolated static func persistenceType(for kind: FileKind) -> PersistenceType? {
        switch kind {
        case .launchAgent: return .launchAgent
        case .launchDaemon: return .launchDaemon
        case .loginItem: return .loginItem
        case .shellProfile: return .shellProfile
        default: return nil
        }
    }

    /// One string mapping shared with EventToRollingCausalGraphBridge. nil means
    /// the file-shaped event never enters graph ingestion (BTM `btm_add`,
    /// chmod `setmode`, and future actions remain impossible until explicitly
    /// added to the bridge contract).
    public nonisolated static func callbackAction(eventAction: String) -> CallbackAction? {
        switch eventAction.lowercased() {
        case "open", "read": return .read
        case "write", "close_modified": return .write
        case "create": return .create
        case "rename": return .rename
        case "unlink", "delete": return .delete
        default: return nil
        }
    }

    /// The graph-local pre-SQL relevance contract. Sensitive ES OPEN paths are
    /// retained even when their truthful semantic kind is `.unknown` (Safari
    /// history, Notes, Messages, TCC, wallet evidence, deception paths).
    public nonisolated static func isRelevant(
        path: String? = nil,
        kind: FileKind,
        untrustedContent: Bool
    ) -> Bool {
        if untrustedContent { return true }
        if let path, ESCollector.isCredentialReadPath(path) { return true }
        switch kind {
        case .credentialFile, .launchAgent, .launchDaemon, .loginItem, .shellProfile:
            return true
        case .script, .binary, .plist, .browserDownload, .packageFile, .projectFile, .unknown:
            return false
        }
    }

    /// Necessary (not sufficient) raw-callback conditions for EventLoop to
    /// generate `untrusted_content=true`: an agent-content OPEN. AI attribution
    /// is evaluated against the atomically-published dynamic process snapshot;
    /// content scanning remains downstream and therefore unknown after this
    /// prerequisite succeeds.
    public nonisolated static func mayGenerateUntrustedContent(
        path: String,
        eventAction: String
    ) -> Bool {
        callbackAction(eventAction: eventAction) == .read
            && eventAction.lowercased() == "open"
            && ESCollector.isAgentContentReadPath(path)
    }
}
