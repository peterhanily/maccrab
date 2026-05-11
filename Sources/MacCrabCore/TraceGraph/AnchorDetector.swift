// AnchorDetector.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-8 ingestion tail) — classifies normalized
// events into trace anchors per §14.1 of the v1.10.0 spec.
//
// PR-8 covers the anchor types that fall out of the event payload
// itself:
//
//   - credential file access
//   - persistence creation (LaunchAgent/Daemon, loginItem, etc.)
//   - AI-agent process spawning a shell
//   - unsigned binary executing from a download path
//   - external network connection from an AI-agent process
//
// The remaining anchor types in §14.1 (rule hit + sequence
// completion + campaign completion + user-requested) need explicit
// integration with the existing v1.9 engines — they're surfaced via
// `recordExternalAnchor(...)` rather than re-implementing detection
// logic here.

import Foundation

public enum AnchorTrigger: Sendable, Equatable {
    case credentialAccess(processEntityId: String, fileEntityId: String)
    case persistenceCreated(processEntityId: String, persistenceEntityId: String)
    case aiAgentSpawnsShell(agentEntityId: String, processEntityId: String)
    case unsignedDownloadExecution(processEntityId: String)
    case externalNetworkFromAgent(agentEntityId: String, networkEntityId: String)
    case external(reason: String, anchorEntityId: String)

    public var anchorEntityId: String {
        switch self {
        case .credentialAccess(_, let fileId):           return fileId
        case .persistenceCreated(_, let persistenceId):  return persistenceId
        case .aiAgentSpawnsShell(_, let processId):      return processId
        case .unsignedDownloadExecution(let processId):  return processId
        case .externalNetworkFromAgent(_, let netId):    return netId
        case .external(_, let anchorId):                 return anchorId
        }
    }

    public var defaultSeverity: String {
        switch self {
        case .credentialAccess:           return "high"
        case .persistenceCreated:         return "high"
        case .aiAgentSpawnsShell:         return "high"
        case .unsignedDownloadExecution:  return "high"
        case .externalNetworkFromAgent:   return "medium"
        case .external:                   return "medium"
        }
    }

    public var defaultTitle: String {
        switch self {
        case .credentialAccess:                 return "Credential file access"
        case .persistenceCreated:               return "Persistence mechanism created"
        case .aiAgentSpawnsShell:               return "AI agent spawned a shell"
        case .unsignedDownloadExecution:        return "Unsigned binary executed from download path"
        case .externalNetworkFromAgent:         return "AI-agent process opened external network connection"
        case .external(let reason, _):          return reason
        }
    }
}

/// Stateless classifier — given the typed nodes produced for an event
/// plus its enrichment context, returns any anchors the event triggers.
public enum AnchorDetector {

    public struct EventContext: Sendable {
        public let processNode: ProcessNode
        public let fileNode: FileNode?
        public let networkNode: NetworkNode?
        public let persistenceNode: PersistenceNode?
        public let agentEntityId: String?
        public let policy: TracePolicy

        public init(
            processNode: ProcessNode,
            fileNode: FileNode? = nil,
            networkNode: NetworkNode? = nil,
            persistenceNode: PersistenceNode? = nil,
            agentEntityId: String? = nil,
            policy: TracePolicy = .default
        ) {
            self.processNode = processNode
            self.fileNode = fileNode
            self.networkNode = networkNode
            self.persistenceNode = persistenceNode
            self.agentEntityId = agentEntityId
            self.policy = policy
        }
    }

    /// Returns every anchor the event triggers, in declaration order
    /// (credential first, persistence next, etc.). Multiple anchors
    /// per event are possible (a credential access by an AI-agent
    /// process triggers both the credential and the agent-shell
    /// anchors); the caller (RollingCausalGraph) materializes per
    /// anchor and dedupes via the trace store.
    public static func classify(_ context: EventContext) -> [AnchorTrigger] {
        var anchors: [AnchorTrigger] = []
        let processEntityId = ProcessNode.entityType + ":" + context.processNode.processKey

        // 1. Credential file access
        if let file = context.fileNode, file.fileKind == .credentialFile {
            let fileEntityId = FileNode.entityType + ":" + file.pathHash
            anchors.append(.credentialAccess(processEntityId: processEntityId, fileEntityId: fileEntityId))
        }

        // 2. Persistence creation
        if let persistence = context.persistenceNode {
            let persistenceEntityId = PersistenceNode.entityType
                + ":" + "\(persistence.persistenceType.rawValue):\(persistence.path)"
            anchors.append(.persistenceCreated(processEntityId: processEntityId, persistenceEntityId: persistenceEntityId))
        }

        // 3. Unsigned binary from download path
        if !context.processNode.isAppleSigned,
           context.policy.trustedConduitPolicy.isPathInDenylist(context.processNode.executablePath) {
            anchors.append(.unsignedDownloadExecution(processEntityId: processEntityId))
        }

        // 4. AI agent spawning a shell
        if let agentEntityId = context.agentEntityId,
           Self.isShellExecutable(context.processNode.executablePath) {
            anchors.append(.aiAgentSpawnsShell(agentEntityId: agentEntityId, processEntityId: processEntityId))
        }

        // 5. External network from AI-agent process
        if let agentEntityId = context.agentEntityId, let net = context.networkNode {
            if Self.isExternalNetwork(net) {
                let networkEntityId = NetworkNode.entityType + ":" + net.stableKey
                anchors.append(.externalNetworkFromAgent(agentEntityId: agentEntityId, networkEntityId: networkEntityId))
            }
        }

        return anchors
    }

    public static func isShellExecutable(_ path: String) -> Bool {
        let shells: Set<String> = ["zsh", "bash", "sh", "fish", "ksh", "csh", "tcsh", "osascript"]
        let basename = (path as NSString).lastPathComponent
        return shells.contains(basename)
    }

    public static func isExternalNetwork(_ net: NetworkNode) -> Bool {
        // Treat anything not in a private-range / known-good as external
        // for anchor purposes. The reputation enum already encodes this.
        switch net.reputation {
        case .knownGood, .privateRange:
            return false
        case .unknown, .suspicious, .malicious:
            return true
        }
    }
}
