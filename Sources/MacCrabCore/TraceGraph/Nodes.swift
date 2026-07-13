// Nodes.swift
// MacCrabCore
//
// v1.10 TraceGraph (PR-7) — typed entity types per §8 of the v1.10.0
// spec. Each node type carries its own shape and serializes into a
// `TraceEntity` row whose `entity_type` tag identifies the typed
// shape and `attributes_json` carries the type-specific payload.
//
// A `TraceGraphNode` (the protocol below) provides one place to
// declare the entity_type tag, the stableKey derivation, and the
// canonical TraceEntity construction. Per-type files were considered
// — these structs are small and live together better as one file.

import Foundation

// MARK: - TraceGraphNode protocol

/// Common shape every typed entity satisfies. The `toEntity()` helper
/// turns a typed node into the storage-level `TraceEntity` row by
/// JSON-encoding the node into `attributesJson` and tagging it with
/// `Self.entityType`.
public protocol TraceGraphNode: Sendable, Codable {
    /// String tag persisted in `trace_entities.entity_type`.
    static var entityType: String { get }

    /// Canonical key for this entity within its type. UNIQUE per
    /// (entity_type, stable_key) — this is the natural-key half of
    /// the §10.2 merge policy.
    var stableKey: String { get }

    /// Human-readable label for the dashboard / CLI.
    var displayName: String { get }

    var firstSeen: Date { get }
    var lastSeen: Date { get }
}

extension TraceGraphNode {

    /// Deterministic id derived from (entity_type, stable_key). The
    /// same entity observed via multiple collectors collapses into
    /// the same row regardless of which observation arrives first.
    public var canonicalId: String {
        "\(Self.entityType):\(stableKey)"
    }

    /// Build the storage-level row.
    public func toEntity(
        source: String,
        confidence: Double = 1.0
    ) throws -> TraceEntity {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .millisecondsSince1970
        encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(self)
        let attrJson = String(data: data, encoding: .utf8) ?? "{}"
        return TraceEntity(
            id: canonicalId,
            entityType: Self.entityType,
            stableKey: stableKey,
            displayName: displayName,
            firstSeen: firstSeen,
            lastSeen: lastSeen,
            attributesJson: attrJson,
            source: source,
            confidence: confidence
        )
    }
}

// MARK: - ProcessNode

public struct ProcessNode: TraceGraphNode, Equatable {
    public static let entityType = "process"

    public let processKey: String
    public let pid: Int32
    public let ppid: Int32?
    public let executablePath: String
    public let executableHash: String?
    public let commandLineRedacted: String?
    public let signingTeamId: String?
    public let signingIdentifier: String?
    public let isAppleSigned: Bool
    public let isNotarized: Bool
    public let startTime: Date
    public let endTime: Date?
    public let user: String?
    public let cwd: String?
    public let agentTraceId: String?
    public let agentSpanId: String?

    public var stableKey: String { processKey }
    public var displayName: String { (executablePath as NSString).lastPathComponent }
    public var firstSeen: Date { startTime }
    public var lastSeen: Date { endTime ?? startTime }

    public init(
        processKey: String,
        pid: Int32,
        ppid: Int32?,
        executablePath: String,
        executableHash: String? = nil,
        commandLineRedacted: String? = nil,
        signingTeamId: String? = nil,
        signingIdentifier: String? = nil,
        isAppleSigned: Bool,
        isNotarized: Bool,
        startTime: Date,
        endTime: Date? = nil,
        user: String? = nil,
        cwd: String? = nil,
        agentTraceId: String? = nil,
        agentSpanId: String? = nil
    ) {
        self.processKey = processKey
        self.pid = pid
        self.ppid = ppid
        self.executablePath = executablePath
        self.executableHash = executableHash
        self.commandLineRedacted = commandLineRedacted
        self.signingTeamId = signingTeamId
        self.signingIdentifier = signingIdentifier
        self.isAppleSigned = isAppleSigned
        self.isNotarized = isNotarized
        self.startTime = startTime
        self.endTime = endTime
        self.user = user
        self.cwd = cwd
        self.agentTraceId = agentTraceId
        self.agentSpanId = agentSpanId
    }
}

// MARK: - FileNode

public enum FileKind: String, Sendable, Codable, Equatable, CaseIterable {
    case credentialFile = "credential_file"
    case launchAgent    = "launch_agent"
    case launchDaemon   = "launch_daemon"
    case loginItem      = "login_item"
    case shellProfile   = "shell_profile"
    case script         = "script"
    case binary         = "binary"
    case plist          = "plist"
    case browserDownload = "browser_download"
    case packageFile    = "package_file"
    case projectFile    = "project_file"
    case unknown        = "unknown"
}

public struct FileNode: TraceGraphNode, Equatable {
    public static let entityType = "file"

    public let path: String
    public let pathHash: String
    public let fileKind: FileKind
    public let sha256: String?
    public let quarantineInfo: String?
    /// v1.21.4 (Phase-6 6B, leg 2): true when this file, read by an
    /// AI-agent-attributed process, carried the shipped plaintext
    /// prompt-injection markers (see `InjectionMarkerScanner`). Encoded
    /// into `attributes_json` so a graph rule can match it with a
    /// `where: { untrusted_content: { equals_bool: true } }` clause — the
    /// load-bearing "untrusted content" leg of the lethal-trifecta rule.
    public let untrustedContent: Bool
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String { pathHash }
    public var displayName: String { (path as NSString).lastPathComponent }

    public init(
        path: String,
        pathHash: String,
        fileKind: FileKind,
        sha256: String? = nil,
        quarantineInfo: String? = nil,
        untrustedContent: Bool = false,
        firstSeen: Date,
        lastSeen: Date
    ) {
        self.path = path
        self.pathHash = pathHash
        self.fileKind = fileKind
        self.sha256 = sha256
        self.quarantineInfo = quarantineInfo
        self.untrustedContent = untrustedContent
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
    }

    private enum CodingKeys: String, CodingKey {
        case path, pathHash, fileKind, sha256, quarantineInfo, untrustedContent, firstSeen, lastSeen
    }

    // Custom decode so `untrustedContent` (new in v1.21.4 Phase-6 6B) is
    // tolerant: pre-upgrade `file` entities persisted without the key decode
    // cleanly (default false) instead of failing — otherwise a ProvO export of
    // a pre-1.21.4 tracegraph would drop those entities. encode(to:) stays
    // synthesized. (The detection path decodes via tolerant JSONSerialization
    // and was never affected.)
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        path = try c.decode(String.self, forKey: .path)
        pathHash = try c.decode(String.self, forKey: .pathHash)
        fileKind = try c.decode(FileKind.self, forKey: .fileKind)
        sha256 = try c.decodeIfPresent(String.self, forKey: .sha256)
        quarantineInfo = try c.decodeIfPresent(String.self, forKey: .quarantineInfo)
        untrustedContent = try c.decodeIfPresent(Bool.self, forKey: .untrustedContent) ?? false
        firstSeen = try c.decode(Date.self, forKey: .firstSeen)
        lastSeen = try c.decode(Date.self, forKey: .lastSeen)
    }
}

// MARK: - NetworkNode

public enum NetworkReputation: String, Sendable, Codable, Equatable, CaseIterable {
    case knownGood    = "known_good"
    case privateRange = "private_range"
    case unknown      = "unknown"
    case suspicious   = "suspicious"
    case malicious    = "malicious"
}

public struct NetworkNode: TraceGraphNode, Equatable {
    public static let entityType = "network"

    public let destinationHost: String?
    public let destinationIP: String?
    public let port: Int?
    public let protocolName: String?
    public let reputation: NetworkReputation
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String {
        let host = destinationHost ?? destinationIP ?? "unknown"
        return "\(host):\(port ?? 0)/\(protocolName ?? "unknown")"
    }
    public var displayName: String {
        let host = destinationHost ?? destinationIP ?? "unknown"
        if let port { return "\(host):\(port)" }
        return host
    }

    public init(
        destinationHost: String? = nil,
        destinationIP: String? = nil,
        port: Int? = nil,
        protocolName: String? = nil,
        reputation: NetworkReputation = .unknown,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.destinationHost = destinationHost
        self.destinationIP = destinationIP
        self.port = port
        self.protocolName = protocolName
        self.reputation = reputation
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - AIAgentNode

public enum AttributionMethod: String, Sendable, Codable, Equatable, CaseIterable {
    case directTraceparent    = "direct_traceparent"
    case mcpProtocolObserved  = "mcp_protocol_observed"
    case processLineageMatch  = "process_lineage_match"
    case temporalProximity    = "temporal_proximity"
}

public struct AIAgentNode: TraceGraphNode, Equatable {
    public static let entityType = "ai_agent"

    public let agentId: String
    public let agentName: String
    public let sourceApp: String?
    public let projectPathHash: String?
    public let toolName: String?
    public let traceId: String?
    public let spanId: String?
    public let confidence: Double
    public let attributionMethod: AttributionMethod
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String { agentId }
    public var displayName: String { agentName }

    public init(
        agentId: String,
        agentName: String,
        sourceApp: String? = nil,
        projectPathHash: String? = nil,
        toolName: String? = nil,
        traceId: String? = nil,
        spanId: String? = nil,
        confidence: Double,
        attributionMethod: AttributionMethod,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.agentId = agentId
        self.agentName = agentName
        self.sourceApp = sourceApp
        self.projectPathHash = projectPathHash
        self.toolName = toolName
        self.traceId = traceId
        self.spanId = spanId
        self.confidence = confidence
        self.attributionMethod = attributionMethod
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - PersistenceNode

public enum PersistenceType: String, Sendable, Codable, Equatable, CaseIterable {
    case launchAgent  = "launch_agent"
    case launchDaemon = "launch_daemon"
    case loginItem    = "login_item"
    case shellProfile = "shell_profile"
    case cron         = "cron"
    case plist        = "plist"
}

public struct PersistenceNode: TraceGraphNode, Equatable {
    public static let entityType = "persistence"

    public let persistenceType: PersistenceType
    public let path: String
    public let label: String?
    public let createdByProcessKey: String?
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String { "\(persistenceType.rawValue):\(path)" }
    public var displayName: String { label ?? (path as NSString).lastPathComponent }

    public init(
        persistenceType: PersistenceType,
        path: String,
        label: String? = nil,
        createdByProcessKey: String? = nil,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.persistenceType = persistenceType
        self.path = path
        self.label = label
        self.createdByProcessKey = createdByProcessKey
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - MCPServerNode

public struct MCPServerNode: TraceGraphNode, Equatable {
    public static let entityType = "mcp_server"

    public let serverName: String
    public let transport: String        // "stdio" | "sse" | "http" | "ws"
    public let command: String?
    public let argsHash: String?
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String { "\(serverName):\(transport)" }
    public var displayName: String { serverName }

    public init(
        serverName: String,
        transport: String,
        command: String? = nil,
        argsHash: String? = nil,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.serverName = serverName
        self.transport = transport
        self.command = command
        self.argsHash = argsHash
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - PackageScriptNode

public struct PackageScriptNode: TraceGraphNode, Equatable {
    public static let entityType = "package_script"

    public let packageManager: String   // "npm" | "pip" | "gem" | "cargo" | ...
    public let scriptKind: String       // "preinstall" | "postinstall" | "install" | ...
    public let packageName: String
    public let packageVersion: String?
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String {
        "\(packageManager):\(scriptKind):\(packageName)"
    }
    public var displayName: String {
        "\(packageManager) \(scriptKind) — \(packageName)"
    }

    public init(
        packageManager: String,
        scriptKind: String,
        packageName: String,
        packageVersion: String? = nil,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.packageManager = packageManager
        self.scriptKind = scriptKind
        self.packageName = packageName
        self.packageVersion = packageVersion
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - BrowserDownloadNode

public struct BrowserDownloadNode: TraceGraphNode, Equatable {
    public static let entityType = "browser_download"

    public let browser: String          // "chrome" | "safari" | "firefox" | ...
    public let downloadPath: String
    public let pathHash: String
    public let originUrl: String?
    public let quarantineInfo: String?
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String { "\(browser):\(pathHash)" }
    public var displayName: String { (downloadPath as NSString).lastPathComponent }

    public init(
        browser: String,
        downloadPath: String,
        pathHash: String,
        originUrl: String? = nil,
        quarantineInfo: String? = nil,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.browser = browser
        self.downloadPath = downloadPath
        self.pathHash = pathHash
        self.originUrl = originUrl
        self.quarantineInfo = quarantineInfo
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - CodeSignatureNode

public struct CodeSignatureNode: TraceGraphNode, Equatable {
    public static let entityType = "code_signature"

    public let teamId: String?
    public let signingId: String?
    public let signerType: SignerType
    public let isNotarized: Bool
    public let cdHash: String?
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String {
        "\(teamId ?? "-"):\(signingId ?? "-"):\(signerType.rawValue)"
    }
    public var displayName: String {
        signingId ?? teamId ?? signerType.rawValue
    }

    public init(
        teamId: String?,
        signingId: String?,
        signerType: SignerType,
        isNotarized: Bool,
        cdHash: String? = nil,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.teamId = teamId
        self.signingId = signingId
        self.signerType = signerType
        self.isNotarized = isNotarized
        self.cdHash = cdHash
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - UserSessionNode

public struct UserSessionNode: TraceGraphNode, Equatable {
    public static let entityType = "user_session"

    public let userId: UInt32
    public let userName: String
    public let sessionId: UInt32?
    public let tty: String?
    public let launchSource: String?
    public let sshRemoteIP: String?
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String {
        "\(userId):\(sessionId ?? 0)"
    }
    public var displayName: String {
        if let tty { return "\(userName) (\(tty))" }
        return userName
    }

    public init(
        userId: UInt32,
        userName: String,
        sessionId: UInt32? = nil,
        tty: String? = nil,
        launchSource: String? = nil,
        sshRemoteIP: String? = nil,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.userId = userId
        self.userName = userName
        self.sessionId = sessionId
        self.tty = tty
        self.launchSource = launchSource
        self.sshRemoteIP = sshRemoteIP
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - TCCPermissionNode

public struct TCCPermissionNode: TraceGraphNode, Equatable {
    public static let entityType = "tcc_permission"

    public let service: String          // "kTCCServiceAccessibility" etc.
    public let client: String           // bundle id or executable path
    public let allowed: Bool
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String { "\(service):\(client)" }
    public var displayName: String { "\(service) → \(client)" }

    public init(
        service: String,
        client: String,
        allowed: Bool,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.service = service
        self.client = client
        self.allowed = allowed
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - RuleNode

public struct RuleNode: TraceGraphNode, Equatable {
    public static let entityType = "rule"

    public let ruleId: String
    public let ruleTitle: String
    public let ruleVersion: String
    public let severity: String
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String { ruleId }
    public var displayName: String { ruleTitle }

    public init(
        ruleId: String,
        ruleTitle: String,
        ruleVersion: String,
        severity: String,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.ruleId = ruleId
        self.ruleTitle = ruleTitle
        self.ruleVersion = ruleVersion
        self.severity = severity
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}

// MARK: - AlertNode

public struct AlertNode: TraceGraphNode, Equatable {
    public static let entityType = "alert"

    public let alertId: String
    public let title: String
    public let severity: String
    public let firstSeen: Date
    public let lastSeen: Date

    public var stableKey: String { alertId }
    public var displayName: String { title }

    public init(
        alertId: String,
        title: String,
        severity: String,
        firstSeen: Date,
        lastSeen: Date? = nil
    ) {
        self.alertId = alertId
        self.title = title
        self.severity = severity
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen ?? firstSeen
    }
}
