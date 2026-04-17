// OCSFMapper.swift
// MacCrabCore
//
// Maps MacCrab's native Event and Alert types to OCSF 1.x records
// (Open Cybersecurity Schema Framework, https://ocsf.io).
//
// OCSF is the Linux Foundation schema used by Amazon Security Lake,
// Snowflake, Splunk, SentinelOne, Rapid7, Palo Alto, Datadog, and others.
// Emitting OCSF on export lets MacCrab plug into any SIEM that understands
// the schema without custom connectors.
//
// Scope: this v1 mapping covers the four OCSF classes that MacCrab produces
// from native telemetry — Process Activity (1007), File System Activity
// (1001), Network Activity (4001), and Security Finding (2004). Additional
// classes (HTTP Activity, DNS Activity, Authentication, Kernel Activity)
// can be added incrementally.

import Foundation

// MARK: - Public API

public enum OCSFMapper {

    /// OCSF schema version embedded in `metadata.version`.
    public static let schemaVersion = "1.3.0"

    /// Product metadata shared by every emitted record.
    public static let product = OCSFProduct(
        name: "MacCrab",
        vendorName: "MacCrab",
        version: "1.2.5"
    )

    /// Map a MacCrab Event to the appropriate OCSF class based on category.
    ///
    /// Returns `.process(...)`, `.file(...)`, `.network(...)`, or `.other(...)`
    /// wrapping a JSON-serializable value. Use `encodeJSON(_:)` to emit.
    public static func mapEvent(_ event: Event) -> OCSFRecord {
        switch event.eventCategory {
        case .process:
            return .process(mapProcessActivity(event))
        case .file:
            return .file(mapFileActivity(event))
        case .network:
            return .network(mapNetworkActivity(event))
        case .tcc, .authentication, .registry:
            // Mapped as a generic Security Finding of informational-to-medium
            // severity until a dedicated OCSF class is picked per category.
            return .finding(mapEventAsFinding(event))
        }
    }

    /// Map a MacCrab Alert to an OCSF Security Finding (class_uid 2004).
    public static func mapAlert(_ alert: Alert, event: Event? = nil) -> OCSFSecurityFinding {
        let attackList: [OCSFAttack] = alert.mitreTacticsList.isEmpty && alert.mitreTechniquesList.isEmpty
            ? []
            : [OCSFAttack(
                tactic: alert.mitreTacticsList.first.map { OCSFAttackItem(uid: $0, name: nil) },
                technique: alert.mitreTechniquesList.first.map { OCSFAttackItem(uid: $0, name: nil) }
            )]

        return OCSFSecurityFinding(
            classUid: 2004,
            className: "Security Finding",
            categoryUid: 2,
            categoryName: "Findings",
            typeUid: 2004 * 100 + 1,      // class_uid * 100 + activity_id
            activityId: 1,                 // 1 = Generate
            activityName: "Generate",
            time: milliseconds(alert.timestamp),
            severityId: severityId(alert.severity),
            severity: severityName(alert.severity),
            metadata: metadata(uid: alert.id),
            finding: OCSFFinding(
                uid: alert.id,
                title: alert.ruleTitle,
                desc: alert.description,
                types: nil,
                relatedEvents: event.map { [OCSFRelatedEvent(uid: $0.id.uuidString)] }
            ),
            attacks: attackList.isEmpty ? nil : attackList,
            state: alertStateName(alert),
            stateId: alertStateId(alert),
            remediation: alert.remediationHint.map { OCSFRemediation(desc: $0) },
            actor: event.map { actorFromEvent($0) },
            process: event.map { process(fromProcess: $0.process) },
            rawData: nil
        )
    }

    /// Encode any OCSFRecord case to pretty-printed JSON.
    public static func encodeJSON(_ record: OCSFRecord, pretty: Bool = false) throws -> String {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        encoder.dateEncodingStrategy = .millisecondsSince1970
        if pretty {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        }
        let data: Data
        switch record {
        case .process(let v):  data = try encoder.encode(v)
        case .file(let v):     data = try encoder.encode(v)
        case .network(let v):  data = try encoder.encode(v)
        case .finding(let v):  data = try encoder.encode(v)
        case .other(let v):    data = try encoder.encode(v)
        }
        return String(data: data, encoding: .utf8) ?? "{}"
    }

    /// Encode a Security Finding directly.
    public static func encodeJSON(_ finding: OCSFSecurityFinding, pretty: Bool = false) throws -> String {
        try encodeJSON(.finding(finding), pretty: pretty)
    }

    // MARK: - Process Activity (1007)

    private static func mapProcessActivity(_ event: Event) -> OCSFProcessActivity {
        let activityId = processActivityId(for: event)
        return OCSFProcessActivity(
            classUid: 1007,
            className: "Process Activity",
            categoryUid: 1,
            categoryName: "System Activity",
            typeUid: 1007 * 100 + activityId,
            activityId: activityId,
            activityName: processActivityName(activityId),
            time: milliseconds(event.timestamp),
            severityId: severityId(event.severity),
            severity: severityName(event.severity),
            metadata: metadata(uid: event.id.uuidString),
            process: process(fromProcess: event.process),
            actor: actorFromEvent(event),
            rawData: nil
        )
    }

    private static func processActivityId(for event: Event) -> Int {
        switch event.eventAction {
        case "exec", "fork":                return 1  // Launch
        case "exit", "signal":              return 2  // Terminate
        case "open":                        return 3  // Open
        default:                            return 0  // Unknown
        }
    }

    private static func processActivityName(_ id: Int) -> String {
        switch id {
        case 1: return "Launch"
        case 2: return "Terminate"
        case 3: return "Open"
        case 4: return "Inject"
        default: return "Unknown"
        }
    }

    // MARK: - File System Activity (1001)

    private static func mapFileActivity(_ event: Event) -> OCSFFileActivity {
        let activityId = fileActivityId(for: event)
        return OCSFFileActivity(
            classUid: 1001,
            className: "File System Activity",
            categoryUid: 1,
            categoryName: "System Activity",
            typeUid: 1001 * 100 + activityId,
            activityId: activityId,
            activityName: fileActivityName(activityId),
            time: milliseconds(event.timestamp),
            severityId: severityId(event.severity),
            severity: severityName(event.severity),
            metadata: metadata(uid: event.id.uuidString),
            file: event.file.map { file(fromFileInfo: $0) } ?? OCSFFile(),
            actor: actorFromEvent(event),
            rawData: nil
        )
    }

    private static func fileActivityId(for event: Event) -> Int {
        guard let action = event.file?.action else { return 0 }
        switch action {
        case .create:   return 1
        case .write:    return 3
        case .rename:   return 5
        case .delete:   return 4
        case .close:    return 0
        case .link:     return 1
        }
    }

    private static func fileActivityName(_ id: Int) -> String {
        switch id {
        case 1: return "Create"
        case 2: return "Read"
        case 3: return "Update"
        case 4: return "Delete"
        case 5: return "Rename"
        default: return "Unknown"
        }
    }

    // MARK: - Network Activity (4001)

    private static func mapNetworkActivity(_ event: Event) -> OCSFNetworkActivity {
        let activityId = 6   // Traffic (default). Finer mapping (Open/Close/Listen) needs more context than we track today.
        return OCSFNetworkActivity(
            classUid: 4001,
            className: "Network Activity",
            categoryUid: 4,
            categoryName: "Network Activity",
            typeUid: 4001 * 100 + activityId,
            activityId: activityId,
            activityName: "Traffic",
            time: milliseconds(event.timestamp),
            severityId: severityId(event.severity),
            severity: severityName(event.severity),
            metadata: metadata(uid: event.id.uuidString),
            srcEndpoint: event.network.map {
                OCSFEndpoint(ip: $0.sourceIp, port: Int($0.sourcePort), hostname: nil)
            } ?? OCSFEndpoint(),
            dstEndpoint: event.network.map {
                OCSFEndpoint(ip: $0.destinationIp, port: Int($0.destinationPort), hostname: $0.destinationHostname)
            } ?? OCSFEndpoint(),
            connectionInfo: event.network.map {
                OCSFConnectionInfo(protocolName: $0.transport, direction: $0.direction.rawValue)
            },
            actor: actorFromEvent(event),
            rawData: nil
        )
    }

    // MARK: - Fallback: Event → Security Finding

    private static func mapEventAsFinding(_ event: Event) -> OCSFSecurityFinding {
        OCSFSecurityFinding(
            classUid: 2004,
            className: "Security Finding",
            categoryUid: 2,
            categoryName: "Findings",
            typeUid: 2004 * 100 + 1,
            activityId: 1,
            activityName: "Generate",
            time: milliseconds(event.timestamp),
            severityId: severityId(event.severity),
            severity: severityName(event.severity),
            metadata: metadata(uid: event.id.uuidString),
            finding: OCSFFinding(
                uid: event.id.uuidString,
                title: "\(event.eventCategory.rawValue): \(event.eventAction)",
                desc: nil,
                types: [event.eventCategory.rawValue],
                relatedEvents: nil
            ),
            attacks: nil,
            state: nil,
            stateId: nil,
            remediation: nil,
            actor: actorFromEvent(event),
            process: process(fromProcess: event.process),
            rawData: nil
        )
    }

    // MARK: - Shared helpers

    private static func metadata(uid: String) -> OCSFMetadata {
        OCSFMetadata(version: schemaVersion, product: product, uid: uid, logName: "maccrab.events")
    }

    private static func milliseconds(_ date: Date) -> Int64 {
        Int64(date.timeIntervalSince1970 * 1000)
    }

    private static func severityId(_ s: Severity) -> Int {
        switch s {
        case .informational: return 1
        case .low:           return 2
        case .medium:        return 3
        case .high:          return 4
        case .critical:      return 5
        }
    }

    private static func severityName(_ s: Severity) -> String {
        switch s {
        case .informational: return "Informational"
        case .low:           return "Low"
        case .medium:        return "Medium"
        case .high:          return "High"
        case .critical:      return "Critical"
        }
    }

    private static func alertStateId(_ alert: Alert) -> Int? {
        if alert.suppressed { return 3 }   // Suppressed
        switch alert.analyst?.status {
        case .new?:              return 1  // New
        case .investigating?:    return 2  // In Progress
        case .resolved?:         return 4  // Resolved
        case .falsePositive?:    return 5  // Other: false positive (custom slot)
        case .dismissed?:        return 5
        case nil:                return nil
        }
    }

    private static func alertStateName(_ alert: Alert) -> String? {
        guard let id = alertStateId(alert) else { return nil }
        switch id {
        case 1: return "New"
        case 2: return "In Progress"
        case 3: return "Suppressed"
        case 4: return "Resolved"
        default: return "Other"
        }
    }

    private static func process(fromProcess p: ProcessInfo) -> OCSFProcess {
        OCSFProcess(
            pid: Int(p.pid),
            name: p.name,
            cmdLine: p.commandLine,
            createdTime: milliseconds(p.startTime),
            file: OCSFFile(
                path: p.executable,
                name: p.name,
                parentFolder: (p.executable as NSString).deletingLastPathComponent,
                hashes: hashesFromProcess(p),
                size: nil
            ),
            user: OCSFUser(
                name: p.userName,
                uid: String(p.userId)
            ),
            parentProcess: p.ancestors.first.map {
                OCSFParentProcess(
                    pid: Int($0.pid),
                    name: $0.name,
                    file: OCSFFile(path: $0.executable, name: $0.name)
                )
            }
        )
    }

    private static func actorFromEvent(_ event: Event) -> OCSFActor {
        OCSFActor(
            process: process(fromProcess: event.process),
            user: OCSFUser(name: event.process.userName, uid: String(event.process.userId))
        )
    }

    private static func file(fromFileInfo f: FileInfo) -> OCSFFile {
        OCSFFile(
            path: f.path,
            name: f.name,
            parentFolder: f.directory,
            hashes: nil,  // Will be populated once FileHasher enrichment is wired in.
            size: f.size.map { Int64($0) }
        )
    }

    private static func hashesFromProcess(_ p: ProcessInfo) -> [OCSFHash]? {
        var result: [OCSFHash] = []
        if let sha = p.hashes?.sha256 {
            result.append(OCSFHash(algorithm: "sha-256", value: sha))
        }
        if let cd = p.hashes?.cdhash {
            result.append(OCSFHash(algorithm: "cdhash", value: cd))
        }
        if let md5 = p.hashes?.md5 {
            result.append(OCSFHash(algorithm: "md5", value: md5))
        }
        return result.isEmpty ? nil : result
    }
}

// MARK: - OCSFRecord

/// Sum type wrapping any OCSF class MacCrab emits. Encoded via `OCSFMapper.encodeJSON`.
public enum OCSFRecord: Sendable {
    case process(OCSFProcessActivity)
    case file(OCSFFileActivity)
    case network(OCSFNetworkActivity)
    case finding(OCSFSecurityFinding)
    case other(OCSFSecurityFinding)
}

// MARK: - OCSF data types
//
// Field names use camelCase in Swift and convert to snake_case on JSON encode
// via `JSONEncoder.KeyEncodingStrategy.convertToSnakeCase`. Examples:
//   classUid   → class_uid
//   typeUid    → type_uid
//   srcEndpoint → src_endpoint
//   cmdLine    → cmd_line

public struct OCSFProduct: Codable, Sendable, Hashable {
    public let name: String
    public let vendorName: String
    public let version: String?
}

public struct OCSFMetadata: Codable, Sendable, Hashable {
    public let version: String
    public let product: OCSFProduct
    public let uid: String?
    public let logName: String?
}

public struct OCSFHash: Codable, Sendable, Hashable {
    public let algorithm: String
    public let value: String
}

public struct OCSFUser: Codable, Sendable, Hashable {
    public let name: String?
    public let uid: String?
}

public struct OCSFFile: Codable, Sendable, Hashable {
    public let path: String?
    public let name: String?
    public let parentFolder: String?
    public let hashes: [OCSFHash]?
    public let size: Int64?

    public init(
        path: String? = nil,
        name: String? = nil,
        parentFolder: String? = nil,
        hashes: [OCSFHash]? = nil,
        size: Int64? = nil
    ) {
        self.path = path
        self.name = name
        self.parentFolder = parentFolder
        self.hashes = hashes
        self.size = size
    }
}

public struct OCSFProcess: Codable, Sendable, Hashable {
    public let pid: Int
    public let name: String?
    public let cmdLine: String?
    public let createdTime: Int64?
    public let file: OCSFFile?
    public let user: OCSFUser?
    public let parentProcess: OCSFParentProcess?
}

/// Non-recursive parent-process summary. Breaks value-type recursion in
/// OCSFProcess and matches OCSF's lighter `parent_process` shape (deeper
/// chains live in `process.lineage[]`, an array of these).
public struct OCSFParentProcess: Codable, Sendable, Hashable {
    public let pid: Int
    public let name: String?
    public let file: OCSFFile?
}

public struct OCSFActor: Codable, Sendable, Hashable {
    public let process: OCSFProcess
    public let user: OCSFUser?
}

public struct OCSFEndpoint: Codable, Sendable, Hashable {
    public let ip: String?
    public let port: Int?
    public let hostname: String?

    public init(ip: String? = nil, port: Int? = nil, hostname: String? = nil) {
        self.ip = ip
        self.port = port
        self.hostname = hostname
    }
}

public struct OCSFConnectionInfo: Codable, Sendable, Hashable {
    public let protocolName: String?
    public let direction: String?
}

public struct OCSFAttackItem: Codable, Sendable, Hashable {
    public let uid: String
    public let name: String?
}

public struct OCSFAttack: Codable, Sendable, Hashable {
    public let tactic: OCSFAttackItem?
    public let technique: OCSFAttackItem?
}

public struct OCSFRelatedEvent: Codable, Sendable, Hashable {
    public let uid: String
}

public struct OCSFFinding: Codable, Sendable, Hashable {
    public let uid: String
    public let title: String
    public let desc: String?
    public let types: [String]?
    public let relatedEvents: [OCSFRelatedEvent]?
}

public struct OCSFRemediation: Codable, Sendable, Hashable {
    public let desc: String
}

// MARK: - Top-level OCSF record types

public struct OCSFProcessActivity: Codable, Sendable, Hashable {
    public let classUid: Int
    public let className: String
    public let categoryUid: Int
    public let categoryName: String
    public let typeUid: Int
    public let activityId: Int
    public let activityName: String?
    public let time: Int64
    public let severityId: Int
    public let severity: String
    public let metadata: OCSFMetadata
    public let process: OCSFProcess
    public let actor: OCSFActor?
    public let rawData: String?
}

public struct OCSFFileActivity: Codable, Sendable, Hashable {
    public let classUid: Int
    public let className: String
    public let categoryUid: Int
    public let categoryName: String
    public let typeUid: Int
    public let activityId: Int
    public let activityName: String?
    public let time: Int64
    public let severityId: Int
    public let severity: String
    public let metadata: OCSFMetadata
    public let file: OCSFFile
    public let actor: OCSFActor?
    public let rawData: String?
}

public struct OCSFNetworkActivity: Codable, Sendable, Hashable {
    public let classUid: Int
    public let className: String
    public let categoryUid: Int
    public let categoryName: String
    public let typeUid: Int
    public let activityId: Int
    public let activityName: String?
    public let time: Int64
    public let severityId: Int
    public let severity: String
    public let metadata: OCSFMetadata
    public let srcEndpoint: OCSFEndpoint
    public let dstEndpoint: OCSFEndpoint
    public let connectionInfo: OCSFConnectionInfo?
    public let actor: OCSFActor?
    public let rawData: String?
}

public struct OCSFSecurityFinding: Codable, Sendable, Hashable {
    public let classUid: Int
    public let className: String
    public let categoryUid: Int
    public let categoryName: String
    public let typeUid: Int
    public let activityId: Int
    public let activityName: String?
    public let time: Int64
    public let severityId: Int
    public let severity: String
    public let metadata: OCSFMetadata
    public let finding: OCSFFinding
    public let attacks: [OCSFAttack]?
    public let state: String?
    public let stateId: Int?
    public let remediation: OCSFRemediation?
    public let actor: OCSFActor?
    public let process: OCSFProcess?
    public let rawData: String?
}
