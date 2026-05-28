// FieldResolver — pulls a named field out of a CommittedArtifact,
// transparently handling record-level fields (observed_at,
// summary, plugin_id) vs data-payload fields (anything declared
// by the plugin).
//
// Used by every artifact viewer: they receive (artifact,
// fieldName) and call back here for the value. Keeps the special-
// case handling in one place.

import Foundation
import MacCrabForensics

public enum ResolvedValue: Equatable, Sendable {
    case string(String)
    case int(Int64)
    case double(Double)
    case bool(Bool)
    case date(Date)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    /// Human-presentable single-line text.
    public func displayString(format: LayoutFormat? = nil) -> String {
        switch self {
        case .string(let s):
            return s
        case .int(let i):
            return "\(i)"
        case .double(let d):
            return String(format: "%g", d)
        case .bool(let b):
            switch format ?? .plain {
            case .boolYesNo:  return b ? "Yes" : "No"
            case .boolArrow:  return b ? "→ Sent" : "← Received"
            default:          return b ? "true" : "false"
            }
        case .date(let d):
            switch format ?? .date {
            case .isoDate:
                return ISO8601DateFormatter().string(from: d)
            default:
                let f = DateFormatter()
                f.dateStyle = .short
                f.timeStyle = .medium
                return f.string(from: d)
            }
        case .array(let arr):
            return "\(arr.count) item\(arr.count == 1 ? "" : "s")"
        case .object(let obj):
            return "{ \(obj.count) keys }"
        case .null:
            return "—"
        }
    }

    /// Sortable comparison key (string-ified, lower-cased).
    public var sortKey: String {
        switch self {
        case .string(let s): return s.lowercased()
        case .int(let i):    return String(format: "%020d", i)
        case .double(let d): return String(format: "%030.6f", d)
        case .bool(let b):   return b ? "1" : "0"
        case .date(let d):   return ISO8601DateFormatter().string(from: d)
        case .array, .object, .null: return ""
        }
    }

    public var isEmpty: Bool {
        switch self {
        case .null: return true
        case .string(let s): return s.isEmpty
        case .array(let a): return a.isEmpty
        case .object(let o): return o.isEmpty
        default: return false
        }
    }

    public var asDate: Date? {
        switch self {
        case .date(let d): return d
        case .string(let s):
            // ISO-8601 fall-through (plugins may emit timestamps as strings)
            if let d = ISO8601DateFormatter().date(from: s) { return d }
            return nil
        case .int(let i):
            // Heuristic: > 10^12 → ms epoch, otherwise seconds.
            let secs = i > 1_000_000_000_000 ? Double(i) / 1000.0 : Double(i)
            return Date(timeIntervalSince1970: secs)
        default: return nil
        }
    }
}

public enum FieldResolver {

    /// Special-case names that resolve to ArtifactRecord-level
    /// fields rather than the JSONValue data payload.
    private static let recordFields: Set<String> = [
        "observed_at", "observedAt",
        "captured_at", "capturedAt",
        "summary",
        "plugin_id", "pluginID",
        "content_type", "contentType",
        "source_path", "sourcePath",
        "sha256",
        "confidence",
        "actor",
    ]

    public static func resolve(_ artifact: CommittedArtifact, field: String) -> ResolvedValue {
        if recordFields.contains(field) {
            return resolveRecord(artifact, field: field)
        }
        guard let v = artifact.record.data[field] else { return .null }
        return wrap(v)
    }

    private static func resolveRecord(_ a: CommittedArtifact, field: String) -> ResolvedValue {
        switch field {
        case "observed_at", "observedAt":   return .date(a.record.observedAt)
        case "captured_at", "capturedAt":   return .date(a.record.capturedAt)
        case "summary":
            return a.record.summary.map { .string($0) } ?? .null
        case "plugin_id", "pluginID":       return .string(a.record.pluginID)
        case "content_type", "contentType": return .string(a.record.contentType)
        case "source_path", "sourcePath":
            return a.record.sourcePath.map { .string($0) } ?? .null
        case "sha256":
            return a.record.sha256.isEmpty ? .null : .string(a.record.sha256)
        case "confidence":
            return .string(a.record.confidence.rawValue)
        case "actor":
            return a.record.actor.map { .string($0) } ?? .null
        default:                            return .null
        }
    }

    /// JSONValue → ResolvedValue conversion.
    public static func wrap(_ v: JSONValue) -> ResolvedValue {
        switch v {
        case .string(let s):  return .string(s)
        case .integer(let i): return .int(i)
        case .double(let d):  return .double(d)
        case .bool(let b):    return .bool(b)
        case .array(let a):   return .array(a)
        case .object(let o):  return .object(o)
        case .null:           return .null
        }
    }

    /// Find the field name associated with a role, or nil.
    public static func field(forRole role: FieldRole, in hint: ViewerHint?) -> String? {
        guard let hint else { return nil }
        for (field, mappedRole) in hint.fieldRoles where mappedRole == role {
            return field
        }
        return nil
    }
}
