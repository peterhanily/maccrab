import Foundation
import CoreFoundation

public enum RuntimeConfigValue: Codable, Sendable, Equatable, CustomStringConvertible {
    case boolean(Bool), integer(Int), number(Double)

    public var foundationValue: Any {
        switch self {
        case .boolean(let value): return value
        case .integer(let value): return value
        case .number(let value): return value
        }
    }
    public var description: String { String(describing: foundationValue) }
    public static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.boolean(let a), .boolean(let b)): return a == b
        case (.boolean, _), (_, .boolean): return false
        default:
            return (lhs.foundationValue as? NSNumber)?.doubleValue
                == (rhs.foundationValue as? NSNumber)?.doubleValue
        }
    }
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let value = try? container.decode(Bool.self) { self = .boolean(value) }
        else if let value = try? container.decode(Int.self) { self = .integer(value) }
        else { self = .number(try container.decode(Double.self)) }
    }
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .boolean(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        }
    }
}

public struct RuntimeConfigContractError: Error, LocalizedError, Sendable {
    public let message: String
    public var errorDescription: String? { message }
    public init(_ message: String) { self.message = message }
}

/// The request contract is shared by every client and revalidated by the
/// daemon. The bounds and disable-only policy retain the existing daemon rules.
public enum RuntimeConfigurationContract {
    public enum Kind: String, Codable, Sendable { case bool, int, double }
    public enum Application: String, Codable, Sendable { case restart, reload, live, unsupported }
    public struct Definition: Codable, Sendable {
        public let key: String
        public let property: String
        public let kind: Kind
        public let defaultValue: RuntimeConfigValue
        public let minimum: Double?
        public let maximum: Double?
        public let responseCapability: Bool
        public let disableOnly: Bool
        public let application: Application

        public func parse(_ text: String) throws -> RuntimeConfigValue {
            switch kind {
            case .bool:
                switch text.lowercased() {
                case "true", "yes", "on", "1": return .boolean(true)
                case "false", "no", "off", "0": return .boolean(false)
                default: throw RuntimeConfigContractError("'\(key)' expects true or false")
                }
            case .int:
                guard let value = Int(text) else { throw RuntimeConfigContractError("'\(key)' expects an integer") }
                return .integer(value)
            case .double:
                guard let value = Double(text), value.isFinite else { throw RuntimeConfigContractError("'\(key)' expects a finite number") }
                return .number(value)
            }
        }

        public func typed(_ value: Any) throws -> RuntimeConfigValue {
            guard let number = value as? NSNumber else {
                throw RuntimeConfigContractError("'\(key)' expects \(kind.rawValue)")
            }
            let isBoolean = CFGetTypeID(number) == CFBooleanGetTypeID()
            switch kind {
            case .bool:
                guard isBoolean else { throw RuntimeConfigContractError("'\(key)' expects a boolean") }
                return .boolean(number.boolValue)
            case .int:
                guard !isBoolean, number.doubleValue.isFinite,
                      let integer = Int(exactly: number.doubleValue) else {
                    throw RuntimeConfigContractError("'\(key)' expects an integer")
                }
                return .integer(integer)
            case .double:
                guard !isBoolean, number.doubleValue.isFinite else {
                    throw RuntimeConfigContractError("'\(key)' expects a finite number")
                }
                return .number(number.doubleValue)
            }
        }

        public func normalized(_ requested: RuntimeConfigValue, forRequest: Bool = true) throws -> RuntimeConfigValue {
            let value = try typed(requested.foundationValue)
            if forRequest, application == .unsupported {
                throw RuntimeConfigContractError("'\(key)' has no runtime consumer in this release and cannot be changed")
            }
            if forRequest, disableOnly, value == .boolean(true) {
                throw RuntimeConfigContractError("'\(key)' can only be disabled here; enabling network enrichment requires the app or administrator configuration")
            }
            guard let minimum, let maximum else { return value }
            let number = (value.foundationValue as? NSNumber)?.doubleValue ?? 0
            let bounded = Swift.min(Swift.max(number, minimum), maximum)
            return kind == .int ? .integer(Int(bounded)) : .number(bounded)
        }
    }

    private static func number(_ key: String, _ property: String, _ value: Double,
                               _ lower: Double, _ upper: Double, integer: Bool = false,
                               application: Application = .restart) -> Definition {
        .init(key: key, property: property, kind: integer ? .int : .double,
              defaultValue: integer ? .integer(Int(value)) : .number(value),
              minimum: lower, maximum: upper, responseCapability: false,
              disableOnly: false, application: application)
    }
    private static func flag(_ key: String, _ property: String, _ value: Bool,
                             response: Bool = false, disableOnly: Bool = false,
                             application: Application = .restart) -> Definition {
        .init(key: key, property: property, kind: .bool, defaultValue: .boolean(value),
              minimum: nil, maximum: nil, responseCapability: response,
              disableOnly: disableOnly, application: application)
    }

    public static let definitions: [Definition] = [
        number("behavior_alert_threshold", "behaviorAlertThreshold", 10, 1, 50),
        number("behavior_critical_threshold", "behaviorCriticalThreshold", 20, 1, 100),
        number("statistical_z_threshold", "statisticalZThreshold", 3, 1, 6),
        number("statistical_min_samples", "statisticalMinSamples", 50, 10, 1000, integer: true),
        number("usb_poll_interval", "usbPollInterval", 10, 1, 300),
        number("clipboard_poll_interval", "clipboardPollInterval", 3, 1, 60),
        number("browser_extension_poll_interval", "browserExtensionPollInterval", 120, 5, 600),
        number("rootkit_poll_interval", "rootkitPollInterval", 120, 10, 600),
        number("event_tap_poll_interval", "eventTapPollInterval", 30, 1, 300),
        number("system_policy_poll_interval", "systemPolicyPollInterval", 300, 10, 1800),
        number("prompt_injection_confidence", "promptInjectionConfidence", 40, 1, 95, integer: true, application: .unsupported),
        number("intent_posterior_threshold", "intentPosteriorThreshold", 0.85, 0.5, 0.99),
        flag("subscribe_file_open_events", "subscribeFileOpenEvents", true, response: true),
        flag("subscribe_introspection_events", "subscribeIntrospectionEvents", true, response: true, application: .reload),
        flag("ultrasonic_enabled", "ultrasonicEnabled", false, response: true),
        flag("threat_intel_enabled", "threatIntelEnabled", false, disableOnly: true, application: .live),
        flag("vuln_scan_enabled", "vulnScanEnabled", false, disableOnly: true, application: .live),
        flag("package_freshness_enabled", "packageFreshnessEnabled", false, disableOnly: true, application: .live),
        flag("cert_transparency_enabled", "certTransparencyEnabled", false, disableOnly: true, application: .live),
    ]
    public static let byKey = Dictionary(uniqueKeysWithValues: definitions.map { ($0.key, $0) })
}

public struct EffectiveRuntimeConfiguration: Codable, Sendable {
    public struct Entry: Codable, Sendable, Equatable {
        public var value: RuntimeConfigValue?
        public var configuredValue: RuntimeConfigValue
        public var source: String
        public var adjustment: String?

        public init(value: RuntimeConfigValue?, configuredValue: RuntimeConfigValue, source: String, adjustment: String? = nil) {
            self.value = value
            self.configuredValue = configuredValue
            self.source = source
            self.adjustment = adjustment
        }
    }
    public let schemaVersion: Int
    public var writtenAt: Date
    public let engineIdentity: EngineTelemetryIdentity
    public var generation: UInt64
    public var values: [String: Entry]

    public init(engineIdentity: EngineTelemetryIdentity, values: [String: Entry], generation: UInt64 = 1, writtenAt: Date = Date()) {
        schemaVersion = 1
        self.engineIdentity = engineIdentity
        self.values = values
        self.generation = generation
        self.writtenAt = writtenAt
    }
}

public struct RuntimeRequestReceipt: Codable, Sendable {
    public enum State: String, Codable, Sendable { case accepted, applied, rejected, superseded }
    public let schemaVersion: Int
    public let requestID: UUID
    public let operation: String
    public var state: State
    public let acceptedAt: Date
    public var updatedAt: Date
    public var engineIdentity: EngineTelemetryIdentity
    public var appliedGeneration: UInt64?
    public let key: String?
    public let requestedValue: RuntimeConfigValue?
    public let acceptedValue: RuntimeConfigValue?
    public var reason: String

    public init(requestID: UUID, operation: String, state: State, engineIdentity: EngineTelemetryIdentity,
                key: String? = nil, requestedValue: RuntimeConfigValue? = nil,
                acceptedValue: RuntimeConfigValue? = nil, reason: String, now: Date = Date()) {
        schemaVersion = 1
        self.requestID = requestID
        self.operation = operation
        self.state = state
        self.engineIdentity = engineIdentity
        self.key = key
        self.requestedValue = requestedValue
        self.acceptedValue = acceptedValue
        self.reason = reason
        acceptedAt = now
        updatedAt = now
    }
}
