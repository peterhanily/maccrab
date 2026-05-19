// Input parameter specification for a plugin invocation.
//
// `inputs` declared in the manifest are presented to the operator
// by `maccrabctl plugin info <id>` and consumed by `maccrabctl
// plugin run <id> --<name>=<value>`. The MCP layer translates them
// into JSON-RPC tool parameters.
//
// Plan reference: §3.3 (manifest schema).

import Foundation

/// Declared input parameter on a plugin manifest.
public struct InputSpec: Codable, Sendable {

    /// Operator-visible parameter name (CLI flag, JSON key).
    public let name: String

    /// Operator-visible explanation, surfaced in `plugin info` output
    /// and MCP tool descriptions.
    public let description: String

    /// Value shape. Plan §3.3 keeps the surface minimal.
    public let type: InputType

    /// Default applied if the operator does not supply a value.
    /// `nil` here together with `required = true` means the plugin
    /// refuses to run without an explicit value.
    public let `default`: InputValue?

    /// If `true`, the plugin rejects invocation when the value is
    /// absent and no `default` is declared. Manifest validator
    /// audits the (required, default) combinations.
    public let required: Bool

    public init(
        name: String,
        description: String,
        type: InputType,
        default: InputValue? = nil,
        required: Bool = false
    ) {
        self.name = name
        self.description = description
        self.type = type
        self.default = `default`
        self.required = required
    }
}

/// Value shapes a plugin input may take. Kept small so the manifest
/// parser, CLI bridge, and MCP-tool translator all stay simple.
public enum InputType: String, Codable, Sendable {
    case bool
    case integer
    case string
    /// Operator-supplied case id (UUID string). Resolved by the
    /// runtime against the case registry before invocation.
    case caseID
    /// Path on disk. Validated for existence + read permission at
    /// invocation start.
    case path
    /// Time window expressed as `--window 24h` / `--since YYYY-MM-DD`.
    /// Parsed by `maccrabctl` before passing into the plugin.
    case timeWindow
}

/// Type-erased input value. Codable round-trips through JSON without
/// erasing the underlying SQLite representation. Used both for
/// declared defaults in the manifest and for actual invocation
/// arguments in `plugin_invocations.inputs_json`.
public enum InputValue: Codable, Sendable, Equatable {
    case bool(Bool)
    case integer(Int)
    case string(String)
    case `nil`

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .nil
        } else if let b = try? c.decode(Bool.self) {
            self = .bool(b)
        } else if let i = try? c.decode(Int.self) {
            self = .integer(i)
        } else if let s = try? c.decode(String.self) {
            self = .string(s)
        } else {
            throw DecodingError.dataCorruptedError(
                in: c,
                debugDescription: "InputValue must be bool, integer, string, or null"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .bool(let b): try c.encode(b)
        case .integer(let i): try c.encode(i)
        case .string(let s): try c.encode(s)
        case .nil: try c.encodeNil()
        }
    }
}
