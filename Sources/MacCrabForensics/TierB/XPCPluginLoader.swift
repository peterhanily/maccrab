// XPCPluginLoader — daemon-side loader for Tier B plugins.
//
// Plan §3.9 + §12 + §3.6 (MCP JSON-RPC IPC contract).
//
// Status: research stub. The full implementation needs an XPC
// service Info.plist + entitlements target which sits outside
// SPM's scope. This file documents the IPC contract shape + the
// loader's runtime responsibilities; the actual NSXPCConnection
// wiring lands when Tier B graduates from research to a release
// chapter.

import Foundation

/// Represents the daemon-side handle to a running Tier B plugin
/// (subprocess sandboxed XPC service).
public struct XPCPluginHandle: Sendable {
    /// Plugin id from the manifest (same shape as Tier A).
    public let pluginID: String

    /// PID of the spawned XPC service. Surface for the
    /// invocations-log + crash detection.
    public let pid: Int32

    /// Compiled sandbox profile applied at spawn. Stored so the
    /// audit log can correlate "this invocation ran under this
    /// profile."
    public let sandboxProfilePath: String

    public init(pluginID: String, pid: Int32, sandboxProfilePath: String) {
        self.pluginID = pluginID
        self.pid = pid
        self.sandboxProfilePath = sandboxProfilePath
    }
}

/// IPC contract — same shape as the MCP JSON-RPC-over-stdio used
/// by `maccrab-mcp`. Plan §3.6: "MCP wire format = plugin↔host
/// IPC contract. Tier B (future) speaks the same JSON-RPC-over-
/// stdio."
public struct TierBJSONRPCRequest: Codable, Sendable {
    public let jsonrpc: String       // "2.0"
    public let id: Int64
    public let method: String        // "collect" / "enrich" / "fingerprint" / "analyze"
    public let params: Data?         // method-specific JSON payload

    public init(jsonrpc: String = "2.0", id: Int64, method: String, params: Data? = nil) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.method = method
        self.params = params
    }
}

public struct TierBJSONRPCResponse: Codable, Sendable {
    public let jsonrpc: String       // "2.0"
    public let id: Int64
    public let result: Data?         // method-specific JSON payload (on success)
    public let error: ErrorObject?   // non-nil on error

    public struct ErrorObject: Codable, Sendable {
        public let code: Int
        public let message: String
        public init(code: Int, message: String) {
            self.code = code
            self.message = message
        }
    }

    public init(jsonrpc: String = "2.0", id: Int64, result: Data? = nil, error: ErrorObject? = nil) {
        self.jsonrpc = jsonrpc
        self.id = id
        self.result = result
        self.error = error
    }
}

/// Research-grade loader. Real implementation: NSXPCConnection
/// to a sandboxed XPC service. Stub returns a placeholder handle
/// + records the design assumptions in code comments so the
/// research write-up has a concrete reference.
public actor XPCPluginLoader {

    /// Spawn a Tier B plugin as an XPC service with the supplied
    /// sandbox profile applied. Returns a handle the runtime
    /// uses for subsequent IPC calls.
    ///
    /// **NOT IMPLEMENTED in research-post-v15.** Documented for
    /// the feasibility memo. When Tier B ships:
    ///
    /// 1. Compile the sandbox profile via SandboxProfileBuilder.
    /// 2. Write the .sb file to a temp path.
    /// 3. Construct an NSXPCConnection to the plugin's XPC
    ///    service identifier (declared in manifest as
    ///    `xpcServiceIdentifier`).
    /// 4. The service spawns under its Info.plist-declared
    ///    sandbox; the .sb adds plugin-specific allowances on
    ///    top.
    /// 5. Set the connection's `exportedInterface` and
    ///    `remoteObjectInterface` to a protocol exposing the four
    ///    JSON-RPC methods (collect / enrich / fingerprint /
    ///    analyze).
    /// 6. resume() the connection. PID is observable via
    ///    `auditToken.processID()` or `auditToken_to_pid()`.
    public func spawn(
        pluginID: String,
        xpcServiceIdentifier: String,
        sandboxProfile: SandboxProfileSpec
    ) async throws -> XPCPluginHandle {
        let profileText = SandboxProfileBuilder.compile(sandboxProfile)
        let profilePath = NSTemporaryDirectory() + "tier-b-\(UUID().uuidString).sb"
        try profileText.write(toFile: profilePath, atomically: true, encoding: .utf8)
        // PID is a research placeholder. When Tier B ships, the
        // real NSXPCConnection setup happens here.
        return XPCPluginHandle(pluginID: pluginID, pid: -1, sandboxProfilePath: profilePath)
    }

    /// Send a JSON-RPC request to a running Tier B plugin.
    /// **NOT IMPLEMENTED.** Documents the IPC shape.
    public func send(
        _ request: TierBJSONRPCRequest,
        to handle: XPCPluginHandle
    ) async throws -> TierBJSONRPCResponse {
        return TierBJSONRPCResponse(
            id: request.id,
            error: TierBJSONRPCResponse.ErrorObject(
                code: -32601,
                message: "Tier B plugin loader is research-only; not implemented."
            )
        )
    }
}
