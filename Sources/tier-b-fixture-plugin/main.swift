// tier-b-fixture-plugin — research-grade reference Tier B
// plugin. Demonstrates the subprocess + JSON-RPC IPC contract
// that any future third-party Tier B plugin would speak.
//
// Plan §3.6 + §3.9. The wire format is JSON-RPC 2.0 over stdio
// (matches MCP). One request per line on stdin; one response per
// line on stdout. Daemon-side TierBSubprocessLoader spawns this
// binary, sends a `collect` request, reads the artifacts, exits.
//
// IMPORTANT: This is a research executable. It is NOT registered
// in the live PluginRegistry and never loads in production
// MacCrab binaries. The first-party in-process plugin catalog
// continues to be the operator-facing surface.

import Foundation
import CryptoKit

// MARK: - JSON-RPC envelope

struct JSONRPCRequest: Decodable {
    let jsonrpc: String
    let id: Int64
    let method: String
    // params is method-specific — decoded per-method below.
}

struct CollectParams: Decodable {
    let case_id: String
    let case_name: String
    let encryption_state: String
    let tick_count: Int?
    /// Optional: a file path to attempt to read inside the
    /// subprocess. Used by the sandbox-enforcement smoke test.
    let probe_file: String?
}

struct JSONRPCErrorResponse: Encodable {
    let jsonrpc: String
    let id: Int64
    let error: ErrorObject

    struct ErrorObject: Encodable {
        let code: Int
        let message: String
    }
}

struct JSONRPCCollectResult: Encodable {
    let jsonrpc: String
    let id: Int64
    let result: CollectResultPayload

    struct CollectResultPayload: Encodable {
        let artifacts: [ArtifactPayload]
        let notes: [String]
        let status: String
    }
}

struct ArtifactPayload: Encodable {
    let content_type: String
    let sha256: String
    let summary: String
    let confidence: String
    let privacy_class: String
    let data_json: String
}

// MARK: - The actual plugin handler

func handleCollect(_ params: CollectParams) -> JSONRPCCollectResult.CollectResultPayload {
    let tickCount = params.tick_count ?? 1
    var artifacts: [ArtifactPayload] = []
    var notes = [
        "tier-b-fixture-plugin running as PID \(ProcessInfo.processInfo.processIdentifier)",
        "received \(tickCount) tick(s) requested via collect params",
    ]
    for tick in 0..<tickCount {
        let seed = "tier-b-fixture:\(params.case_id):tick=\(tick)"
        let digest = SHA256.hash(data: Data(seed.utf8))
        let sha = digest.map { String(format: "%02x", $0) }.joined()
        let dataJSON = """
            {"tick": \(tick), "case_id": "\(params.case_id)", "fixture_marker": "tier-b-fixture-plugin-research-post-v15"}
            """
        artifacts.append(ArtifactPayload(
            content_type: "tier_b_fixture.heartbeat",
            sha256: sha,
            summary: "tier-b fixture heartbeat tick \(tick)",
            confidence: "observed",
            privacy_class: "metadata",
            data_json: dataJSON
        ))
    }
    // Optional sandbox probe: attempt to read the supplied path.
    // The fixture reports success/failure as an additional
    // artifact so the daemon can verify the sandbox did its job.
    if let probe = params.probe_file {
        let readable = (try? Data(contentsOf: URL(fileURLWithPath: probe))) != nil
        let probeDataJSON = """
            {"probe_path": \(jsonString(probe)), "readable_inside_subprocess": \(readable ? "true" : "false")}
            """
        artifacts.append(ArtifactPayload(
            content_type: "tier_b_fixture.probe_read",
            sha256: SHA256.hash(data: Data(probe.utf8))
                .map { String(format: "%02x", $0) }.joined(),
            summary: "probe-read \(probe): readable=\(readable)",
            confidence: "observed",
            privacy_class: "metadata",
            data_json: probeDataJSON
        ))
        notes.append("probe_file=\(probe) readable=\(readable)")
    }
    return JSONRPCCollectResult.CollectResultPayload(
        artifacts: artifacts,
        notes: notes,
        status: "ok"
    )
}

/// JSON-escape a string for embedding in a manually-built JSON
/// literal. Uses JSONEncoder to handle escaping correctly.
func jsonString(_ raw: String) -> String {
    if let data = try? JSONEncoder().encode(raw),
       let s = String(data: data, encoding: .utf8) {
        return s
    }
    return "\"\""
}

// MARK: - Main loop

func emitError(id: Int64, code: Int, message: String) {
    let resp = JSONRPCErrorResponse(
        jsonrpc: "2.0",
        id: id,
        error: JSONRPCErrorResponse.ErrorObject(code: code, message: message)
    )
    if let data = try? JSONEncoder().encode(resp),
       let line = String(data: data, encoding: .utf8) {
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }
}

func emit<T: Encodable>(_ response: T) {
    if let data = try? JSONEncoder().encode(response),
       let line = String(data: data, encoding: .utf8) {
        FileHandle.standardOutput.write(Data((line + "\n").utf8))
    }
}

setbuf(stdout, nil)

while let line = readLine(strippingNewline: true) {
    let trimmed = line.trimmingCharacters(in: .whitespaces)
    guard !trimmed.isEmpty else { continue }
    guard let data = trimmed.data(using: .utf8) else { continue }
    guard let any = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        continue
    }
    let id = (any["id"] as? Int64) ?? Int64((any["id"] as? Int) ?? 0)
    let method = any["method"] as? String ?? ""

    switch method {
    case "collect":
        // Decode params.
        var params: CollectParams
        if let paramsData = try? JSONSerialization.data(withJSONObject: any["params"] ?? [:]),
           let decoded = try? JSONDecoder().decode(CollectParams.self, from: paramsData) {
            params = decoded
        } else {
            emitError(id: id, code: -32602, message: "invalid params")
            continue
        }
        let result = handleCollect(params)
        let response = JSONRPCCollectResult(jsonrpc: "2.0", id: id, result: result)
        emit(response)

    case "shutdown":
        // Daemon signals end-of-conversation. Exit cleanly.
        exit(0)

    default:
        emitError(id: id, code: -32601, message: "method not found: \(method)")
    }
}
