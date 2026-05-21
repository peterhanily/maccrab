// TierBSubprocessLoader — daemon-side loader that spawns a Tier
// B plugin binary via Process + stdin/stdout JSON-RPC pipes.
//
// Plan §3.9 + §3.6. Real working IPC, no NSXPCConnection wiring
// yet (that lands when Tier B graduates from research with the
// full XPC service Info.plist + entitlements). This loader
// proves the JSON-RPC-over-stdio contract end-to-end and
// produces ArtifactRecords the daemon commits via the existing
// ArtifactStore.
//
// The contract:
//   - Daemon spawns the binary as a subprocess.
//   - Daemon writes one JSON-RPC request per line to subprocess
//     stdin.
//   - Subprocess writes one JSON-RPC response per line to stdout.
//   - Each artifact in a `collect` response is converted to an
//     ArtifactRecord on the daemon side and committed.

import Foundation
import CryptoKit

public actor TierBSubprocessLoader {

    public enum LoaderError: Error, CustomStringConvertible {
        case binaryMissing(path: String)
        case spawnFailed(message: String)
        case ipcWriteFailed(message: String)
        case ipcReadFailed(message: String)
        case protocolError(message: String)
        case subprocessError(code: Int, message: String)
        case responseLineTooLarge(limitBytes: Int)
        case artifactCountExceeded(limit: Int)
        case artifactDataTooLarge(limitBytes: Int, observedBytes: Int)
        case subprocessTimedOut(seconds: Double)

        public var description: String {
            switch self {
            case .binaryMissing(let p): return "TierBSubprocessLoader: binary missing at \(p)"
            case .spawnFailed(let m): return "TierBSubprocessLoader: spawn failed: \(m)"
            case .ipcWriteFailed(let m): return "TierBSubprocessLoader: stdin write failed: \(m)"
            case .ipcReadFailed(let m): return "TierBSubprocessLoader: stdout read failed: \(m)"
            case .protocolError(let m): return "TierBSubprocessLoader: protocol error: \(m)"
            case .subprocessError(let c, let m): return "TierBSubprocessLoader: subprocess error \(c): \(m)"
            case .responseLineTooLarge(let n): return "TierBSubprocessLoader: subprocess response line exceeded \(n) bytes (DoS guard)"
            case .artifactCountExceeded(let n): return "TierBSubprocessLoader: subprocess returned more than \(n) artifacts (DoS guard)"
            case .artifactDataTooLarge(let lim, let obs): return "TierBSubprocessLoader: artifact data_json (\(obs) bytes) exceeded \(lim) bytes (DoS guard)"
            case .subprocessTimedOut(let s): return "TierBSubprocessLoader: subprocess did not respond within \(s) seconds (DoS guard)"
            }
        }
    }

    /// DoS guard limits. Hardcoded — these protect the daemon
    /// from a hostile (or buggy) Tier B plugin. Per plan §3.9
    /// "the host process must not be at the mercy of a sandboxed
    /// guest." Numbers chosen to allow legitimate plugins to do
    /// real forensic work — Tier A plugins routinely commit a
    /// few thousand artifacts per case — while denying a plugin
    /// the ability to OOM the daemon or fill the disk.
    public struct Limits: Sendable {
        /// Maximum bytes the daemon will buffer waiting for a
        /// '\n' terminator on subprocess stdout. 16 MB easily
        /// covers a fat JSON-RPC response with thousands of
        /// metadata-class artifacts.
        public let maxResponseLineBytes: Int
        /// Maximum artifacts a single collect response may
        /// commit. Larger requests probably indicate a runaway
        /// plugin loop.
        public let maxArtifactsPerResponse: Int
        /// Maximum bytes per artifact's `data_json` payload.
        public let maxArtifactDataBytes: Int
        /// Wall-clock deadline for the subprocess to respond
        /// to a collect request.
        public let subprocessTimeoutSeconds: Double

        public init(
            maxResponseLineBytes: Int = 16 * 1024 * 1024,
            maxArtifactsPerResponse: Int = 10_000,
            maxArtifactDataBytes: Int = 1 * 1024 * 1024,
            subprocessTimeoutSeconds: Double = 30
        ) {
            self.maxResponseLineBytes = maxResponseLineBytes
            self.maxArtifactsPerResponse = maxArtifactsPerResponse
            self.maxArtifactDataBytes = maxArtifactDataBytes
            self.subprocessTimeoutSeconds = subprocessTimeoutSeconds
        }

        public static let `default` = Limits()
    }

    public let limits: Limits

    public init(limits: Limits = .default) {
        self.limits = limits
        Self.ignoreSIGPIPEOnce()
    }

    /// Idempotent: set SIGPIPE → SIG_IGN once for the process.
    /// Required so a hostile (or buggy) Tier B subprocess that
    /// closes its end of the pipe mid-conversation can't kill the
    /// daemon by triggering SIGPIPE on the daemon's next write.
    /// Default disposition is process-terminating; we want EPIPE
    /// surfaced as a Swift error instead.
    private static let _sigpipeIgnoreOnce: Void = {
        signal(SIGPIPE, SIG_IGN)
    }()
    private static func ignoreSIGPIPEOnce() { _ = _sigpipeIgnoreOnce }

    /// Result of a Tier B collect invocation. Mirrors the Tier A
    /// CollectionResult shape but carries the parsed artifacts so
    /// the daemon can decide how to commit them.
    public struct TierBCollectResult: Sendable {
        public let artifacts: [TierBArtifact]
        public let notes: [String]
        public let status: String
        public let subprocessExitCode: Int32
    }

    public struct TierBArtifact: Sendable {
        public let contentType: String
        public let sha256: String
        public let summary: String
        public let confidence: String
        public let privacyClass: String
        public let dataJSON: String
    }

    /// Spawn the plugin, send a `collect` request, read the
    /// response, signal shutdown, wait for exit. Returns the
    /// parsed Tier B result for the daemon to commit.
    ///
    /// When `sandboxProfile` is non-nil, the binary is spawned
    /// inside a /usr/bin/sandbox-exec wrapper with the compiled
    /// profile applied. The profile is written to a temp file
    /// that is deleted after the subprocess exits.
    public func runCollect(
        binaryPath: String,
        caseID: String,
        caseName: String,
        encryptionState: String,
        tickCount: Int = 1,
        probeRead: String? = nil,
        sandboxProfile: SandboxProfileSpec? = nil
    ) async throws -> TierBCollectResult {

        guard FileManager.default.isExecutableFile(atPath: binaryPath) else {
            throw LoaderError.binaryMissing(path: binaryPath)
        }

        let proc = Process()
        // Compile + materialize the sandbox profile if supplied.
        var profileFileToDelete: String? = nil
        if let spec = sandboxProfile {
            // Always allow process-exec + file-read on the binary
            // itself, plus its containing directory + .build/debug
            // for Swift runtime / dyld cache discovery. Operators
            // declare the rest in the manifest's SandboxProfileSpec.
            let binaryDir = (binaryPath as NSString).deletingLastPathComponent
            let augmented = SandboxProfileSpec(
                allowAllByDefault: spec.allowAllByDefault,
                fileReadSubpaths: spec.fileReadSubpaths + [binaryDir],
                fileWriteSubpaths: spec.fileWriteSubpaths,
                networkConnectAllowlist: spec.networkConnectAllowlist,
                machServiceConnects: spec.machServiceConnects,
                processExecPaths: spec.processExecPaths + [binaryPath],
                allowProcessFork: true
            )
            let sbplText = SandboxProfileBuilder.compile(augmented)
            let profilePath = NSTemporaryDirectory()
                + "maccrab-tier-b-\(UUID().uuidString).sb"
            do {
                try sbplText.write(
                    toFile: profilePath,
                    atomically: true,
                    encoding: .utf8
                )
            } catch {
                throw LoaderError.spawnFailed(message: "could not write sandbox profile: \(error.localizedDescription)")
            }
            profileFileToDelete = profilePath
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
            proc.arguments = ["-f", profilePath, binaryPath]
        } else {
            proc.executableURL = URL(fileURLWithPath: binaryPath)
        }
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        proc.standardInput = stdin
        proc.standardOutput = stdout
        proc.standardError = stderr

        do {
            try proc.run()
        } catch {
            throw LoaderError.spawnFailed(message: error.localizedDescription)
        }

        // Send collect request.
        var params: [String: Any] = [
            "case_id": caseID,
            "case_name": caseName,
            "encryption_state": encryptionState,
            "tick_count": tickCount,
        ]
        if let probe = probeRead {
            params["probe_file"] = probe
        }
        let request: [String: Any] = [
            "jsonrpc": "2.0",
            "id": 1,
            "method": "collect",
            "params": params,
        ]
        guard let reqData = try? JSONSerialization.data(withJSONObject: request) else {
            proc.terminate()
            throw LoaderError.protocolError(message: "could not encode collect request")
        }
        do {
            try stdin.fileHandleForWriting.write(contentsOf: reqData)
            try stdin.fileHandleForWriting.write(contentsOf: Data([0x0a]))
        } catch {
            proc.terminate()
            throw LoaderError.ipcWriteFailed(message: error.localizedDescription)
        }

        // Read response. We expect one JSON line per response;
        // collect emits one line then waits for shutdown. Two
        // guards: size limit (max 16 MB) + wall-clock timeout
        // (default 30 s). A hostile plugin can otherwise OOM
        // the daemon or hang it indefinitely.
        let responseLine: Data
        do {
            responseLine = try await Self.readLineFromHandleWithLimits(
                stdout.fileHandleForReading,
                process: proc,
                maxBytes: limits.maxResponseLineBytes,
                timeoutSeconds: limits.subprocessTimeoutSeconds
            )
        } catch let e as LoaderError {
            proc.terminate()
            if let path = profileFileToDelete {
                try? FileManager.default.removeItem(atPath: path)
            }
            throw e
        } catch {
            proc.terminate()
            if let path = profileFileToDelete {
                try? FileManager.default.removeItem(atPath: path)
            }
            throw LoaderError.ipcReadFailed(message: error.localizedDescription)
        }
        guard let responseAny = try? JSONSerialization.jsonObject(with: responseLine) as? [String: Any] else {
            proc.terminate()
            throw LoaderError.protocolError(message: "subprocess emitted non-JSON: \(String(data: responseLine, encoding: .utf8) ?? "(binary)")")
        }
        if let errObj = responseAny["error"] as? [String: Any] {
            let code = (errObj["code"] as? Int) ?? -1
            let message = (errObj["message"] as? String) ?? "(no message)"
            // Signal shutdown so the subprocess exits cleanly
            // even on error.
            Self.sendShutdown(to: stdin)
            proc.waitUntilExit()
            throw LoaderError.subprocessError(code: code, message: message)
        }
        guard let result = responseAny["result"] as? [String: Any],
              let artifactsRaw = result["artifacts"] as? [[String: Any]] else {
            Self.sendShutdown(to: stdin)
            proc.waitUntilExit()
            throw LoaderError.protocolError(message: "collect response missing result.artifacts")
        }

        // Cap artifact count + per-artifact data size before
        // parsing so a malicious plugin can't fill memory by
        // building a huge in-memory artifact array.
        if artifactsRaw.count > limits.maxArtifactsPerResponse {
            Self.sendShutdown(to: stdin)
            proc.waitUntilExit()
            if let path = profileFileToDelete {
                try? FileManager.default.removeItem(atPath: path)
            }
            throw LoaderError.artifactCountExceeded(limit: limits.maxArtifactsPerResponse)
        }
        var artifacts: [TierBArtifact] = []
        artifacts.reserveCapacity(artifactsRaw.count)
        for raw in artifactsRaw {
            let ct = (raw["content_type"] as? String) ?? "tier_b.unknown"
            let sha = (raw["sha256"] as? String) ?? ""
            let summary = (raw["summary"] as? String) ?? ""
            let confidence = (raw["confidence"] as? String) ?? "observed"
            let pc = (raw["privacy_class"] as? String) ?? "metadata"
            let dataJSON = (raw["data_json"] as? String) ?? "{}"
            let dataBytes = dataJSON.utf8.count
            if dataBytes > limits.maxArtifactDataBytes {
                Self.sendShutdown(to: stdin)
                proc.waitUntilExit()
                if let path = profileFileToDelete {
                    try? FileManager.default.removeItem(atPath: path)
                }
                throw LoaderError.artifactDataTooLarge(
                    limitBytes: limits.maxArtifactDataBytes,
                    observedBytes: dataBytes
                )
            }
            artifacts.append(TierBArtifact(
                contentType: ct,
                sha256: sha,
                summary: summary,
                confidence: confidence,
                privacyClass: pc,
                dataJSON: dataJSON
            ))
        }
        let notes = (result["notes"] as? [String]) ?? []
        let status = (result["status"] as? String) ?? "ok"

        // Signal shutdown + wait.
        Self.sendShutdown(to: stdin)
        proc.waitUntilExit()
        let exitCode = proc.terminationStatus

        // Clean up the temp profile file after subprocess exits.
        if let path = profileFileToDelete {
            try? FileManager.default.removeItem(atPath: path)
        }

        return TierBCollectResult(
            artifacts: artifacts,
            notes: notes,
            status: status,
            subprocessExitCode: exitCode
        )
    }

    /// Read one '\n'-terminated line from a FileHandle, bounded
    /// by maxBytes (throws responseLineTooLarge if exceeded) and
    /// by a wall-clock timeout (throws subprocessTimedOut if
    /// exceeded; also terminates the subprocess so the pipe
    /// closes and the read loop exits).
    private static func readLineFromHandleWithLimits(
        _ fh: FileHandle,
        process: Process,
        maxBytes: Int,
        timeoutSeconds: Double
    ) async throws -> Data {
        // Set up a deadline. We use an in-actor Task that fires
        // after `timeoutSeconds` and terminates the subprocess —
        // closing its stdout, which lets the read loop notice
        // EOF. The reader then detects the deadline-fired flag
        // and throws subprocessTimedOut rather than ipcReadFailed.
        let timeoutNanos = UInt64(timeoutSeconds * 1_000_000_000)
        let deadlineFired = LockedBox<Bool>(false)
        let timeoutTask = Task {
            try? await Task.sleep(nanoseconds: timeoutNanos)
            if process.isRunning {
                deadlineFired.set(true)
                process.terminate()
            }
        }
        defer { timeoutTask.cancel() }

        var buffer = Data()
        while true {
            let chunk = fh.availableData
            if chunk.isEmpty { break } // EOF (or terminated)
            if buffer.count + chunk.count > maxBytes {
                throw LoaderError.responseLineTooLarge(limitBytes: maxBytes)
            }
            buffer.append(chunk)
            if let nl = buffer.firstIndex(of: 0x0a) {
                return buffer.subdata(in: 0..<nl)
            }
        }
        if deadlineFired.get() {
            throw LoaderError.subprocessTimedOut(seconds: timeoutSeconds)
        }
        if buffer.isEmpty {
            throw NSError(domain: "TierBSubprocessLoader", code: 1, userInfo: [
                NSLocalizedDescriptionKey: "subprocess closed stdout before responding",
            ])
        }
        return buffer
    }

    /// Sendable thread-safe box for the deadline-fired flag.
    /// The reader runs on the actor's executor; the timeout
    /// task runs on a background executor. Both touch this.
    private final class LockedBox<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var value: T
        init(_ initial: T) { self.value = initial }
        func get() -> T { lock.lock(); defer { lock.unlock() }; return value }
        func set(_ new: T) { lock.lock(); value = new; lock.unlock() }
    }

    private static func sendShutdown(to stdin: Pipe) {
        let shutdownReq: [String: Any] = [
            "jsonrpc": "2.0",
            "id": 999,
            "method": "shutdown",
        ]
        if let data = try? JSONSerialization.data(withJSONObject: shutdownReq) {
            try? stdin.fileHandleForWriting.write(contentsOf: data)
            try? stdin.fileHandleForWriting.write(contentsOf: Data([0x0a]))
            try? stdin.fileHandleForWriting.close()
        }
    }

}

// MARK: - Daemon-side commit helper

public extension TierBSubprocessLoader {

    /// Convenience: spawn the binary, collect, and commit every
    /// returned artifact to the supplied ArtifactStore using the
    /// existing TierA ArtifactRecord type. Returns commit counts.
    func runCollectAndCommit(
        binaryPath: String,
        pluginID: String,
        pluginVersion: String,
        schemaVersion: Int,
        caseID: String,
        caseName: String,
        encryptionState: CaseEncryptionState,
        store: ArtifactStore,
        tickCount: Int = 1,
        probeRead: String? = nil,
        sandboxProfile: SandboxProfileSpec? = nil
    ) async throws -> (committed: Int, rejected: Int, result: TierBCollectResult) {
        let result = try await runCollect(
            binaryPath: binaryPath,
            caseID: caseID,
            caseName: caseName,
            encryptionState: encryptionState.rawValue,
            tickCount: tickCount,
            probeRead: probeRead,
            sandboxProfile: sandboxProfile
        )
        var committed = 0
        var rejected = 0
        let now = Date()
        for a in result.artifacts {
            // Parse the data_json blob into [String: JSONValue].
            var data: [String: JSONValue] = [:]
            if let bytes = a.dataJSON.data(using: .utf8),
               let parsed = (try? JSONSerialization.jsonObject(with: bytes)) as? [String: Any] {
                for (k, v) in parsed {
                    data[k] = Self.toJSONValue(v)
                }
            }
            let privacy = PrivacyClass(rawValue: a.privacyClass) ?? .metadata
            let confidence = Confidence(rawValue: a.confidence) ?? .observed
            let record = ArtifactRecord(
                caseID: caseID,
                pluginID: pluginID,
                pluginVersion: pluginVersion,
                schemaVersion: schemaVersion,
                contentType: a.contentType,
                sha256: a.sha256,
                observedAt: now,
                capturedAt: now,
                summary: a.summary,
                sizeBytes: Int64(a.dataJSON.utf8.count),
                confidence: confidence,
                privacyClass: privacy,
                data: data
            )
            do {
                try await store.commit(record)
                committed += 1
            } catch {
                rejected += 1
            }
        }
        return (committed, rejected, result)
    }

    private static func toJSONValue(_ any: Any) -> JSONValue {
        if let b = any as? Bool { return .bool(b) }
        if let i = any as? Int { return .integer(Int64(i)) }
        if let i = any as? Int64 { return .integer(i) }
        if let d = any as? Double { return .double(d) }
        if let s = any as? String { return .string(s) }
        if any is NSNull { return .null }
        return .string("\(any)")
    }
}
