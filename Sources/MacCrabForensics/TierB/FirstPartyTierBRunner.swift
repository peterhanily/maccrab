// FirstPartyTierBRunner — spawns a verified FIRST-PARTY Tier-B plugin as a
// trusted subprocess and reads its TierBIPC stream (Shape 2, Phase 2b).
//
// First-party plugins run WITHOUT a sandbox profile (they are our own
// offline-key-signed code, exactly as trusted as a built-in) — so this runner is
// the SandboxAnalyzer Process pattern MINUS the /usr/bin/sandbox-exec wrapper,
// HARDENED against the Shape-2 attack pass:
//   - hard-requires VerifiedPlugin.isFirstParty (only the Phase-1 gate sets it);
//     a non-first-party plugin can never reach this runner.
//   - environment is scrubbed to PATH + HOME ONLY — never inherits the host env
//     (no MACCRAB_LLM_*_KEY / token leak); the SQLCipher DEK never crosses.
//   - the request goes via stdin (one JSON line), never argv (no secrets in argv).
//   - stdout is STREAMED on a background thread with a running total-byte cap
//     (no readDataToEndOfFile-after-exit deadlock/OOM); per-line, artifact-count,
//     and JSON-nesting caps are enforced when parsing.
//   - wall-clock timeout → terminate (SIGTERM) → SIGKILL escalation.
// The caller owns the scratch dir + maps the returned DTOs to ArtifactRecords
// (host stamps identity, recomputes size, ingests blobs) — see the Phase 2c bridge.

import Foundation

public struct TierBRunOutcome: Sendable {
    public let artifacts: [TierBArtifactDTO]
    public let result: TierBCollectResult?
    public let exitCode: Int32
    public let timedOut: Bool
    public let stdoutTruncated: Bool      // hit maxStdoutBytes / a too-long line / artifact cap
    public let decodeErrors: Int          // lines that failed to decode / exceeded depth
    public let stderrTail: String
}

public enum FirstPartyTierBRunnerError: Error, CustomStringConvertible {
    case notFirstParty(pluginID: String)
    case spawnFailed(pluginID: String, message: String)

    public var description: String {
        switch self {
        case .notFirstParty(let id):
            return "FirstPartyTierBRunner: refusing to spawn \(id) — not first-party-verified (only resolveForFirstPartyExecution may produce a runnable first-party plugin)"
        case .spawnFailed(let id, let m):
            return "FirstPartyTierBRunner: failed to spawn \(id): \(m)"
        }
    }
}

public struct FirstPartyTierBRunner: Sendable {

    public init() {}

    /// Spawn the verified first-party plugin, deliver the request on stdin, and
    /// stream + parse its TierBIPC stdout. SYNCHRONOUS (blocks until the child
    /// exits or the timeout fires) — call it off any actor/main thread.
    public func run(
        verified: TierBRegistry.VerifiedPlugin,
        scratchDir: String,
        windowStartUnix: Int64? = nil,
        windowEndUnix: Int64? = nil,
        timeout: TimeInterval = TierBIPC.defaultTimeoutSeconds
    ) throws -> TierBRunOutcome {
        // Defense in depth: this runner is ONLY for first-party-gated plugins.
        guard verified.isFirstParty else {
            throw FirstPartyTierBRunnerError.notFirstParty(pluginID: verified.pluginID)
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: verified.binaryPath)
        proc.arguments = []   // request crosses via stdin, never argv
        // Scrub the environment: PATH + HOME only. Never nil (nil inherits the
        // full host env). No MACCRAB_* / tokens / DEK ever cross the boundary.
        proc.environment = [
            "PATH": "/usr/bin:/bin",
            "HOME": NSHomeDirectory(),
        ]

        let inPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
        proc.standardInput = inPipe
        proc.standardOutput = outPipe
        proc.standardError = errPipe

        // Thread-safe stdout accumulator with a hard total-byte cap.
        let lock = NSLock()
        var outBuf = Data()
        var truncated = false
        let outHandle = outPipe.fileHandleForReading
        let errHandle = errPipe.fileHandleForReading
        let readQ = DispatchQueue(label: "com.maccrab.tierb.stdout")
        let errQ = DispatchQueue(label: "com.maccrab.tierb.stderr")
        let outDone = DispatchSemaphore(value: 0)
        let errDone = DispatchSemaphore(value: 0)
        var errBuf = Data()

        do {
            try proc.run()
        } catch {
            throw FirstPartyTierBRunnerError.spawnFailed(pluginID: verified.pluginID, message: "\(error)")
        }

        // Background drain of stdout with a running cap (avoids pipe-buffer
        // deadlock and unbounded memory).
        readQ.async {
            while true {
                let chunk = outHandle.availableData
                if chunk.isEmpty { break }      // EOF (child closed stdout / exited)
                lock.lock()
                if outBuf.count + chunk.count > TierBIPC.maxStdoutBytes {
                    let room = max(0, TierBIPC.maxStdoutBytes - outBuf.count)
                    if room > 0 { outBuf.append(chunk.prefix(room)) }
                    truncated = true
                    lock.unlock()
                    proc.terminate()
                    break
                }
                outBuf.append(chunk)
                lock.unlock()
            }
            outDone.signal()
        }
        // Background drain of stderr too (an un-drained stderr pipe can also
        // deadlock the child); keep only a small capped tail for diagnostics.
        errQ.async {
            while true {
                let chunk = errHandle.availableData
                if chunk.isEmpty { break }
                if errBuf.count < 64 * 1024 { errBuf.append(chunk.prefix(64 * 1024 - errBuf.count)) }
            }
            errDone.signal()
        }

        // Wall-clock timeout → SIGTERM, then SIGKILL escalation after a grace.
        var timedOut = false
        let timer = DispatchSource.makeTimerSource()
        timer.schedule(deadline: .now() + timeout)
        timer.setEventHandler {
            timedOut = true
            proc.terminate()
            let pid = proc.processIdentifier
            DispatchQueue.global().asyncAfter(deadline: .now() + 2.0) {
                if proc.isRunning { kill(pid, SIGKILL) }
            }
        }
        timer.resume()

        // Deliver the request (one JSON line) then close stdin. Tolerate EPIPE
        // (a plugin that never reads stdin); bound nothing else on this path.
        if let reqData = try? JSONEncoder().encode(TierBCollectRequest(
            pluginID: verified.pluginID,
            pluginVersion: verified.manifest.version,
            scratchDir: scratchDir,
            windowStartUnix: windowStartUnix,
            windowEndUnix: windowEndUnix
        )) {
            let w = inPipe.fileHandleForWriting
            try? w.write(contentsOf: reqData)
            try? w.write(contentsOf: Data([0x0A]))
        }
        try? inPipe.fileHandleForWriting.close()

        proc.waitUntilExit()
        timer.cancel()
        outDone.wait()
        errDone.wait()

        lock.lock()
        let finalOut = outBuf
        let didTruncate = truncated
        lock.unlock()

        let parsed = Self.parseOutputLines(finalOut)
        let stderrTail = String(data: errBuf, encoding: .utf8) ?? ""

        return TierBRunOutcome(
            artifacts: parsed.artifacts,
            result: parsed.result,
            exitCode: proc.terminationStatus,
            timedOut: timedOut,
            stdoutTruncated: didTruncate || parsed.truncated,
            decodeErrors: parsed.decodeErrors,
            stderrTail: String(stderrTail.prefix(4096))
        )
    }

    // MARK: - Pure parse (testable without spawning)

    /// Parse a JSONL stdout buffer into artifacts + the terminal result, enforcing
    /// the per-line, artifact-count, and JSON-nesting caps. Pure + deterministic.
    public static func parseOutputLines(
        _ data: Data
    ) -> (artifacts: [TierBArtifactDTO], result: TierBCollectResult?, decodeErrors: Int, truncated: Bool) {
        var artifacts: [TierBArtifactDTO] = []
        var result: TierBCollectResult? = nil
        var decodeErrors = 0
        var truncated = false
        let decoder = JSONDecoder()

        for lineData in data.split(separator: 0x0A, omittingEmptySubsequences: true) {
            let line = Data(lineData)
            if line.count > TierBIPC.maxLineBytes { truncated = true; decodeErrors += 1; continue }
            if jsonDepthExceeds(line, max: TierBIPC.maxJSONDepth) { decodeErrors += 1; continue }
            guard let parsed = try? decoder.decode(TierBOutputLine.self, from: line) else {
                decodeErrors += 1; continue
            }
            switch parsed {
            case .artifact(let a):
                if artifacts.count >= TierBIPC.maxArtifacts { truncated = true; continue }
                artifacts.append(a)
            case .result(let r):
                result = r   // last result line wins
            }
        }
        return (artifacts, result, decodeErrors, truncated)
    }

    /// Cheap structural depth scan (string-aware) so a deeply-nested line is
    /// rejected BEFORE handing it to JSONDecoder (nesting-DoS guard).
    static func jsonDepthExceeds(_ data: Data, max: Int) -> Bool {
        var depth = 0, maxSeen = 0
        var inString = false, escaped = false
        for b in data {
            if inString {
                if escaped { escaped = false }
                else if b == 0x5C { escaped = true }    // backslash
                else if b == 0x22 { inString = false }  // closing quote
                continue
            }
            switch b {
            case 0x22: inString = true                  // opening quote
            case 0x7B, 0x5B:                             // { or [
                depth += 1
                if depth > maxSeen { maxSeen = depth }
                if maxSeen > max { return true }
            case 0x7D, 0x5D:                             // } or ]
                if depth > 0 { depth -= 1 }
            default: break
            }
        }
        return false
    }
}
