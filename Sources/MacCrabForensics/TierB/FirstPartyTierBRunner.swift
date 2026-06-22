// FirstPartyTierBRunner — spawns a verified FIRST-PARTY Tier-B plugin as a
// trusted subprocess and reads its TierBIPC stream (Shape 2, Phase 2b + reap).
//
// First-party plugins run WITHOUT a sandbox profile (they are our own
// offline-key-signed code, exactly as trusted as a built-in), HARDENED against
// the Shape-2 attack pass:
//   - hard-requires VerifiedPlugin.isFirstParty (only the Phase-1 gate sets it);
//     a non-first-party plugin can never reach this runner.
//   - spawned in its OWN PROCESS GROUP (posix_spawn + POSIX_SPAWN_SETPGROUP) so
//     the entire subtree is reachable via kill(-pgid) — a forked descendant is
//     REAPED, not orphaned (Foundation.Process cannot set the group).
//   - environment scrubbed to PATH + HOME ONLY — never inherits the host env
//     (no MACCRAB_LLM_*_KEY / token leak); the SQLCipher DEK never crosses.
//   - request via stdin (one JSON line), never argv; the stdin write fd is
//     F_SETNOSIGPIPE so a closed-read-end write returns EPIPE, not a fatal SIGPIPE.
//   - stdout STREAMED on a background thread with a running total-byte cap (no
//     readDataToEndOfFile-after-exit deadlock/OOM); stderr drained to a capped
//     tail; per-line, artifact-count, and JSON-nesting caps enforced when parsing.
//   - wall-clock timeout → SIGTERM the group → SIGKILL the group; the child is
//     awaited WNOWAIT (no pid reuse) then the group is SIGKILL'd then reaped.
// The caller owns the scratch dir + maps the returned DTOs to ArtifactRecords
// (host stamps identity, recomputes size) — see the Phase 2c bridge.

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

        // First-party: spawn the verified binary directly (no sandbox, no broker).
        // The hardened spawn/drain/reap/timeout machinery is the shared
        // TierBSubprocess (audit #9: one source of truth across both lanes).
        do {
            return try TierBSubprocess.spawnAndStream(
                executable: verified.binaryPath,
                argv: [verified.binaryPath],
                request: TierBCollectRequest(
                    pluginID: verified.pluginID,
                    pluginVersion: verified.manifest.version,
                    scratchDir: scratchDir,
                    windowStartUnix: windowStartUnix,
                    windowEndUnix: windowEndUnix),
                timeout: timeout)
        } catch let e as TierBSubprocessError {
            throw FirstPartyTierBRunnerError.spawnFailed(pluginID: verified.pluginID, message: e.description)
        }
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
