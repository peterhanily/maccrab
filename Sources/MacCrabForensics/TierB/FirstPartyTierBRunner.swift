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
import Darwin

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

        // Pipes (raw fds): child stdin <- in[0], stdout -> out[1], stderr -> err[1].
        var inFds: [Int32] = [-1, -1]
        var outFds: [Int32] = [-1, -1]
        var errFds: [Int32] = [-1, -1]
        guard pipe(&inFds) == 0, pipe(&outFds) == 0, pipe(&errFds) == 0 else {
            throw FirstPartyTierBRunnerError.spawnFailed(pluginID: verified.pluginID, message: "pipe() failed")
        }

        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, inFds[0], 0)
        posix_spawn_file_actions_adddup2(&fileActions, outFds[1], 1)
        posix_spawn_file_actions_adddup2(&fileActions, errFds[1], 2)
        posix_spawn_file_actions_addclose(&fileActions, inFds[1])
        posix_spawn_file_actions_addclose(&fileActions, outFds[0])
        posix_spawn_file_actions_addclose(&fileActions, errFds[0])
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        // Own process group with the child as leader (pgid == child pid) → the
        // whole subtree is reachable via kill(-pid, ...).
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP))
        posix_spawnattr_setpgroup(&attr, 0)
        defer { posix_spawnattr_destroy(&attr) }

        let argv: [UnsafeMutablePointer<CChar>?] = [strdup(verified.binaryPath), nil]
        let envp: [UnsafeMutablePointer<CChar>?] = [
            strdup("PATH=/usr/bin:/bin"),
            strdup("HOME=\(NSHomeDirectory())"),
            nil,
        ]
        defer {
            for p in argv where p != nil { free(p) }
            for p in envp where p != nil { free(p) }
        }

        var pid: pid_t = 0
        let spawnRC = posix_spawn(&pid, verified.binaryPath, &fileActions, &attr, argv, envp)
        // Parent closes the child ends of every pipe.
        close(inFds[0]); close(outFds[1]); close(errFds[1])
        guard spawnRC == 0 else {
            close(inFds[1]); close(outFds[0]); close(errFds[0])
            throw FirstPartyTierBRunnerError.spawnFailed(
                pluginID: verified.pluginID,
                message: "posix_spawn: \(String(cString: strerror(spawnRC)))")
        }
        // Per-fd SIGPIPE suppression (audit HIGH#1).
        _ = fcntl(inFds[1], F_SETNOSIGPIPE, 1)

        let inWrite = FileHandle(fileDescriptor: inFds[1], closeOnDealloc: true)
        let outHandle = FileHandle(fileDescriptor: outFds[0], closeOnDealloc: true)
        let errHandle = FileHandle(fileDescriptor: errFds[0], closeOnDealloc: true)

        let lock = NSLock()
        var outBuf = Data()
        var truncated = false
        var errBuf = Data()
        let readQ = DispatchQueue(label: "com.maccrab.tierb.stdout")
        let errQ = DispatchQueue(label: "com.maccrab.tierb.stderr")
        let outDone = DispatchSemaphore(value: 0)
        let errDone = DispatchSemaphore(value: 0)

        // Background drain of stdout with a running cap (no pipe-buffer deadlock / OOM).
        readQ.async {
            while true {
                let chunk = outHandle.availableData
                if chunk.isEmpty { break }     // EOF
                lock.lock()
                if outBuf.count + chunk.count > TierBIPC.maxStdoutBytes {
                    let room = max(0, TierBIPC.maxStdoutBytes - outBuf.count)
                    if room > 0 { outBuf.append(chunk.prefix(room)) }
                    truncated = true
                    lock.unlock()
                    kill(-pid, SIGKILL)        // stop the producer(s): the whole group
                    break
                }
                outBuf.append(chunk)
                lock.unlock()
            }
            outDone.signal()
        }
        errQ.async {
            while true {
                let chunk = errHandle.availableData
                if chunk.isEmpty { break }
                if errBuf.count < 64 * 1024 { errBuf.append(chunk.prefix(64 * 1024 - errBuf.count)) }
            }
            errDone.signal()
        }

        // Wall-clock timeout → SIGTERM the GROUP, then SIGKILL the GROUP after a grace.
        var timedOut = false
        let timer = DispatchSource.makeTimerSource()
        timer.schedule(deadline: .now() + timeout)
        timer.setEventHandler {
            timedOut = true
            kill(-pid, SIGTERM)
            DispatchQueue.global().asyncAfter(deadline: .now() + 2.0) { kill(-pid, SIGKILL) }
        }
        timer.resume()

        // Deliver the request (one JSON line) then close stdin. Tolerate EPIPE.
        if let reqData = try? JSONEncoder().encode(TierBCollectRequest(
            pluginID: verified.pluginID,
            pluginVersion: verified.manifest.version,
            scratchDir: scratchDir,
            windowStartUnix: windowStartUnix,
            windowEndUnix: windowEndUnix
        )) {
            try? inWrite.write(contentsOf: reqData)
            try? inWrite.write(contentsOf: Data([0x0A]))
        }
        try? inWrite.close()

        // Await the leader's exit WITHOUT reaping (WNOWAIT keeps the zombie, so the
        // pgid stays valid + the pid can't be reused), THEN SIGKILL the whole GROUP
        // to reap any forked descendant, THEN reap the leader for its exit status.
        // The timer bounds this wait (it SIGKILLs the group on timeout).
        var si = siginfo_t()
        _ = waitid(P_PID, id_t(pid), &si, WEXITED | WNOWAIT)
        kill(-pid, SIGKILL)
        var status: Int32 = 0
        waitpid(pid, &status, 0)
        timer.cancel()

        // The group is dead now, so EOF should arrive promptly; keep the bound as a
        // safety net against any unexpected fd holder.
        _ = outDone.wait(timeout: .now() + 3.0)
        _ = errDone.wait(timeout: .now() + 3.0)

        lock.lock()
        let finalOut = outBuf
        let didTruncate = truncated
        let finalErr = errBuf
        lock.unlock()

        let parsed = Self.parseOutputLines(finalOut)
        let stderrTail = String(data: finalErr, encoding: .utf8) ?? ""
        // exit status: WIFEXITED → code; WIFSIGNALED → -signal.
        let exitCode: Int32 = (status & 0x7f) == 0 ? ((status >> 8) & 0xff) : -(status & 0x7f)

        return TierBRunOutcome(
            artifacts: parsed.artifacts,
            result: parsed.result,
            exitCode: exitCode,
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
