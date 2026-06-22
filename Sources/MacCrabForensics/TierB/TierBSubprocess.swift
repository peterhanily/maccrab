// TierBSubprocess — the ONE copy of the Tier-B subprocess spawn / drain / reap /
// timeout machinery shared by FirstPartyTierBRunner (unsandboxed) and
// SandboxedTierBRunner (the trampoline lane). These ~150 lines were previously
// byte-duplicated across both runners, so a hardening fix to one silently missed
// the other (audit #9: the most security-sensitive subprocess code in the product
// must have a single source of truth).
//
// Security-critical invariants preserved EXACTLY (these are the audit-hardened
// behaviors the duplication risked diverging):
//   - own process group (POSIX_SPAWN_SETPGROUP) so the whole subtree is reaped via
//     kill(-pgid), never orphaned;
//   - env scrubbed to PATH + HOME only (no MACCRAB_* / DEK leak to the child);
//   - request on stdin (one JSON line, slashes un-escaped), never argv; the stdin
//     write fd is F_SETNOSIGPIPE so a closed read end returns EPIPE, not SIGKILL;
//   - stdout STREAMED on a background thread with a running total-byte cap (no
//     readDataToEndOfFile-after-exit deadlock / OOM); stderr drained to a capped tail;
//   - wall-clock timeout → SIGTERM the group → SIGKILL the group after a grace;
//   - WNOWAIT the leader (no pid reuse) → SIGKILL the group → reap the leader.
//
// Lane-specific work stays in each runner and is injected via `Extras`: the
// sandboxed lane adds the broker fd-3 dup (an extra file action), the broker
// child-fd close after spawn, and the broker serve-thread start/teardown
// (afterSpawn / afterReap). Parse reuses FirstPartyTierBRunner.parseOutputLines
// (same wire contract; kept there with its tests).

import Foundation
import Darwin

public enum TierBSubprocessError: Error, CustomStringConvertible {
    case pipeFailed
    case spawnFailed(String)
    public var description: String {
        switch self {
        case .pipeFailed: return "pipe() failed"
        case .spawnFailed(let m): return m
        }
    }
}

public struct TierBSubprocess {

    /// Lane-specific spawn hooks. The default (first-party) adds nothing.
    public struct Extras {
        /// Extra posix_spawn file actions, e.g. dup the broker child end onto fd 3.
        public var fileActions: ((UnsafeMutablePointer<posix_spawn_file_actions_t?>) -> Void)?
        /// Child-end fds the PARENT closes UNCONDITIONALLY after the spawn call
        /// (e.g. the broker child fd — the child inherited it).
        public var parentCloseAfterSpawn: [Int32]
        /// fds to close only if the spawn FAILS (e.g. the broker host fd).
        public var parentCloseOnFailure: [Int32]
        /// Called right after a successful spawn (e.g. start the broker serve thread).
        public var afterSpawn: ((pid_t) -> Void)?
        /// Called after the child is reaped (e.g. broker teardown: close the host
        /// socket → EOF the serve loop → bounded join).
        public var afterReap: (() -> Void)?
        public init(
            fileActions: ((UnsafeMutablePointer<posix_spawn_file_actions_t?>) -> Void)? = nil,
            parentCloseAfterSpawn: [Int32] = [],
            parentCloseOnFailure: [Int32] = [],
            afterSpawn: ((pid_t) -> Void)? = nil,
            afterReap: (() -> Void)? = nil
        ) {
            self.fileActions = fileActions
            self.parentCloseAfterSpawn = parentCloseAfterSpawn
            self.parentCloseOnFailure = parentCloseOnFailure
            self.afterSpawn = afterSpawn
            self.afterReap = afterReap
        }
    }

    /// Spawn `executable` with `argvStrings` under the hardened machinery, deliver
    /// `request` on stdin, then stream + parse its TierBIPC stdout. SYNCHRONOUS —
    /// call off any actor/main thread. Throws `TierBSubprocessError` (callers map
    /// it to their lane's error type).
    public static func spawnAndStream(
        executable: String,
        argv argvStrings: [String],
        request: TierBCollectRequest,
        timeout: TimeInterval,
        extras: Extras = Extras()
    ) throws -> TierBRunOutcome {
        // Pipes (raw fds): child stdin <- in[0], stdout -> out[1], stderr -> err[1].
        var inFds: [Int32] = [-1, -1]
        var outFds: [Int32] = [-1, -1]
        var errFds: [Int32] = [-1, -1]
        guard pipe(&inFds) == 0, pipe(&outFds) == 0, pipe(&errFds) == 0 else {
            throw TierBSubprocessError.pipeFailed
        }

        var fileActions: posix_spawn_file_actions_t?
        posix_spawn_file_actions_init(&fileActions)
        posix_spawn_file_actions_adddup2(&fileActions, inFds[0], 0)
        posix_spawn_file_actions_adddup2(&fileActions, outFds[1], 1)
        posix_spawn_file_actions_adddup2(&fileActions, errFds[1], 2)
        posix_spawn_file_actions_addclose(&fileActions, inFds[1])
        posix_spawn_file_actions_addclose(&fileActions, outFds[0])
        posix_spawn_file_actions_addclose(&fileActions, errFds[0])
        extras.fileActions?(&fileActions)   // e.g. dup the broker child end onto fd 3
        defer { posix_spawn_file_actions_destroy(&fileActions) }

        var attr: posix_spawnattr_t?
        posix_spawnattr_init(&attr)
        // Own process group with the child as leader → the whole subtree is
        // reachable via kill(-pid). Even with fork-deny, the group reap stays correct.
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP))
        posix_spawnattr_setpgroup(&attr, 0)
        defer { posix_spawnattr_destroy(&attr) }

        let argv: [UnsafeMutablePointer<CChar>?] = argvStrings.map { strdup($0) } + [nil]
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
        let spawnRC = posix_spawn(&pid, executable, &fileActions, &attr, argv, envp)
        // Parent closes the child ends of every pipe + any lane-specific child fds
        // (UNCONDITIONAL: the child inherited them regardless of spawn success).
        close(inFds[0]); close(outFds[1]); close(errFds[1])
        for fd in extras.parentCloseAfterSpawn { close(fd) }
        guard spawnRC == 0 else {
            close(inFds[1]); close(outFds[0]); close(errFds[0])
            for fd in extras.parentCloseOnFailure { close(fd) }
            throw TierBSubprocessError.spawnFailed("posix_spawn: \(String(cString: strerror(spawnRC)))")
        }
        _ = fcntl(inFds[1], F_SETNOSIGPIPE, 1)

        extras.afterSpawn?(pid)   // e.g. start the broker serve thread on the host end

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
        // withoutEscapingSlashes: paths in the request must NOT be JSON-escaped
        // (`/`→`\/`), or a plugin's path comparison / a crude parser breaks.
        let reqEncoder = JSONEncoder()
        reqEncoder.outputFormatting = [.withoutEscapingSlashes]
        if let reqData = try? reqEncoder.encode(request) {
            try? inWrite.write(contentsOf: reqData)
            try? inWrite.write(contentsOf: Data([0x0A]))
        }
        try? inWrite.close()

        // Await the leader's exit WITHOUT reaping (WNOWAIT keeps the zombie so the
        // pgid stays valid + the pid can't be reused), THEN SIGKILL the whole GROUP
        // to reap any forked descendant, THEN reap the leader for its exit status.
        var si = siginfo_t()
        _ = waitid(P_PID, id_t(pid), &si, WEXITED | WNOWAIT)
        kill(-pid, SIGKILL)
        var status: Int32 = 0
        waitpid(pid, &status, 0)
        timer.cancel()

        extras.afterReap?()   // e.g. broker teardown (close host socket → join serve thread)

        // The group is dead now, so EOF should arrive promptly; keep the bound as a
        // safety net against any unexpected fd holder.
        _ = outDone.wait(timeout: .now() + 3.0)
        _ = errDone.wait(timeout: .now() + 3.0)

        lock.lock()
        let finalOut = outBuf
        let didTruncate = truncated
        let finalErr = errBuf
        lock.unlock()

        let parsed = FirstPartyTierBRunner.parseOutputLines(finalOut)
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
}
