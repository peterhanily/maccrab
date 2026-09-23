// SFTPOutput.swift
// MacCrabCore
//
// Upload batched alert NDJSON over SFTP by shelling out to the system
// `sftp` binary in batch mode (-b). No SwiftNIO-SSH dependency —
// macOS ships sftp by default and delegating to it gives us known_hosts
// enforcement and proper key handling for free.
//
// Strategy: buffer alerts in memory; on flush() (the daemon's output-flush
// timer and the graceful-shutdown hook) write the buffer to a temp file and
// invoke sftp with a batch script that issues `put` + quits. Then delete the
// temp file. A failed upload keeps its batch (bounded, oldest-drop) and the
// next flush retries it after an exponential backoff.
// Host key checking is mandatory — StrictHostKeyChecking=yes — so the
// operator MUST ensure the SSH key + known_hosts entry exist before
// the daemon starts.

import Foundation
import os.log

/// Builds the `sftp -b` batch script. The script is a line-oriented command
/// language, so every path that reaches it is validated against a
/// conservative allow-list and double-quoted: a remote path carrying a
/// newline, a quote or a control character could otherwise inject further
/// batch commands (`rm`, `get`, `!shell`) into a root-run sftp session.
enum SFTPBatchScript {
    /// Characters a path may contain. Deliberately narrow: no quotes,
    /// backslashes, globs, `#` (batch comment), `!` (batch shell escape),
    /// `$`/`` ` `` or control characters. Space is allowed because the path
    /// is always emitted double-quoted.
    private static let allowedCharacters: Set<Character> = {
        var set = Set<Character>()
        for scalar in UnicodeScalar("A").value...UnicodeScalar("Z").value {
            set.insert(Character(UnicodeScalar(scalar)!))
        }
        for scalar in UnicodeScalar("a").value...UnicodeScalar("z").value {
            set.insert(Character(UnicodeScalar(scalar)!))
        }
        for scalar in UnicodeScalar("0").value...UnicodeScalar("9").value {
            set.insert(Character(UnicodeScalar(scalar)!))
        }
        for c in " /._-~+@:," { set.insert(c) }
        return set
    }()

    static let maximumPathLength = 1_024

    /// True when `path` can be placed in a batch script without changing its
    /// meaning: non-empty, bounded, and every character is on the allow-list.
    /// Control characters (including newline and carriage return) and any
    /// quoting character fail this check.
    static func isRepresentable(_ path: String) -> Bool {
        guard !path.isEmpty, path.utf8.count <= maximumPathLength else { return false }
        for character in path {
            guard allowedCharacters.contains(character) else { return false }
        }
        return true
    }

    /// Double-quoted form for the batch script, or nil when the path is not
    /// representable. sftp's batch parser honours double quotes, which is what
    /// makes the embedded space safe.
    static func quoted(_ path: String) -> String? {
        guard isRepresentable(path) else { return nil }
        return "\"\(path)\""
    }

    /// The full batch script for one upload, or nil when any path is not
    /// representable. The caller must then fail the upload; it must never
    /// fall back to an unquoted interpolation.
    static func build(localPath: String, remotePath: String, localName: String) -> String? {
        guard let local = quoted(localPath),
              let remote = quoted("\(remotePath)/\(localName)") else {
            return nil
        }
        return """
            put \(local) \(remote)
            bye
            """
    }
}

public actor SFTPOutput: Output {

    public nonisolated let name = "sftp"

    /// Runs `/usr/bin/sftp` with the given arguments. Injected so the
    /// retain-and-retry path can be exercised without a server; the default
    /// is the bounded privileged runner below.
    typealias BatchRunner = @Sendable (_ arguments: [String]) -> BoundedPrivilegedProcessRunner.Result?

    // MARK: - Config

    private let host: String
    private let port: Int
    private let user: String
    private let privateKeyPath: String
    private let remotePath: String
    private let flushIntervalSeconds: TimeInterval
    /// True when `remotePath` failed `SFTPBatchScript.isRepresentable`. Both
    /// `send` and `flush` short-circuit, so a path that cannot be quoted
    /// safely never reaches a batch script (mirrors `S3Output.policyRejected`).
    private let remotePathRejected: Bool
    private let runner: BatchRunner

    // MARK: - State

    private let logger = Logger(subsystem: "com.maccrab.output", category: "sftp")
    private var buffer: OutputBatchBuffer
    private var backoff = OutputRetryBackoff()
    private var stats = OutputStats()

    // MARK: - Init

    /// - Parameters:
    ///   - host: SFTP server hostname.
    ///   - port: SFTP port (default 22).
    ///   - user: SSH user to authenticate as.
    ///   - privateKeyPath: Path to SSH private key (e.g.
    ///     `~/.ssh/maccrab_ed25519`).
    ///   - remotePath: Directory on the server to drop uploads into. Must be
    ///     representable in an sftp batch script (see `SFTPBatchScript`);
    ///     otherwise the sink is disabled and every alert counted as dropped.
    ///   - flushIntervalSeconds: Recommended daemon-timer interval for
    ///     invoking flush(). The daemon's output-flush timer takes the
    ///     smallest configured value; the actor itself doesn't own a timer.
    ///   - maxRetainedBytes / maxRetainedRecords: Bound on the in-memory
    ///     batch, including batches retained after a failed upload. Oldest
    ///     records are dropped first and counted in `OutputStats.dropped`.
    public init(
        host: String,
        port: Int = 22,
        user: String,
        privateKeyPath: String,
        remotePath: String,
        flushIntervalSeconds: TimeInterval = 300,
        maxRetainedBytes: Int = 8_388_608,
        maxRetainedRecords: Int = 10_000
    ) {
        self.init(
            host: host,
            port: port,
            user: user,
            privateKeyPath: privateKeyPath,
            remotePath: remotePath,
            flushIntervalSeconds: flushIntervalSeconds,
            maxRetainedBytes: maxRetainedBytes,
            maxRetainedRecords: maxRetainedRecords,
            runner: Self.defaultRunner
        )
    }

    init(
        host: String,
        port: Int = 22,
        user: String,
        privateKeyPath: String,
        remotePath: String,
        flushIntervalSeconds: TimeInterval = 300,
        maxRetainedBytes: Int = 8_388_608,
        maxRetainedRecords: Int = 10_000,
        runner: @escaping BatchRunner
    ) {
        self.host = host
        self.port = port
        self.user = user
        self.privateKeyPath = privateKeyPath
        self.remotePath = remotePath
        self.flushIntervalSeconds = flushIntervalSeconds
        self.runner = runner
        self.buffer = OutputBatchBuffer(
            maxRetainedBytes: maxRetainedBytes,
            maxRetainedRecords: maxRetainedRecords
        )
        let rejected = !SFTPBatchScript.isRepresentable(remotePath)
        if rejected {
            Logger(subsystem: "com.maccrab.output", category: "sftp")
                .error("SFTPOutput remotePath rejected: not representable in an sftp batch script (allowed: letters, digits, space, / . _ - ~ + @ : ,); output disabled")
        }
        self.remotePathRejected = rejected
    }

    // MARK: - Output

    public func send(alert: Alert, event: Event?) async {
        if remotePathRejected {
            stats.dropped += 1
            return
        }
        let finding = OCSFMapper.mapAlert(alert, event: event)
        guard let json = try? OCSFMapper.encodeJSON(finding) else {
            stats.dropped += 1
            return
        }
        let overflow = buffer.append(line: Data((json + "\n").utf8))
        if overflow > 0 {
            stats.dropped += overflow
            logger.warning("sftp buffer cap reached; dropped \(overflow) oldest record(s)")
        }
    }

    public func flush() async {
        if remotePathRejected { return }
        await uploadBuffer(now: Date())
    }

    public func outputStats() async -> OutputStats { stats }

    /// Records currently buffered, including any batch retained after a
    /// failed upload. Internal for tests.
    var bufferedRecordCount: Int { buffer.count }

    // MARK: - Private upload

    /// Bounded, environment-scrubbed sftp invocation. Preserve the account's
    /// fixed home-directory lookup for its known_hosts file, but inherit no
    /// process environment or SSH agent socket.
    private static let defaultRunner: BatchRunner = { arguments in
        let sftpEnvironment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
            "TMPDIR": "/private/tmp",
            "LANG": "C",
            "LC_ALL": "C",
        ]
        return BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/sftp",
            arguments: arguments,
            environment: sftpEnvironment,
            timeout: 60,
            maximumOutputBytes: 64 * 1_024
        )
    }

    /// Internal so tests can drive the backoff deterministically.
    func uploadBuffer(now: Date) async {
        guard !buffer.isEmpty else { return }
        guard backoff.mayAttempt(now: now) else { return }

        let (payload, count) = buffer.take()

        // Write batch to a temp NDJSON file.
        let tmpDir = NSTemporaryDirectory()
        let localName = "maccrab-\(Int(now.timeIntervalSince1970))-\(UUID().uuidString.prefix(8)).jsonl"
        let localPath = tmpDir + localName

        // Build sftp batch script. A path the script cannot carry safely is a
        // permanent condition (the temp dir is fixed for the process), so the
        // batch is dropped rather than retained for a retry that cannot succeed.
        guard let batchScript = SFTPBatchScript.build(
            localPath: localPath, remotePath: remotePath, localName: localName
        ) else {
            stats.dropped += count
            stats.lastError = "upload path not representable in sftp batch script"
            logger.error("sftp batch script rejected temp path; dropped \(count) record(s)")
            return
        }

        do {
            try payload.write(to: URL(fileURLWithPath: localPath), options: .atomic)
        } catch {
            recordFailure(payload: payload, count: count, detail: error.localizedDescription, now: now)
            return
        }
        defer { try? FileManager.default.removeItem(atPath: localPath) }

        let batchPath = tmpDir + "maccrab-sftp-batch-\(UUID().uuidString.prefix(8)).txt"
        do {
            try batchScript.write(toFile: batchPath, atomically: true, encoding: .utf8)
        } catch {
            recordFailure(payload: payload, count: count, detail: error.localizedDescription, now: now)
            return
        }
        defer { try? FileManager.default.removeItem(atPath: batchPath) }

        // Run sftp with strict host checking.
        let result = runner([
            "-b", batchPath,
            "-i", privateKeyPath,
            "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes",
            "-P", String(port),
            "\(user)@\(host)",
        ])
        if result?.succeeded == true {
            stats.sent += count
            stats.lastSentAt = now
            backoff.recordSuccess()
        } else {
            let status = result?.terminationStatus ?? -1
            let detail: String
            if result?.timedOut == true {
                detail = "sftp timed out"
            } else if result?.outputLimitExceeded == true {
                detail = "sftp diagnostic output exceeded 65536 bytes"
            } else if let output = result?.output,
                      let message = String(data: output, encoding: .utf8),
                      !message.isEmpty {
                detail = message
            } else if result == nil {
                detail = "sftp could not be launched"
            } else {
                detail = "status \(status)"
            }
            recordFailure(payload: payload, count: count, detail: detail, now: now)
            logger.error("sftp failed (status \(status)): \(String(detail.prefix(200)))")
        }
    }

    /// A failed upload keeps its batch for the next flush. The retained
    /// batch goes back in front of anything buffered meanwhile; whatever no
    /// longer fits under the caps is dropped oldest-first and counted.
    private func recordFailure(payload: Data, count: Int, detail: String, now: Date) {
        stats.failed += count
        stats.lastError = String(detail.prefix(200))
        backoff.recordFailure(now: now)
        let overflow = buffer.retain(payload: payload, count: count)
        if overflow > 0 {
            stats.dropped += overflow
            logger.warning("sftp retained batch exceeded cap; dropped \(overflow) oldest record(s)")
        }
    }
}
