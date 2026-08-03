// SFTPOutput.swift
// MacCrabCore
//
// Upload batched alert NDJSON over SFTP by shelling out to the system
// `sftp` binary in batch mode (-b). No SwiftNIO-SSH dependency —
// macOS ships sftp by default and delegating to it gives us known_hosts
// enforcement and proper key handling for free.
//
// Strategy: buffer alerts in memory; on flush() (or when a periodic
// timer fires) write the buffer to a temp file and invoke sftp with a
// batch script that issues `put` + quits. Then delete the temp file.
// Host key checking is mandatory — StrictHostKeyChecking=yes — so the
// operator MUST ensure the SSH key + known_hosts entry exist before
// the daemon starts.

import Foundation
import os.log

public actor SFTPOutput: Output {

    public nonisolated let name = "sftp"

    // MARK: - Config

    private let host: String
    private let port: Int
    private let user: String
    private let privateKeyPath: String
    private let remotePath: String
    private let flushIntervalSeconds: TimeInterval

    // MARK: - State

    private let logger = Logger(subsystem: "com.maccrab.output", category: "sftp")
    private var buffer: Data = Data()
    private var bufferedCount: Int = 0
    private var stats = OutputStats()

    // MARK: - Init

    /// - Parameters:
    ///   - host: SFTP server hostname.
    ///   - port: SFTP port (default 22).
    ///   - user: SSH user to authenticate as.
    ///   - privateKeyPath: Path to SSH private key (e.g.
    ///     `~/.ssh/maccrab_ed25519`).
    ///   - remotePath: Directory on the server to drop uploads into.
    ///   - flushIntervalSeconds: Recommended daemon-timer interval for
    ///     invoking flush(). Stored for reference; the actor itself
    ///     doesn't own a timer.
    public init(
        host: String,
        port: Int = 22,
        user: String,
        privateKeyPath: String,
        remotePath: String,
        flushIntervalSeconds: TimeInterval = 300
    ) {
        self.host = host
        self.port = port
        self.user = user
        self.privateKeyPath = privateKeyPath
        self.remotePath = remotePath
        self.flushIntervalSeconds = flushIntervalSeconds
    }

    // MARK: - Output

    public func send(alert: Alert, event: Event?) async {
        let finding = OCSFMapper.mapAlert(alert, event: event)
        guard let json = try? OCSFMapper.encodeJSON(finding) else {
            stats.dropped += 1
            return
        }
        buffer.append(Data((json + "\n").utf8))
        bufferedCount += 1
    }

    public func flush() async {
        await uploadBuffer()
    }

    public func outputStats() async -> OutputStats { stats }

    // MARK: - Private upload

    private func uploadBuffer() async {
        guard !buffer.isEmpty else { return }

        let payload = buffer
        let count = bufferedCount
        buffer.removeAll(keepingCapacity: true)
        bufferedCount = 0

        // Write batch to a temp NDJSON file.
        let tmpDir = NSTemporaryDirectory()
        let localName = "maccrab-\(Int(Date().timeIntervalSince1970))-\(UUID().uuidString.prefix(8)).jsonl"
        let localPath = tmpDir + localName
        do {
            try payload.write(to: URL(fileURLWithPath: localPath), options: .atomic)
        } catch {
            stats.failed += count
            stats.lastError = error.localizedDescription
            return
        }
        defer { try? FileManager.default.removeItem(atPath: localPath) }

        // Build sftp batch script.
        let remoteFinal = "\(remotePath)/\(localName)"
        let batchScript = """
            put \(localPath) \(remoteFinal)
            bye
            """
        let batchPath = tmpDir + "maccrab-sftp-batch-\(UUID().uuidString.prefix(8)).txt"
        do {
            try batchScript.write(toFile: batchPath, atomically: true, encoding: .utf8)
        } catch {
            stats.failed += count
            stats.lastError = error.localizedDescription
            return
        }
        defer { try? FileManager.default.removeItem(atPath: batchPath) }

        // Run sftp with strict host checking. Preserve the account's fixed
        // home-directory lookup for its known_hosts file, but inherit no
        // process environment or SSH agent socket.
        let sftpEnvironment = [
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": FileManager.default.homeDirectoryForCurrentUser.path,
            "TMPDIR": "/private/tmp",
            "LANG": "C",
            "LC_ALL": "C",
        ]
        let result = BoundedPrivilegedProcessRunner.run(
            executable: "/usr/bin/sftp",
            arguments: [
            "-b", batchPath,
            "-i", privateKeyPath,
            "-o", "StrictHostKeyChecking=yes",
            "-o", "BatchMode=yes",
            "-P", String(port),
            "\(user)@\(host)",
            ],
            environment: sftpEnvironment,
            timeout: 60,
            maximumOutputBytes: 64 * 1_024
        )
        if result?.succeeded == true {
            stats.sent += count
            stats.lastSentAt = Date()
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
            stats.failed += count
            stats.lastError = String(detail.prefix(200))
            logger.error("sftp failed (status \(status)): \(String(detail.prefix(200)))")
        }
    }
}
