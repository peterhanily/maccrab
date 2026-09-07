import Foundation
import os.log

/// Owns only the response-action anchor. Other PF features have separate owners.
actor TemporaryNetworkBlocks {
    static let anchorName = "com.maccrab.response"
    static let anchorFilename = "maccrab_response_blocks.conf"
    static let legacyAnchorFilename = "maccrab_blocks.conf"
    static let retryInterval: TimeInterval = 30
    static let maximumSleepInterval: TimeInterval = 3600
    private static let clockOrigin = ContinuousClock.now

    private static func monotonicTime() -> TimeInterval {
        let value = clockOrigin.duration(to: .now).components
        return Double(value.seconds) + Double(value.attoseconds) / 1e18
    }

    struct Block: Sendable, Equatable {
        let ip: String
        let expiresAt: Date
        let expiryDeadline: TimeInterval
        let ruleID: String
    }

    struct ReloadResult: Sendable {
        let loaded: Bool
        let enforcing: Bool
    }

    struct IO: Sendable {
        let write: @Sendable (String) async -> Bool
        let reload: @Sendable () async -> ReloadResult
        let legacyStateUnverified: @Sendable () -> Bool
    }

    struct Snapshot: Sendable {
        let blocks: [Block]
        let reconciliationPending: Bool
        let operationInFlight: Bool
    }

    private struct AddRequest {
        let ip: String
        let duration: TimeInterval
        let ruleID: String
        let isNew: Bool
    }

    private let io: IO
    private let now: @Sendable () -> Date
    private let monotonicNow: @Sendable () -> TimeInterval
    private let sleep: @Sendable (TimeInterval) async throws -> Void
    private let didSettle: @Sendable (Snapshot) -> Void
    private let logger = Logger(subsystem: "com.maccrab", category: "response-pf")
    private var blocks: [Block] = []
    // A restarted engine clears only its dedicated anchor. No in-memory TTL is
    // treated as proof that an older kernel rule disappeared with the process.
    private var reconciliationPending = true
    private var operationInFlight = false
    private var retryAt: TimeInterval?
    private var maintenanceTask: Task<Void, Never>?
    private var maintenanceEnabled = false
    private var maintenanceGeneration: UInt64 = 0
    private var checkedLegacyState = false

    init(
        io: IO,
        now: @escaping @Sendable () -> Date = { Date() },
        monotonicNow: (@Sendable () -> TimeInterval)? = nil,
        didSettle: @escaping @Sendable (Snapshot) -> Void = { _ in },
        sleep: @escaping @Sendable (TimeInterval) async throws -> Void = {
            try await Task.sleep(for: .seconds($0))
        }
    ) {
        self.io = io
        self.now = now
        self.monotonicNow = monotonicNow ?? { Self.monotonicTime() }
        self.sleep = sleep
        self.didSettle = didSettle
    }

    deinit { maintenanceTask?.cancel() }

    func startMaintenance() {
        guard !maintenanceEnabled else { return }
        maintenanceEnabled = true
        if !checkedLegacyState {
            checkedLegacyState = true
            if io.legacyStateUnverified() {
                logger.error("Legacy temporary PF state is unverified: review maccrab_blocks.conf and the shared com.maccrab anchor manually. Automatic cleanup is limited to com.maccrab.response; no shared-anchor rules were removed.")
            }
        }
        rescheduleMaintenance()
    }

    func stopMaintenance() async {
        maintenanceEnabled = false
        maintenanceGeneration &+= 1
        let task = maintenanceTask
        maintenanceTask = nil
        task?.cancel()
        await task?.value
    }

    private func rescheduleMaintenance() {
        guard maintenanceEnabled else { return }
        maintenanceTask?.cancel()
        maintenanceTask = nil
        maintenanceGeneration &+= 1
        let currentTime = monotonicNow()
        let deadline: TimeInterval
        if reconciliationPending {
            deadline = retryAt ?? currentTime
        } else if let expiry = blocks.map(\.expiryDeadline).min() {
            deadline = expiry
        } else {
            // No periodic wakeups once startup cleanup and all expirations
            // have settled. A later add explicitly installs a new deadline.
            return
        }
        let delay = min(Self.maximumSleepInterval, max(0, deadline - currentTime))
        let generation = maintenanceGeneration
        let sleeper = sleep
        maintenanceTask = Task { [weak self] in
            do {
                if delay > 0 { try await sleeper(delay) }
                try Task.checkCancellation()
            } catch { return }
            await self?.scheduledMaintenance(generation: generation)
        }
    }

    private func scheduledMaintenance(generation: UInt64) async {
        guard maintenanceEnabled, maintenanceGeneration == generation else { return }
        // The active transaction reschedules after its final state update.
        // Rescheduling an already-due timer here would spin while IO awaits.
        guard !operationInFlight else { return }
        await maintain()
        if maintenanceEnabled, maintenanceGeneration == generation {
            rescheduleMaintenance()
        }
    }

    func snapshot() -> Snapshot {
        Snapshot(blocks: blocks, reconciliationPending: reconciliationPending,
                 operationInFlight: operationInFlight)
    }

    func add(ip: String, durationSeconds: Int, ruleID: String) async -> Bool {
        guard durationSeconds > 0 else { return false }
        let duration = TimeInterval(durationSeconds)
        let expiresAt = now().addingTimeInterval(duration)
        guard expiresAt.timeIntervalSince1970.isFinite else { return false }
        await maintain()
        guard !operationInFlight, !reconciliationPending else { return false }
        var candidate = blocks
        let isNew = !candidate.contains(where: { $0.ip == ip })
        if isNew {
            candidate.append(Block(ip: ip, expiresAt: expiresAt,
                expiryDeadline: monotonicNow() + duration, ruleID: ruleID))
        }
        // Even a duplicate must verify the complete anchor; an old inventory
        // entry is not evidence that PF is still enforcing it.
        return await apply(candidate, request: AddRequest(
            ip: ip, duration: duration, ruleID: ruleID, isNew: isNew
        ))
    }

    func maintain() async {
        guard !operationInFlight else { return }
        let currentTime = monotonicNow()
        if let retryAt, currentTime < retryAt { return }
        let candidate = blocks.filter { $0.expiryDeadline > currentTime }
        guard reconciliationPending || candidate.count != blocks.count else { return }
        _ = await apply(candidate, request: nil)
    }

    private func apply(_ candidate: [Block], request: AddRequest?) async -> Bool {
        guard !operationInFlight else { return false }
        operationInFlight = true
        defer {
            operationInFlight = false
            rescheduleMaintenance()
            didSettle(snapshot())
        }
        let previous = blocks
        guard await io.write(Self.render(candidate)) else {
            deferRetry()
            logger.error("Temporary PF anchor write failed; committed block inventory is retained and reconciliation will retry.")
            return false
        }
        let result = await io.reload()
        if result.loaded && (request == nil || result.enforcing) {
            var committed = candidate
            let completedAt = now()
            let completedDeadline = monotonicNow()
            if let request, let index = committed.firstIndex(where: { $0.ip == request.ip }),
               request.isNew || committed[index].expiryDeadline <= completedDeadline {
                // The lifetime begins after the load/probe has completed, as
                // it did before this state-machine correction. A long load
                // cannot report a newly successful block with an elapsed TTL.
                committed[index] = Block(ip: request.ip,
                    expiresAt: completedAt.addingTimeInterval(request.duration),
                    expiryDeadline: completedDeadline + request.duration, ruleID: request.ruleID)
            }
            blocks = committed
            reconciliationPending = false
            retryAt = nil
            return true
        }

        // A failed add may still have loaded rules before the prerequisite
        // probe failed. Restore the entire committed snapshot, never leave an
        // untracked appended rule for a later successful request to activate.
        if request != nil, await io.write(Self.render(previous)) {
            let rollback = await io.reload()
            if rollback.loaded {
                reconciliationPending = false
                retryAt = nil
                logger.error("Temporary PF block was not confirmed; the previous dedicated-anchor rules were restored.")
                return false
            }
        }
        deferRetry()
        logger.error("Temporary PF reload was not confirmed; retained inventory and pending dedicated-anchor cleanup will retry. No removal or new block is reported applied.")
        return false
    }

    private func deferRetry() {
        reconciliationPending = true
        retryAt = monotonicNow() + Self.retryInterval
    }

    static func render(_ blocks: [Block]) -> String {
        var content = "# MacCrab response-action temporary blocks\n"
        content += "# Managed only by com.maccrab.response\n"
        for block in blocks {
            content += "block drop out quick to \(block.ip)\n"
        }
        return content
    }

    static func liveIO(supportDirectory: String) -> IO {
        let path = (supportDirectory as NSString).appendingPathComponent(anchorFilename)
        let legacyPath = (supportDirectory as NSString).appendingPathComponent(legacyAnchorFilename)
        return IO(
            write: { content in
                do {
                    try FileManager.default.createDirectory(atPath: supportDirectory, withIntermediateDirectories: true)
                    try content.write(toFile: path, atomically: true, encoding: .utf8)
                    return true
                } catch { return false }
            },
            reload: {
                await Task.detached(priority: .utility) {
                    let loaded = BoundedPrivilegedProcessRunner.run(
                        executable: "/sbin/pfctl", arguments: ["-a", anchorName, "-f", path],
                        timeout: 10, maximumOutputBytes: nil
                    )?.succeeded == true
                    return ReloadResult(loaded: loaded,
                        enforcing: loaded && PFEnforcement.probe(anchorName: anchorName).enforcing)
                }.value
            },
            legacyStateUnverified: {
                // Existence is deliberately enough: this older file has no
                // durable TTL inventory and unreadability cannot prove absence.
                FileManager.default.fileExists(atPath: legacyPath)
            }
        )
    }
}
