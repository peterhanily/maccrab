// SequenceCheckpointTests.swift
// Durable SequenceEngine restart continuity and adversarial carrier validation.

import Testing
import Foundation
import Darwin
import Compression
@testable import MacCrabCore

private final class SequenceTestMonotonicClock: @unchecked Sendable {
    private let lock = NSLock()
    private var tick: TimeInterval

    init(_ tick: TimeInterval) { self.tick = tick }

    func now() -> TimeInterval {
        lock.lock()
        defer { lock.unlock() }
        return tick
    }

    func set(_ value: TimeInterval) {
        lock.lock()
        tick = value
        lock.unlock()
    }
}

@Suite("SequenceEngine durable recovery checkpoint")
struct SequenceCheckpointTests {
    private func process(
        _ executable: String,
        pid: Int32,
        ppid: Int32 = 1,
        ancestors: [ProcessAncestor] = []
    ) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid,
            ppid: ppid,
            rpid: 1,
            name: (executable as NSString).lastPathComponent,
            executable: executable,
            commandLine: executable,
            args: [executable],
            workingDirectory: "/tmp",
            userId: 501,
            userName: "checkpoint-test",
            groupId: 20,
            startTime: Date(),
            codeSignature: nil,
            ancestors: ancestors,
            architecture: "arm64",
            isPlatformBinary: false
        )
    }

    private func event(
        _ executable: String,
        pid: Int32,
        timestamp: Date,
        ppid: Int32 = 1,
        ancestors: [ProcessAncestor] = []
    ) -> Event {
        Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process(
                executable,
                pid: pid,
                ppid: ppid,
                ancestors: ancestors
            )
        )
    }

    private func rule(
        id: String = "checkpoint-sequence",
        window: TimeInterval = 600,
        enabled: Bool = true,
        finishSuffix: String = "/payload",
        correlation: CorrelationType = .processSame
    ) -> SequenceRule {
        SequenceRule(
            id: id,
            title: "checkpoint restart sequence",
            description: "download then execute",
            level: .high,
            tags: ["attack.execution", "attack.t1059"],
            window: window,
            correlationType: correlation,
            ordered: true,
            steps: [
                SequenceStep(
                    id: "download",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image",
                        modifier: .endswith,
                        values: ["/curl"],
                        negate: false
                    )]
                ),
                SequenceStep(
                    id: "execute",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image",
                        modifier: .endswith,
                        values: [finishSuffix],
                        negate: false
                    )],
                    afterStep: "download"
                ),
            ],
            trigger: .allSteps,
            enabled: enabled
        )
    }

    private func temporaryCheckpoint() throws -> (directory: URL, file: URL) {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-seq-checkpoint-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false
        )
        return (directory, directory.appendingPathComponent("sequence.chk"))
    }

    private func inode(of url: URL) throws -> UInt64 {
        var metadata = stat()
        guard url.path.withCString({ lstat($0, &metadata) }) == 0 else {
            throw SequenceCheckpointError.ioFailure("lstat errno \(errno)")
        }
        return UInt64(metadata.st_ino)
    }

    private func permissions(of url: URL) throws -> mode_t {
        var metadata = stat()
        guard url.path.withCString({ lstat($0, &metadata) }) == 0 else {
            throw SequenceCheckpointError.ioFailure("lstat errno \(errno)")
        }
        return metadata.st_mode & 0o777
    }

    private func deterministicBytes(count: Int, seed: UInt64) -> Data {
        var state = seed
        var bytes = [UInt8](repeating: 0, count: count)
        for index in bytes.indices {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            bytes[index] = UInt8(truncatingIfNeeded: state >> 24)
        }
        return Data(bytes)
    }

    private func lzfse(_ input: Data) throws -> Data {
        var output = Data(count: input.count + 1_024 * 1_024)
        let encodedCount = input.withUnsafeBytes { source in
            output.withUnsafeMutableBytes { destination in
                guard let sourceBase = source.bindMemory(to: UInt8.self).baseAddress,
                      let destinationBase = destination.bindMemory(to: UInt8.self).baseAddress else {
                    return 0
                }
                return compression_encode_buffer(
                    destinationBase,
                    destination.count,
                    sourceBase,
                    source.count,
                    nil,
                    COMPRESSION_LZFSE
                )
            }
        }
        guard encodedCount > 0 else {
            throw SequenceCheckpointError.decompressionFailed
        }
        output.count = encodedCount
        return output
    }

    @Test("a real partial completes after engine restart")
    func restartCompletion() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()

        let first = SequenceEngine(lineage: ProcessLineage())
        try await first.addRule(rule())
        _ = await first.evaluate(event("/usr/bin/curl", pid: 101, timestamp: base))

        let writer = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        let write = await writer.forceFlush(engine: first, now: base.addingTimeInterval(0.1))
        guard case .written = write else {
            Issue.record("expected checkpoint write, got \(write)")
            return
        }

        let restarted = SequenceEngine(lineage: ProcessLineage())
        try await restarted.addRule(rule())
        let reader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        let restore = await reader.restore(
            into: restarted,
            now: base.addingTimeInterval(0.2)
        )
        #expect(restore == .restored(
            partials: 1,
            pendingSteps: 0,
            expiredPartials: 0,
            expiredPendingSteps: 0
        ))

        let matches = await restarted.evaluate(
            event("/tmp/payload", pid: 101, timestamp: base.addingTimeInterval(1))
        )
        #expect(matches.contains { $0.ruleId == "checkpoint-sequence" })
        #expect(await restarted.activePartialMatchCount == 0)
    }

    @Test("persisted ancestry completes a process-lineage sequence after restart")
    func processLineageRestartCompletion() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()
        let lineageRule = rule(correlation: .processLineage)

        let first = SequenceEngine(lineage: ProcessLineage())
        try await first.addRule(lineageRule)
        _ = await first.evaluate(event(
            "/usr/bin/curl",
            pid: 900,
            timestamp: base,
            ppid: 50,
            ancestors: [ProcessAncestor(pid: 50, executable: "/bin/zsh", name: "zsh")]
        ))
        let writer = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        _ = await writer.forceFlush(engine: first, now: base.addingTimeInterval(0.1))

        // Deliberately use a fresh, empty ProcessLineage actor. The candidate is
        // a grandchild of the persisted first step, and its event-time ancestry
        // must carry the relation across the process restart.
        let restarted = SequenceEngine(lineage: ProcessLineage())
        try await restarted.addRule(lineageRule)
        let reader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .restored = await reader.restore(
            into: restarted,
            now: base.addingTimeInterval(0.2)
        ) else {
            Issue.record("process-lineage checkpoint did not restore")
            return
        }
        let matches = await restarted.evaluate(event(
            "/tmp/payload",
            pid: 902,
            timestamp: base.addingTimeInterval(1),
            ppid: 901,
            ancestors: [
                ProcessAncestor(pid: 901, executable: "/tmp/child", name: "child"),
                ProcessAncestor(pid: 900, executable: "/usr/bin/curl", name: "curl"),
            ]
        ))
        #expect(matches.contains { $0.ruleId == lineageRule.id })
    }

    @Test("out-of-order pending later step survives restart and replays")
    func pendingLaterStepContinuity() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()

        let first = SequenceEngine(lineage: ProcessLineage())
        try await first.addRule(rule())
        // Delivery is reversed but event time is chronological.
        _ = await first.evaluate(
            event("/tmp/payload", pid: 202, timestamp: base.addingTimeInterval(2))
        )
        let writer = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        _ = await writer.forceFlush(engine: first, now: base.addingTimeInterval(0.1))

        let restarted = SequenceEngine(lineage: ProcessLineage())
        try await restarted.addRule(rule())
        let reader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        let restore = await reader.restore(
            into: restarted,
            now: base.addingTimeInterval(0.2)
        )
        #expect(restore == .restored(
            partials: 0,
            pendingSteps: 1,
            expiredPartials: 0,
            expiredPendingSteps: 0
        ))

        let matches = await restarted.evaluate(
            event("/usr/bin/curl", pid: 202, timestamp: base)
        )
        #expect(matches.contains { $0.ruleId == "checkpoint-sequence" })
    }

    @Test("changed, removed, or differently-enabled rules cannot consume old state")
    func ruleFingerprintMismatchFailsClosed() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()

        let original = SequenceEngine(lineage: ProcessLineage())
        try await original.addRule(rule())
        _ = await original.evaluate(event("/usr/bin/curl", pid: 303, timestamp: base))
        let writer = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        _ = await writer.forceFlush(engine: original, now: base.addingTimeInterval(0.1))

        let changed = SequenceEngine(lineage: ProcessLineage())
        try await changed.addRule(rule(finishSuffix: "/different-payload"))
        let changedReader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .rejected(let changedDetail) = await changedReader.restore(
            into: changed,
            now: base.addingTimeInterval(0.2)
        ) else {
            Issue.record("changed rule definition unexpectedly restored old state")
            return
        }
        #expect(changedDetail.contains("fingerprint mismatch"))
        #expect(await changed.activePartialMatchCount == 0)

        let removed = SequenceEngine(lineage: ProcessLineage())
        try await removed.addRule(rule(id: "replacement-rule"))
        let removedReader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .rejected = await removedReader.restore(
            into: removed,
            now: base.addingTimeInterval(0.2)
        ) else {
            Issue.record("removed rule unexpectedly restored old state")
            return
        }

        let disabled = SequenceEngine(lineage: ProcessLineage())
        try await disabled.addRule(rule(enabled: false))
        let disabledReader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .rejected = await disabledReader.restore(
            into: disabled,
            now: base.addingTimeInterval(0.2)
        ) else {
            Issue.record("enabled-state mismatch unexpectedly restored old state")
            return
        }
    }

    @Test("expired state is validated, pruned, and cannot later complete")
    func expiryPrunesOnRestore() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()
        let shortRule = rule(window: 1)

        let first = SequenceEngine(lineage: ProcessLineage())
        try await first.addRule(shortRule)
        _ = await first.evaluate(event("/usr/bin/curl", pid: 404, timestamp: base))
        _ = await first.evaluate(
            event("/tmp/payload", pid: 405, timestamp: base.addingTimeInterval(0.2))
        ) // non-correlating later step remains pending
        let writer = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        _ = await writer.forceFlush(engine: first, now: base.addingTimeInterval(0.3))

        let restarted = SequenceEngine(lineage: ProcessLineage())
        try await restarted.addRule(shortRule)
        let reader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        let restore = await reader.restore(
            into: restarted,
            now: base.addingTimeInterval(5)
        )
        #expect(restore == .restored(
            partials: 0,
            pendingSteps: 0,
            expiredPartials: 1,
            expiredPendingSteps: 1
        ))
        #expect(await restarted.activePartialMatchCount == 0)

        let final = await restarted.evaluate(
            event("/tmp/payload", pid: 404, timestamp: base.addingTimeInterval(6))
        )
        #expect(final.isEmpty)
        #expect((await reader.telemetry(now: base.addingTimeInterval(5))).dirty)
    }

    @Test("corruption, truncation, bomb headers, and oversized files fail bounded")
    func malformedEnvelopeFailsBounded() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        let prepared = try SequenceCheckpointCodec.prepare(
            try await engine.checkpointCapture()
        )

        var corrupt = prepared.encodedFile
        corrupt[corrupt.index(before: corrupt.endIndex)] ^= 0xff
        #expect(throws: (any Error).self) {
            _ = try SequenceCheckpointCodec.decode(corrupt)
        }

        let truncated = Data(prepared.encodedFile.dropLast())
        #expect(throws: (any Error).self) {
            _ = try SequenceCheckpointCodec.decode(truncated)
        }

        var bomb = prepared.encodedFile
        let declared = UInt32(SequenceCheckpointCodec.maximumUncompressedBytes + 1)
        bomb[12] = UInt8((declared >> 24) & 0xff)
        bomb[13] = UInt8((declared >> 16) & 0xff)
        bomb[14] = UInt8((declared >> 8) & 0xff)
        bomb[15] = UInt8(declared & 0xff)
        #expect(throws: SequenceCheckpointError.self) {
            _ = try SequenceCheckpointCodec.decode(bomb)
        }

        let oversized = Data(
            repeating: 0,
            count: SequenceCheckpointCodec.maximumFileBytes + 1
        )
        #expect(throws: SequenceCheckpointError.self) {
            _ = try SequenceCheckpointCodec.decode(oversized)
        }
    }

    @Test("checkpoint read refuses public permissions and symlinks")
    func permissionsAndSymlinkDefense() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        let writer = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        _ = await writer.forceFlush(engine: engine)

        #expect(try permissions(of: fixture.file) == 0o600)
        #expect(fixture.file.path.withCString { chmod($0, 0o644) } == 0)
        let permissionsReader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .rejected(let permissionsDetail) = await permissionsReader.restore(
            into: SequenceEngine(lineage: ProcessLineage())
        ) else {
            Issue.record("0644 checkpoint unexpectedly accepted")
            return
        }
        #expect(permissionsDetail.contains("permissions are not private"))
        #expect(fixture.file.path.withCString { chmod($0, 0o600) } == 0)

        let symlink = fixture.directory.appendingPathComponent("linked.chk")
        try FileManager.default.createSymbolicLink(
            at: symlink,
            withDestinationURL: fixture.file
        )
        let symlinkReader = SequenceCheckpointCoordinator(checkpointURL: symlink)
        guard case .rejected(let symlinkDetail) = await symlinkReader.restore(
            into: SequenceEngine(lineage: ProcessLineage())
        ) else {
            Issue.record("symlink checkpoint unexpectedly accepted")
            return
        }
        #expect(symlinkDetail.contains("symlink") || symlinkDetail.contains("carrier"))
    }

    @Test("unchanged semantic state does not replace or rewrite the checkpoint")
    func unchangedStateSkipsRewrite() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        _ = await engine.evaluate(event("/usr/bin/curl", pid: 505, timestamp: base))
        let coordinator = SequenceCheckpointCoordinator(checkpointURL: fixture.file)

        guard case .written = await coordinator.forceFlush(engine: engine, now: base) else {
            Issue.record("initial checkpoint was not written")
            return
        }
        let firstInode = try inode(of: fixture.file)
        let second = await coordinator.forceFlush(
            engine: engine,
            now: base.addingTimeInterval(10)
        )
        #expect(second == .unchanged)
        #expect(try inode(of: fixture.file) == firstInode)
        let telemetry = await coordinator.telemetry(now: base.addingTimeInterval(10))
        #expect(telemetry.unchangedSkipsTotal == 1)
        #expect(!telemetry.dirty)
    }

    @Test("graceful flush bypasses cadence and captures the newest generation")
    func gracefulFlushBypassesCadence() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()
        let policy = SequenceCheckpointPolicy(cadence: 3_600)
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        _ = await engine.evaluate(event("/usr/bin/curl", pid: 601, timestamp: base))
        let coordinator = SequenceCheckpointCoordinator(
            checkpointURL: fixture.file,
            policy: policy
        )
        guard case .written = await coordinator.checkpointIfDue(engine: engine, now: base) else {
            Issue.record("initial periodic checkpoint was not written")
            return
        }

        _ = await engine.evaluate(
            event("/usr/bin/curl", pid: 602, timestamp: base.addingTimeInterval(1))
        )
        let dirtyBeforeFlush = await coordinator.telemetry(
            engine: engine,
            now: base.addingTimeInterval(2)
        )
        #expect(dirtyBeforeFlush.dirty)
        #expect(dirtyBeforeFlush.currentSemanticDigest == nil)
        #expect(await coordinator.checkpointIfDue(
            engine: engine,
            now: base.addingTimeInterval(2)
        ) == .notDue)
        guard case .written = await coordinator.forceFlush(
            engine: engine,
            now: base.addingTimeInterval(3)
        ) else {
            Issue.record("forced graceful flush did not bypass cadence")
            return
        }

        let restarted = SequenceEngine(lineage: ProcessLineage())
        try await restarted.addRule(rule())
        let reader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        #expect(await reader.restore(
            into: restarted,
            now: base.addingTimeInterval(4)
        ) == .restored(
            partials: 2,
            pendingSteps: 0,
            expiredPartials: 0,
            expiredPendingSteps: 0
        ))
    }

    @Test("write failure remains dirty and is visible in telemetry")
    func failureTelemetry() async throws {
        let missingDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("missing-seq-checkpoint-\(UUID().uuidString)")
        let file = missingDirectory.appendingPathComponent("sequence.chk")
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        _ = await engine.evaluate(event("/usr/bin/curl", pid: 707, timestamp: Date()))
        let coordinator = SequenceCheckpointCoordinator(checkpointURL: file)

        guard case .failed(let detail) = await coordinator.forceFlush(engine: engine) else {
            Issue.record("checkpoint into absent parent unexpectedly succeeded")
            return
        }
        #expect(!detail.isEmpty)
        let telemetry = await coordinator.telemetry()
        #expect(telemetry.dirty)
        #expect(telemetry.lastFailure != nil)
        #expect(telemetry.lastFailureAt != nil)
        #expect(telemetry.writesTotal == 0)
    }

    @Test("invalid identities and step membership reject before atomic restore")
    func adversarialPayloadValidation() async throws {
        let base = Date()
        let source = SequenceEngine(lineage: ProcessLineage())
        try await source.addRule(rule())
        _ = await source.evaluate(event("/usr/bin/curl", pid: 808, timestamp: base))
        let prepared = try SequenceCheckpointCodec.prepare(
            try await source.checkpointCapture(at: base.addingTimeInterval(0.1))
        )
        let original = prepared.payload
        guard let bucket = original.partialBuckets.first,
              let partial = bucket.partials.first,
              let matched = partial.matchedSteps.first else {
            Issue.record("test precondition: one persisted partial")
            return
        }

        let unknownMatched = SequenceCheckpointMatchedStep(
            stepID: "removed-step",
            eventID: matched.eventID,
            timestamp: matched.timestamp,
            processPID: matched.processPID,
            processParentPID: matched.processParentPID,
            processParentWasTracked: matched.processParentWasTracked,
            processAncestorPIDs: matched.processAncestorPIDs,
            filePath: matched.filePath,
            networkDestination: matched.networkDestination
        )
        let invalidPartial = SequenceCheckpointPartial(
            id: partial.id,
            ruleID: partial.ruleID,
            createdAt: partial.createdAt,
            matchedSteps: [unknownMatched],
            correlationKey: partial.correlationKey
        )
        let unknownStepPayload = SequenceCheckpointPayload(
            schemaVersion: original.schemaVersion,
            capturedAt: original.capturedAt,
            ruleFingerprint: original.ruleFingerprint,
            sourceGeneration: original.sourceGeneration,
            partialBuckets: [SequenceCheckpointPartialBucket(
                ruleID: bucket.ruleID,
                partials: [invalidPartial]
            )],
            pendingBuckets: original.pendingBuckets,
            evictionOrder: [partial.id],
            pendingEvictionOrder: original.pendingEvictionOrder
        )

        let unknownStepTarget = SequenceEngine(lineage: ProcessLineage())
        try await unknownStepTarget.addRule(rule())
        await #expect(throws: SequenceCheckpointError.self) {
            _ = try await unknownStepTarget.restoreCheckpoint(
                unknownStepPayload,
                now: base.addingTimeInterval(1)
            )
        }
        #expect(await unknownStepTarget.activePartialMatchCount == 0)

        let duplicateEvictionPayload = SequenceCheckpointPayload(
            schemaVersion: original.schemaVersion,
            capturedAt: original.capturedAt,
            ruleFingerprint: original.ruleFingerprint,
            sourceGeneration: original.sourceGeneration,
            partialBuckets: original.partialBuckets,
            pendingBuckets: original.pendingBuckets,
            evictionOrder: [partial.id, partial.id],
            pendingEvictionOrder: original.pendingEvictionOrder
        )
        let duplicateTarget = SequenceEngine(lineage: ProcessLineage())
        try await duplicateTarget.addRule(rule())
        await #expect(throws: SequenceCheckpointError.self) {
            _ = try await duplicateTarget.restoreCheckpoint(
                duplicateEvictionPayload,
                now: base.addingTimeInterval(1)
            )
        }

        let futureMatched = SequenceCheckpointMatchedStep(
            stepID: matched.stepID,
            eventID: matched.eventID,
            timestamp: base.addingTimeInterval(
                SequenceCheckpointLimits.futureTimestampTolerance + 10
            ),
            processPID: matched.processPID,
            processParentPID: matched.processParentPID,
            processParentWasTracked: matched.processParentWasTracked,
            processAncestorPIDs: matched.processAncestorPIDs,
            filePath: matched.filePath,
            networkDestination: matched.networkDestination
        )
        let futurePayload = SequenceCheckpointPayload(
            schemaVersion: original.schemaVersion,
            capturedAt: original.capturedAt,
            ruleFingerprint: original.ruleFingerprint,
            sourceGeneration: original.sourceGeneration,
            partialBuckets: [SequenceCheckpointPartialBucket(
                ruleID: bucket.ruleID,
                partials: [SequenceCheckpointPartial(
                    id: partial.id,
                    ruleID: partial.ruleID,
                    createdAt: partial.createdAt,
                    matchedSteps: [futureMatched],
                    correlationKey: partial.correlationKey
                )]
            )],
            pendingBuckets: [],
            evictionOrder: [partial.id],
            pendingEvictionOrder: []
        )
        let futureTarget = SequenceEngine(lineage: ProcessLineage())
        try await futureTarget.addRule(rule())
        await #expect(throws: SequenceCheckpointError.self) {
            _ = try await futureTarget.restoreCheckpoint(
                futurePayload,
                now: base
            )
        }

        let laterStep = rule().steps[1]
        let overCapPending = (0...SequenceEngine.maxPendingPerRule).map { index in
            SequenceCheckpointPendingStep(
                ruleID: original.partialBuckets[0].ruleID,
                stepID: laterStep.id,
                matched: SequenceCheckpointMatchedStep(
                    stepID: laterStep.id,
                    eventID: UUID(),
                    timestamp: base,
                    processPID: Int32(index + 1),
                    processParentPID: 0,
                    processParentWasTracked: false,
                    processAncestorPIDs: [],
                    filePath: nil,
                    networkDestination: nil
                ),
                arrivedAt: base
            )
        }
        let pendingCapPayload = SequenceCheckpointPayload(
            schemaVersion: original.schemaVersion,
            capturedAt: original.capturedAt,
            ruleFingerprint: original.ruleFingerprint,
            sourceGeneration: original.sourceGeneration,
            partialBuckets: [],
            pendingBuckets: [SequenceCheckpointPendingBucket(
                ruleID: bucket.ruleID,
                steps: overCapPending
            )],
            evictionOrder: [],
            pendingEvictionOrder: overCapPending.map {
                SequenceCheckpointPendingIdentity(
                    ruleID: $0.ruleID,
                    stepID: $0.stepID,
                    eventID: $0.matched.eventID
                )
            }
        )
        let pendingCapTarget = SequenceEngine(lineage: ProcessLineage())
        try await pendingCapTarget.addRule(rule())
        await #expect(throws: SequenceCheckpointError.self) {
            _ = try await pendingCapTarget.restoreCheckpoint(
                pendingCapPayload,
                now: base.addingTimeInterval(1)
            )
        }

        let secondPartialID = UUID()
        let secondMatched = SequenceCheckpointMatchedStep(
            stepID: matched.stepID,
            eventID: UUID(),
            timestamp: matched.timestamp,
            processPID: matched.processPID + 1,
            processParentPID: matched.processParentPID,
            processParentWasTracked: matched.processParentWasTracked,
            processAncestorPIDs: matched.processAncestorPIDs,
            filePath: matched.filePath,
            networkDestination: matched.networkDestination
        )
        let overGlobalCapPayload = SequenceCheckpointPayload(
            schemaVersion: original.schemaVersion,
            capturedAt: original.capturedAt,
            ruleFingerprint: original.ruleFingerprint,
            sourceGeneration: original.sourceGeneration,
            partialBuckets: [SequenceCheckpointPartialBucket(
                ruleID: bucket.ruleID,
                partials: bucket.partials + [SequenceCheckpointPartial(
                    id: secondPartialID,
                    ruleID: bucket.ruleID,
                    createdAt: partial.createdAt,
                    matchedSteps: [secondMatched],
                    correlationKey: String(secondMatched.processPID)
                )]
            )],
            pendingBuckets: [],
            evictionOrder: [partial.id, secondPartialID],
            pendingEvictionOrder: []
        )
        let globalCapTarget = SequenceEngine(
            lineage: ProcessLineage(),
            maxPartialMatches: 1
        )
        try await globalCapTarget.addRule(rule())
        await #expect(throws: SequenceCheckpointError.self) {
            _ = try await globalCapTarget.restoreCheckpoint(
                overGlobalCapPayload,
                now: base.addingTimeInterval(1)
            )
        }

        let wrongSchema = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion + 1,
            capturedAt: original.capturedAt,
            ruleFingerprint: original.ruleFingerprint,
            sourceGeneration: original.sourceGeneration,
            partialBuckets: original.partialBuckets,
            pendingBuckets: original.pendingBuckets,
            evictionOrder: original.evictionOrder,
            pendingEvictionOrder: original.pendingEvictionOrder
        )
        let schemaTarget = SequenceEngine(lineage: ProcessLineage())
        try await schemaTarget.addRule(rule())
        await #expect(throws: SequenceCheckpointError.self) {
            _ = try await schemaTarget.restoreCheckpoint(
                wrongSchema,
                now: base.addingTimeInterval(1)
            )
        }
    }

    @Test("10,000-partial checkpoint stays inside file and hourly write budgets")
    func stateAtCapSizeAndWriteRate() async throws {
        let base = Date()
        let activeRule = rule(window: 3_600)
        let partials: [SequenceCheckpointPartial] = (0..<10_000).map { index in
            let partialID = UUID()
            return SequenceCheckpointPartial(
                id: partialID,
                ruleID: activeRule.id,
                createdAt: base.addingTimeInterval(Double(index) / 100_000),
                matchedSteps: [SequenceCheckpointMatchedStep(
                    stepID: "download",
                    eventID: UUID(),
                    timestamp: base,
                    processPID: Int32(index + 1),
                    processParentPID: 0,
                    processParentWasTracked: false,
                    processAncestorPIDs: [],
                    filePath: nil,
                    networkDestination: nil
                )],
                correlationKey: String(index + 1)
            )
        }
        let capture = SequenceCheckpointCapture(
            capturedAt: base.addingTimeInterval(1),
            sourceGeneration: 10_000,
            rules: [activeRule],
            partialBuckets: [SequenceCheckpointPartialBucket(
                ruleID: activeRule.id,
                partials: partials
            )],
            pendingBuckets: [],
            evictionOrder: partials.map(\.id),
            pendingEvictionOrder: []
        )
        let prepared = try SequenceCheckpointCodec.prepare(capture)
        #expect(prepared.encodedFile.count <= SequenceCheckpointCodec.maximumFileBytes)

        let policy = SequenceCheckpointPolicy()
        let maximumHourlyRateAtCadence = prepared.encodedFile.count
            * Int(3_600 / policy.cadence)
        #expect(maximumHourlyRateAtCadence <= policy.maximumPeriodicBytesPerHour,
                "cap-state checkpoint would consume \(maximumHourlyRateAtCadence) bytes/hour")

        let target = SequenceEngine(
            lineage: ProcessLineage(),
            maxPartialMatches: 10_000
        )
        try await target.addRule(activeRule)
        let restored = try await target.restoreCheckpoint(
            prepared.payload,
            now: base.addingTimeInterval(2)
        )
        #expect(restored.partialCount == 10_000)
        #expect(await target.activePartialMatchCount == 10_000)
        let clock = ContinuousClock()
        let diagnosticsStarted = clock.now
        let weight = await target.checkpointWeightDiagnostics()
        let diagnosticsElapsed = diagnosticsStarted.duration(to: clock.now)
        #expect(weight.cachedWeight == weight.recomputedWeight)
        #expect(weight.partialCount == 10_000)
        #expect(diagnosticsElapsed < .milliseconds(250),
                "30-second heartbeat diagnostic took \(diagnosticsElapsed) at the live cap")
        let diagnostics = await target.evictionQueueDiagnostics()
        #expect(diagnostics.referenceCount == 10_000)
        #expect(diagnostics.referencesMatchLivePartials)
    }

    @Test("LZFSE framing accepts bounded streams and rejects trailing expansion")
    func streamingLZFSEIsExactAndBounded() throws {
        // Exercise both highly-compressible and incompressible carrier shapes;
        // Apple's encoder may choose LZFSE, LZVN, or raw blocks by input shape.
        let legitimatePayloads = [
            Data(repeating: 0x41, count: 64 * 1_024),
            deterministicBytes(count: 1_200_000, seed: 0x5eed),
        ]
        for payload in legitimatePayloads {
            let encoded = try lzfse(payload)
            #expect(encoded.count <= payload.count + 1_024 * 1_024)
            #expect(try SequenceCheckpointCodec.decompressLZFSE(
                encoded,
                exactOutputBytes: payload.count
            ) == payload)
        }

        let prefix = legitimatePayloads[1]
        let compressedPrefix = try lzfse(prefix)

        // A second valid stream is an adversarial suffix: a one-shot decoder
        // and Apple's streaming API both return the declared prefix while
        // silently accepting/consuming this second high-expansion stream.
        let expansion = Data(repeating: 0x41, count: 4 * 1_024 * 1_024)
        var concatenated = compressedPrefix
        concatenated.append(try lzfse(expansion))
        #expect(throws: SequenceCheckpointError.self) {
            _ = try SequenceCheckpointCodec.decompressLZFSE(
                concatenated,
                exactOutputBytes: prefix.count
            )
        }

        var trailingByte = compressedPrefix
        trailingByte.append(0)
        #expect(throws: SequenceCheckpointError.self) {
            _ = try SequenceCheckpointCodec.decompressLZFSE(
                trailingByte,
                exactOutputBytes: prefix.count
            )
        }

        #expect(throws: SequenceCheckpointError.self) {
            _ = try SequenceCheckpointCodec.decompressLZFSE(
                Data(compressedPrefix.dropLast()),
                exactOutputBytes: prefix.count
            )
        }
        #expect(throws: SequenceCheckpointError.self) {
            _ = try SequenceCheckpointCodec.decompressLZFSE(
                compressedPrefix,
                exactOutputBytes: prefix.count - 1
            )
        }
        #expect(throws: SequenceCheckpointError.self) {
            _ = try SequenceCheckpointCodec.decompressLZFSE(
                compressedPrefix,
                exactOutputBytes: prefix.count + 1
            )
        }
    }

    @Test("empty rule corpus has a valid deterministic round trip")
    func emptyRuleCorpusRoundTrip() async throws {
        let engine = SequenceEngine(lineage: ProcessLineage())
        let capture = try await engine.checkpointCapture()
        let prepared = try SequenceCheckpointCodec.prepare(capture)
        let decoded = try SequenceCheckpointCodec.decode(prepared.encodedFile)
        #expect(decoded.partialBuckets.isEmpty)
        #expect(decoded.pendingBuckets.isEmpty)

        let restarted = SequenceEngine(lineage: ProcessLineage())
        let applied = try await restarted.restoreCheckpoint(decoded)
        #expect(applied.partialCount == 0)
        #expect(applied.pendingCount == 0)
    }

    @Test("even a non-matching event permanently closes the startup restore gate")
    func lateRestoreAfterMissIsRefused() async throws {
        let source = SequenceEngine(lineage: ProcessLineage())
        try await source.addRule(rule())
        let payload = try SequenceCheckpointCodec.prepare(
            try await source.checkpointCapture()
        ).payload

        let target = SequenceEngine(lineage: ProcessLineage())
        try await target.addRule(rule())
        let misses = await target.evaluate(event(
            "/usr/bin/true",
            pid: 9001,
            timestamp: Date()
        ))
        #expect(misses.isEmpty)
        await #expect(throws: SequenceCheckpointError.self) {
            _ = try await target.restoreCheckpoint(payload)
        }
    }

    @Test("unchanged-state validation repairs deleted and corrupted carriers")
    func unchangedCarrierInvalidationRepairsImmediately() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        _ = await engine.evaluate(event("/usr/bin/curl", pid: 9101, timestamp: base))
        let coordinator = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .written = await coordinator.forceFlush(engine: engine, now: base) else {
            Issue.record("initial carrier write failed")
            return
        }

        try FileManager.default.removeItem(at: fixture.file)
        guard case .written = await coordinator.forceFlush(
            engine: engine,
            now: base.addingTimeInterval(1)
        ) else {
            Issue.record("deleted unchanged carrier was not repaired")
            return
        }
        var telemetry = await coordinator.telemetry(now: base.addingTimeInterval(1))
        #expect(telemetry.carrierInvalidationsTotal == 1)
        #expect(telemetry.lastCarrierInvalidationReason == .missing)
        #expect(telemetry.durableCarrierValid)
        #expect(telemetry.crashRPOBoundCurrentlyMaintained)

        var corrupt = try Data(contentsOf: fixture.file)
        corrupt[20] ^= 0xff // digest byte; body remains a valid envelope/payload
        try SecureFileIO.atomicReplace(at: fixture.file.path, data: corrupt, mode: 0o600)
        guard case .written = await coordinator.forceFlush(
            engine: engine,
            now: base.addingTimeInterval(2)
        ) else {
            Issue.record("corrupted unchanged carrier was not repaired")
            return
        }
        telemetry = await coordinator.telemetry(now: base.addingTimeInterval(2))
        #expect(telemetry.carrierInvalidationsTotal == 2)
        #expect(telemetry.lastCarrierInvalidationReason == .integrityMismatch)
        #expect(telemetry.durableCarrierValid)
        #expect(try SequenceCheckpointCodec.decode(Data(contentsOf: fixture.file))
            .ruleFingerprint.count == 64)
    }

    @Test("rejected startup carrier becomes recovered without erasing its cause")
    func rejectedCarrierRepairIsObservable() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        try SecureFileIO.atomicReplace(
            at: fixture.file.path,
            data: Data("not-a-checkpoint".utf8),
            mode: 0o600
        )
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        let coordinator = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .rejected = await coordinator.restore(into: engine) else {
            Issue.record("malformed startup carrier was not rejected")
            return
        }
        let rejection = await coordinator.telemetry()
        #expect(rejection.restoreStatus == .rejected)
        #expect(rejection.restoreDetail != nil)

        guard case .written = await coordinator.forceFlush(engine: engine) else {
            Issue.record("rejected carrier was not replaced")
            return
        }
        let repaired = await coordinator.telemetry()
        #expect(repaired.restoreStatus == .recovered)
        #expect(repaired.restoreDetail == rejection.restoreDetail)
        #expect(repaired.carrierInvalidationsTotal == 1)
        #expect(repaired.durableCarrierValid)
        #expect(repaired.lastFailure == nil)
        #expect(repaired.crashRPOBoundCurrentlyMaintained)
    }

    @Test("fresh absent startup writes before returning and establishes the RPO")
    func periodicStartSeedsImmediately() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        let coordinator = SequenceCheckpointCoordinator(
            checkpointURL: fixture.file,
            policy: SequenceCheckpointPolicy(cadence: 3_600)
        )
        #expect(await coordinator.restore(into: engine) == .absent)
        await coordinator.startPeriodicCheckpointing(engine: engine)
        await coordinator.stopPeriodicCheckpointing()

        let telemetry = await coordinator.telemetry(engine: engine)
        #expect(FileManager.default.fileExists(atPath: fixture.file.path))
        #expect(telemetry.restoreStatus == .initialized)
        #expect(telemetry.durableCarrierValid)
        #expect(!telemetry.dirty)
        #expect(telemetry.crashRPOBoundCurrentlyMaintained)
    }

    @Test("cadence and rolling budgets use monotonic time across wall rollback")
    func monotonicCadenceAndBudget() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let base = Date()
        let clock = SequenceTestMonotonicClock(100)
        let policy = SequenceCheckpointPolicy(
            cadence: 1,
            maximumPeriodicWritesPerHour: 1,
            maximumPeriodicBytesPerHour: SequenceCheckpointCodec.maximumFileBytes
        )
        let coordinator = SequenceCheckpointCoordinator(
            checkpointURL: fixture.file,
            policy: policy,
            monotonicNow: { clock.now() }
        )
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        #expect(await coordinator.checkpointIfDue(engine: engine, now: base)
            .isWrittenForSequenceTest)

        _ = await engine.evaluate(event("/usr/bin/curl", pid: 9201, timestamp: base))
        clock.set(100.5)
        #expect(await coordinator.checkpointIfDue(
            engine: engine,
            now: base.addingTimeInterval(-10_000)
        ) == .notDue)
        clock.set(101)
        #expect(await coordinator.checkpointIfDue(engine: engine, now: base) == .budgetDeferred)

        clock.set(3_701)
        #expect(await coordinator.checkpointIfDue(
            engine: engine,
            now: base.addingTimeInterval(-20_000)
        ).isWrittenForSequenceTest)
        let telemetry = await coordinator.telemetry(now: base.addingTimeInterval(-20_000))
        #expect(telemetry.periodicWritesLastHour == 1)
        #expect(telemetry.budgetDeferralsTotal == 1)
    }

    @Test("semantic weight estimate dominates adversarial canonical JSON size")
    func semanticWeightEstimateIsConservative() throws {
        let base = Date()
        let hostile = String(repeating: "\u{0001}\\\"", count: 2_000)
        let matched = SequenceCheckpointMatchedStep(
            stepID: "download",
            eventID: UUID(),
            timestamp: base,
            processPID: 1,
            processParentPID: 0,
            processParentWasTracked: false,
            processAncestorPIDs: Array(2...65).map(Int32.init),
            filePath: hostile,
            networkDestination: hostile
        )
        let partial = SequenceCheckpointPartial(
            id: UUID(),
            ruleID: "rule-\(hostile)",
            createdAt: base,
            matchedSteps: [matched],
            correlationKey: hostile
        )
        let bucket = SequenceCheckpointPartialBucket(
            ruleID: partial.ruleID,
            partials: [partial]
        )
        let payload = SequenceCheckpointPayload(
            schemaVersion: SequenceCheckpointPayload.currentSchemaVersion,
            capturedAt: base,
            ruleFingerprint: String(repeating: "a", count: 64),
            sourceGeneration: 1,
            partialBuckets: [bucket],
            pendingBuckets: [],
            evictionOrder: [partial.id],
            pendingEvictionOrder: []
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let encoded = try encoder.encode(payload)
        let estimate = SequenceCheckpointCodec.estimatedSemanticStateWeight(
            partialBuckets: [bucket],
            pendingBuckets: []
        )
        #expect(encoded.count <= estimate)
    }

    @Test("orphan cleanup is namespace-exact, stale-only, and link-safe")
    func scopedOrphanCleanup() throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let prefix = SequenceCheckpointFileStore.temporaryNamePrefix
        let now = Date()

        func createFile(_ name: String, age: TimeInterval) throws -> URL {
            let url = fixture.directory.appendingPathComponent(name)
            try Data(repeating: 0x5a, count: 128).write(to: url)
            #expect(url.path.withCString { chmod($0, 0o600) } == 0)
            try FileManager.default.setAttributes(
                [.modificationDate: now.addingTimeInterval(-age)],
                ofItemAtPath: url.path
            )
            return url
        }

        let stale = try createFile("\(prefix)\(UUID().uuidString).tmp", age: 600)
        let fresh = try createFile("\(prefix)\(UUID().uuidString).tmp", age: 1)
        let wrongPrefix = try createFile(
            ".maccrab-write-\(UUID().uuidString).tmp",
            age: 600
        )
        let symlinkTarget = try createFile("symlink-target", age: 600)
        let symlink = fixture.directory.appendingPathComponent(
            "\(prefix)\(UUID().uuidString).tmp"
        )
        try FileManager.default.createSymbolicLink(
            at: symlink,
            withDestinationURL: symlinkTarget
        )
        let hardlinkSource = try createFile("hardlink-source", age: 600)
        let hardlink = fixture.directory.appendingPathComponent(
            "\(prefix)\(UUID().uuidString).tmp"
        )
        #expect(hardlinkSource.path.withCString { source in
            hardlink.path.withCString { destination in Darwin.link(source, destination) }
        } == 0)

        let report = try SecureFileIO.cleanupStaleAtomicWriteTemporaries(
            near: fixture.file.path,
            temporaryNamePrefix: prefix,
            olderThan: 300,
            now: now
        )
        #expect(report.removedFiles == 1)
        #expect(report.removedBytes == 128)
        #expect(report.remainingFiles == 1)
        #expect(report.remainingBytes == 128)
        #expect(!report.scanTruncated)
        #expect(!FileManager.default.fileExists(atPath: stale.path))
        #expect(FileManager.default.fileExists(atPath: fresh.path))
        #expect(FileManager.default.fileExists(atPath: wrongPrefix.path))
        #expect(FileManager.default.fileExists(atPath: symlink.path))
        #expect(FileManager.default.fileExists(atPath: hardlink.path))
    }

    @Test("carrier read refuses hard links and symlinked parent components")
    func carrierParentAndHardlinkDefense() async throws {
        let fixture = try temporaryCheckpoint()
        defer { try? FileManager.default.removeItem(at: fixture.directory) }
        let engine = SequenceEngine(lineage: ProcessLineage())
        try await engine.addRule(rule())
        let coordinator = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .written = await coordinator.forceFlush(engine: engine) else {
            Issue.record("carrier precondition write failed")
            return
        }

        let hardlink = fixture.directory.appendingPathComponent("hardlink.chk")
        #expect(fixture.file.path.withCString { source in
            hardlink.path.withCString { destination in Darwin.link(source, destination) }
        } == 0)
        let hardlinkReader = SequenceCheckpointCoordinator(checkpointURL: fixture.file)
        guard case .rejected = await hardlinkReader.restore(
            into: SequenceEngine(lineage: ProcessLineage())
        ) else {
            Issue.record("multi-link carrier was accepted")
            return
        }

        try FileManager.default.removeItem(at: hardlink)
        let realParent = fixture.directory.appendingPathComponent("real-parent")
        try FileManager.default.createDirectory(at: realParent, withIntermediateDirectories: false)
        let realCarrier = realParent.appendingPathComponent("sequence.chk")
        try FileManager.default.copyItem(at: fixture.file, to: realCarrier)
        #expect(realCarrier.path.withCString { chmod($0, 0o600) } == 0)
        let linkedParent = fixture.directory.appendingPathComponent("linked-parent")
        try FileManager.default.createSymbolicLink(
            at: linkedParent,
            withDestinationURL: realParent
        )
        let linkedCarrier = linkedParent.appendingPathComponent("sequence.chk")
        let parentReader = SequenceCheckpointCoordinator(checkpointURL: linkedCarrier)
        guard case .rejected = await parentReader.restore(
            into: SequenceEngine(lineage: ProcessLineage())
        ) else {
            Issue.record("carrier through symlinked parent was accepted")
            return
        }
        let parentReason = (await parentReader.telemetry())
            .lastCarrierInvalidationReason
        #expect(
            parentReason == .unsafeCarrier,
            "symlinked parent mapped to \(String(describing: parentReason))"
        )
    }

    @Test("direct PPID relation evidence survives restart without a live lineage DAG")
    func directParentRelationRestartParity() async throws {
        let base = Date()
        let relationRule = SequenceRule(
            id: "direct-parent-restart",
            title: "direct parent restart",
            description: "direct PPID evidence",
            level: .high,
            tags: [],
            window: 600,
            correlationType: .none,
            ordered: true,
            steps: [
                rule().steps[0],
                SequenceStep(
                    id: "execute",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image",
                        modifier: .endswith,
                        values: ["/payload"],
                        negate: false
                    )],
                    afterStep: "download",
                    processRelation: ProcessRelationSpec(
                        relation: .descendant,
                        relativeToStep: "download"
                    )
                ),
            ],
            trigger: .allSteps
        )
        let source = SequenceEngine(lineage: ProcessLineage())
        try await source.addRule(relationRule)
        _ = await source.evaluate(event("/usr/bin/curl", pid: 10_001, timestamp: base))
        let payload = try SequenceCheckpointCodec.prepare(
            try await source.checkpointCapture(at: base.addingTimeInterval(0.1))
        ).payload

        let restarted = SequenceEngine(lineage: ProcessLineage())
        try await restarted.addRule(relationRule)
        _ = try await restarted.restoreCheckpoint(payload, now: base.addingTimeInterval(0.2))
        let matches = await restarted.evaluate(event(
            "/tmp/payload",
            pid: 10_002,
            timestamp: base.addingTimeInterval(1),
            ppid: 10_001
        ))
        #expect(matches.contains { $0.ruleId == relationRule.id })
    }

    @Test("process-lineage explicit any remains intentionally unconstrained after restart")
    func explicitAnyProcessLineageRestartParity() async throws {
        let base = Date()
        let anyRule = SequenceRule(
            id: "lineage-explicit-any-restart",
            title: "explicit any restart",
            description: "independent tool is permitted",
            level: .high,
            tags: [],
            window: 600,
            correlationType: .processLineage,
            ordered: true,
            steps: [
                rule().steps[0],
                SequenceStep(
                    id: "execute",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image",
                        modifier: .endswith,
                        values: ["/payload"],
                        negate: false
                    )],
                    afterStep: "download",
                    processRelation: ProcessRelationSpec(
                        relation: .any,
                        relativeToStep: "download"
                    )
                ),
            ],
            trigger: .allSteps
        )
        let source = SequenceEngine(lineage: ProcessLineage())
        try await source.addRule(anyRule)
        _ = await source.evaluate(event("/usr/bin/curl", pid: 11_001, timestamp: base))
        let payload = try SequenceCheckpointCodec.prepare(
            try await source.checkpointCapture(at: base.addingTimeInterval(0.1))
        ).payload

        let restarted = SequenceEngine(lineage: ProcessLineage())
        try await restarted.addRule(anyRule)
        _ = try await restarted.restoreCheckpoint(payload, now: base.addingTimeInterval(0.2))
        let matches = await restarted.evaluate(event(
            "/tmp/payload",
            pid: 99_999,
            timestamp: base.addingTimeInterval(1),
            ppid: 88_888
        ))
        #expect(matches.contains { $0.ruleId == anyRule.id })
    }

    @Test("snapshot-only ancestry proof survives restart for an ancestor relation")
    func snapshotOnlyAncestryRestartParity() async throws {
        let base = Date()
        let ancestryRule = SequenceRule(
            id: "snapshot-only-ancestry",
            title: "snapshot ancestry restart",
            description: "persist authoritative lineage proof",
            level: .critical,
            tags: [],
            window: 600,
            correlationType: .none,
            ordered: true,
            steps: [
                rule().steps[0],
                SequenceStep(
                    id: "middle",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image",
                        modifier: .endswith,
                        values: ["/middle"],
                        negate: false
                    )],
                    afterStep: "download",
                    processRelation: ProcessRelationSpec(
                        relation: .descendant,
                        relativeToStep: "download"
                    )
                ),
                SequenceStep(
                    id: "root-returns",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image",
                        modifier: .endswith,
                        values: ["/root"],
                        negate: false
                    )],
                    afterStep: "middle",
                    processRelation: ProcessRelationSpec(
                        relation: .ancestor,
                        relativeToStep: "middle"
                    )
                ),
            ],
            trigger: .allSteps
        )
        let lineage = ProcessLineage(maxAncestorDepth: 1_000)
        await lineage.recordProcess(
            pid: 12_000,
            ppid: 1,
            path: "/tmp/root",
            name: "root",
            startTime: base
        )
        await lineage.recordProcess(
            pid: 12_001,
            ppid: 12_000,
            path: "/usr/bin/curl",
            name: "curl",
            startTime: base
        )
        await lineage.recordProcess(
            pid: 12_002,
            ppid: 12_001,
            path: "/tmp/middle",
            name: "middle",
            startTime: base
        )
        let source = SequenceEngine(lineage: lineage)
        try await source.addRule(ancestryRule)
        _ = await source.evaluate(event(
            "/usr/bin/curl",
            pid: 12_001,
            timestamp: base,
            ppid: 12_000
        ))
        _ = await source.evaluate(event(
            "/tmp/middle",
            pid: 12_002,
            timestamp: base.addingTimeInterval(1),
            ppid: 12_001
        ))
        let payload = try SequenceCheckpointCodec.prepare(
            try await source.checkpointCapture(at: base.addingTimeInterval(1.1))
        ).payload
        #expect(payload.partialBuckets[0].partials[0].matchedSteps
            .first(where: { $0.stepID == "middle" })?
            .processAncestorPIDs.contains(12_000) == true)

        let restarted = SequenceEngine(lineage: ProcessLineage())
        try await restarted.addRule(ancestryRule)
        _ = try await restarted.restoreCheckpoint(payload, now: base.addingTimeInterval(1.2))
        let matches = await restarted.evaluate(event(
            "/tmp/root",
            pid: 12_000,
            timestamp: base.addingTimeInterval(2),
            ppid: 1
        ))
        #expect(matches.contains { $0.ruleId == ancestryRule.id })
    }

    @Test("sibling restart parity requires an observed parent on both sides")
    func siblingRestartRequiresTrackedParents() async throws {
        let base = Date()
        let siblingRule = SequenceRule(
            id: "sibling-restart-proof",
            title: "sibling restart",
            description: "tracked-parent proof",
            level: .high,
            tags: [],
            window: 600,
            correlationType: .none,
            ordered: true,
            steps: [
                rule().steps[0],
                SequenceStep(
                    id: "execute",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(
                        field: "Image",
                        modifier: .endswith,
                        values: ["/payload"],
                        negate: false
                    )],
                    afterStep: "download",
                    processRelation: ProcessRelationSpec(
                        relation: .sibling,
                        relativeToStep: "download"
                    )
                ),
            ],
            trigger: .allSteps
        )

        let trackedLineage = ProcessLineage()
        await trackedLineage.recordProcess(
            pid: 13_000,
            ppid: 1,
            path: "/bin/zsh",
            name: "zsh",
            startTime: base
        )
        await trackedLineage.recordProcess(
            pid: 13_001,
            ppid: 13_000,
            path: "/usr/bin/curl",
            name: "curl",
            startTime: base
        )
        let trackedSource = SequenceEngine(lineage: trackedLineage)
        try await trackedSource.addRule(siblingRule)
        _ = await trackedSource.evaluate(event(
            "/usr/bin/curl",
            pid: 13_001,
            timestamp: base,
            ppid: 13_000
        ))
        let trackedPayload = try SequenceCheckpointCodec.prepare(
            try await trackedSource.checkpointCapture(at: base.addingTimeInterval(0.1))
        ).payload

        let restartedLineage = ProcessLineage()
        await restartedLineage.recordProcess(
            pid: 13_000,
            ppid: 1,
            path: "/bin/zsh",
            name: "zsh",
            startTime: base
        )
        await restartedLineage.recordProcess(
            pid: 13_002,
            ppid: 13_000,
            path: "/tmp/payload",
            name: "payload",
            startTime: base
        )
        let trackedRestart = SequenceEngine(lineage: restartedLineage)
        try await trackedRestart.addRule(siblingRule)
        _ = try await trackedRestart.restoreCheckpoint(
            trackedPayload,
            now: base.addingTimeInterval(0.2)
        )
        let trackedMatches = await trackedRestart.evaluate(event(
            "/tmp/payload",
            pid: 13_002,
            timestamp: base.addingTimeInterval(1),
            ppid: 13_000
        ))
        #expect(trackedMatches.contains { $0.ruleId == siblingRule.id })

        // Equal numeric PPIDs from untracked event metadata are not evidence
        // that the two processes shared an observed parent node.
        let untrackedSource = SequenceEngine(lineage: ProcessLineage())
        try await untrackedSource.addRule(siblingRule)
        _ = await untrackedSource.evaluate(event(
            "/usr/bin/curl",
            pid: 14_001,
            timestamp: base,
            ppid: 14_000
        ))
        let untrackedPayload = try SequenceCheckpointCodec.prepare(
            try await untrackedSource.checkpointCapture(at: base.addingTimeInterval(0.1))
        ).payload
        let untrackedRestart = SequenceEngine(lineage: ProcessLineage())
        try await untrackedRestart.addRule(siblingRule)
        _ = try await untrackedRestart.restoreCheckpoint(
            untrackedPayload,
            now: base.addingTimeInterval(0.2)
        )
        let falseMatches = await untrackedRestart.evaluate(event(
            "/tmp/payload",
            pid: 14_002,
            timestamp: base.addingTimeInterval(1),
            ppid: 14_000
        ))
        #expect(falseMatches.isEmpty)
    }

    @Test("rule admission rejects non-checkpointable dependency shapes")
    func ruleAdmissionGuardsRestoreInvariants() async {
        let engine = SequenceEngine(lineage: ProcessLineage())
        let base = rule()
        let selfDependent = SequenceRule(
            id: "self-dependent",
            title: base.title,
            description: base.description,
            level: base.level,
            tags: base.tags,
            window: base.window,
            correlationType: base.correlationType,
            ordered: true,
            steps: [
                base.steps[0],
                SequenceStep(
                    id: "execute",
                    logsourceCategory: "process_creation",
                    predicates: base.steps[1].predicates,
                    afterStep: "execute"
                ),
            ],
            trigger: .allSteps
        )
        await #expect(throws: (any Error).self) {
            try await engine.addRule(selfDependent)
        }

        let forwardDependent = SequenceRule(
            id: "forward-dependent",
            title: base.title,
            description: base.description,
            level: base.level,
            tags: base.tags,
            window: base.window,
            correlationType: base.correlationType,
            ordered: true,
            steps: [
                SequenceStep(
                    id: "download",
                    logsourceCategory: "process_creation",
                    predicates: base.steps[0].predicates,
                    afterStep: "execute"
                ),
                base.steps[1],
            ],
            trigger: .allSteps
        )
        await #expect(throws: (any Error).self) {
            try await engine.addRule(forwardDependent)
        }

        let oversizedTrigger = SequenceRule(
            id: "oversized-trigger",
            title: base.title,
            description: base.description,
            level: base.level,
            tags: base.tags,
            window: base.window,
            correlationType: base.correlationType,
            ordered: true,
            steps: base.steps,
            trigger: .steps(Array(
                repeating: "download",
                count: SequenceCheckpointLimits.maximumStepsPerRule + 1
            ))
        )
        await #expect(throws: (any Error).self) {
            try await engine.addRule(oversizedTrigger)
        }

        let invalidWindow = SequenceRule(
            id: "invalid-window",
            title: base.title,
            description: base.description,
            level: base.level,
            tags: base.tags,
            window: .infinity,
            correlationType: base.correlationType,
            ordered: true,
            steps: base.steps,
            trigger: .allSteps
        )
        await #expect(throws: (any Error).self) {
            try await engine.addRule(invalidWindow)
        }
    }
}

private extension SequenceCheckpointWriteResult {
    var isWrittenForSequenceTest: Bool {
        if case .written = self { return true }
        return false
    }
}
