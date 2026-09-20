import Foundation
import Testing
@testable import MacCrabCore

@Suite("Alert trigger representation")
struct AlertTriggerRepresentationTests {
    private func event(
        id: UUID = UUID(),
        timestamp: Date = Date(),
        commandLine: String,
        args: [String],
        enrichments: [String: String] = [:]
    ) -> Event {
        Event(
            id: id,
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .creation,
            eventAction: "exec",
            process: ProcessInfo(
                pid: 4_242,
                ppid: 1,
                rpid: 4_242,
                name: "fixture",
                executable: "/usr/bin/fixture",
                commandLine: commandLine,
                args: args,
                workingDirectory: "/private/tmp",
                userId: 501,
                userName: "tester",
                groupId: 20,
                startTime: timestamp,
                ancestors: [],
                architecture: "arm64",
                isPlatformBinary: false,
                envVars: [
                    "PATH": "/usr/bin",
                    "SESSION_TOKEN": "must-never-survive",
                    "SUDO_COMMAND": commandLine,
                ]
            ),
            enrichments: enrichments,
            severity: .high
        )
    }

    private func admission(
        for event: Event,
        generation: UInt64
    ) throws -> EventJournalAdmission {
        let prepared = try EventJournalAdmissionValidator.prepare(event)
        return EventJournalAdmission(
            eventID: event.id,
            generation: generation,
            canonicalSHA256: prepared.canonicalSHA256,
            canonicalByteCount: prepared.canonicalJSON.count
        )
    }

    @Test("one deterministic sanitized value feeds snapshot and evidence")
    func sharedSanitizedValue() throws {
        let secret = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890" // secret-scan:allow — synthetic redaction fixture.
        let source = event(
            commandLine: "/usr/bin/fixture --api-key=\(secret)",
            args: ["/usr/bin/fixture", "--api-key=\(secret)"],
            enrichments: [
                "authorization": "Bearer \(secret)",
                "detail": "request used \(secret)",
            ]
        )

        let first = EventSnapshot.prepare(source)
        let second = EventSnapshot.prepare(source)
        let canonical = try EventPrivacySanitizer.sanitize(source)
        #expect(first == second)
        #expect(first.disposition == .complete)
        #expect(first.snapshotJSON.utf8.count
            <= EventSnapshot.maximumSnapshotBytes)
        let raw = try #require(first.eventJSON)
        #expect(raw.utf8.count <= EventSnapshot.maxBytesPerEvent)
        #expect(!raw.contains(secret))
        #expect(!first.snapshotJSON.contains(secret))
        #expect(raw.contains("REDACTED"))
        #expect(first.evidenceCandidate?.rawJSON == raw)
        #expect(first.snapshotJSON == "[" + raw + "]")
        #expect(raw == String(decoding: canonical.canonicalJSON, as: UTF8.self))
        #expect(!canonical.event.process.args.joined().contains(secret))
        #expect(!canonical.event.process.envVars!["SUDO_COMMAND"]!.contains(secret))

        let decoded = try JSONDecoder().decode(
            Event.self,
            from: Data(raw.utf8)
        )
        #expect(decoded.id == source.id)
        #expect(decoded.process.envVars?["SESSION_TOKEN"] == "[REDACTED]")
    }

    @Test("at-rest sanitizing preserves forensic network and opaque evidence")
    func preservesForensicValues() throws {
        let timestamp = Date(timeIntervalSince1970: 1_777_777_777)
        let ipv4 = "192.168.44.9"
        let ipv6 = "fd12:3456:789a::7"
        let host = "MacBook-Pro.local"
        let sha256 = String(repeating: "ab", count: 32)
        let opaqueEvidence = String(repeating: "QWxhZGRpbjpvcGVuIHNlc2FtZQ", count: 8)
        let anthropicKey = "sk-ant-api03-" + String(repeating: "a", count: 32)
        let openAIKey = "sk-proj-" + String(repeating: "b", count: 32)
        let slackToken = "xoxb-" + String(repeating: "C", count: 24)
        let source = Event(
            timestamp: timestamp,
            eventCategory: .network,
            eventType: .connection,
            eventAction: "connect",
            process: ProcessInfo(
                pid: 4_242,
                ppid: 1,
                rpid: 4_242,
                name: "fixture",
                executable: "/private/tmp/opaque-sample",
                commandLine: "/private/tmp/opaque-sample --token actual-secret-token",
                args: ["/private/tmp/opaque-sample", opaqueEvidence],
                workingDirectory: "/private/tmp",
                userId: 501,
                userName: "tester",
                groupId: 20,
                startTime: timestamp,
                ancestors: [],
                architecture: "arm64",
                isPlatformBinary: false,
                envVars: ["SUDO_COMMAND": "curl --password actual-secret-token"]
            ),
            network: NetworkInfo(
                sourceIp: ipv6,
                sourcePort: 52_001,
                destinationIp: ipv4,
                destinationPort: 443,
                destinationHostname: host,
                direction: .outbound,
                transport: "tcp"
            ),
            enrichments: [
                "malware_sha256": sha256,
                "opaque_evidence": opaqueEvidence,
                "operator_note": "leaks \(anthropicKey) \(openAIKey) \(slackToken)",
                "credential": "actual-secret-token",
            ],
            severity: .high
        )

        let prepared = try EventPrivacySanitizer.sanitize(source)
        let json = String(decoding: prepared.canonicalJSON, as: UTF8.self)

        #expect(prepared.event.network?.sourceIp == ipv6)
        #expect(prepared.event.network?.destinationIp == ipv4)
        #expect(prepared.event.network?.destinationHostname == host)
        #expect(prepared.event.enrichments["malware_sha256"] == sha256)
        #expect(prepared.event.enrichments["opaque_evidence"] == opaqueEvidence)
        #expect(prepared.event.process.args.contains(opaqueEvidence))
        #expect(prepared.event.enrichments["credential"] == "[REDACTED]")
        #expect(!json.contains("actual-secret-token"))
        #expect(!json.contains(anthropicKey))
        #expect(!json.contains(openAIKey))
        #expect(!json.contains(slackToken))
        #expect(json.contains("ANTHROPIC_KEY"))
        #expect(json.contains("OPENAI_KEY"))
        #expect(json.contains("SLACK_TOKEN"))
    }

    @Test("argv sequencing redacts separate, equals, short, and repeated flags")
    func argvSequenceCredentialRedaction() throws {
        let source = event(
            commandLine: "/usr/bin/fixture --benign different-capture",
            args: [
                "/usr/bin/fixture",
                "safe-before",
                "--password", "plaincredential",
                "safe-middle",
                "--token=equals-value",
                "-p", "short-value",
                "--secret", "--token", "repeated-value",
                "--",
                "--password", "after-end-of-options",
                "safe-after",
            ]
        )

        let args = try EventPrivacySanitizer.sanitize(source).event.process.args
        #expect(args[1] == "safe-before")
        #expect(args[2] == "--password" && args[3] == "[REDACTED]")
        #expect(args[4] == "safe-middle")
        #expect(args[5] == "--token=[REDACTED]")
        #expect(args[6] == "-p" && args[7] == "[REDACTED]")
        #expect(args[8] == "--secret")
        #expect(args[9] == "--token" && args[10] == "[REDACTED]")
        #expect(args[11] == "--")
        #expect(args[12] == "--password")
        #expect(args[13] == "after-end-of-options")
        #expect(args[14] == "safe-after")
    }

    @Test("argv sequencing redacts alphabetic compact MySQL passwords")
    func compactArgvPasswordRedaction() throws {
        let source = event(
            commandLine: "/usr/bin/fixture --benign different-capture",
            args: [
                "/usr/bin/mysql",
                "safe-before",
                "-phuntertwo",
                "safe-after",
                "--",
                "-ppositional-is-not-an-option",
            ]
        )

        let args = try EventPrivacySanitizer.sanitize(source).event.process.args
        #expect(args[1] == "safe-before")
        #expect(args[2] == "-p[REDACTED]")
        #expect(args[3] == "safe-after")
        #expect(args[4] == "--")
        #expect(args[5] == "-ppositional-is-not-an-option")
    }

    @Test("an oversized current trigger compacts to a valid Event under 64 KiB")
    func oversizedTriggerCompacts() throws {
        let secret = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ123456" // secret-scan:allow — synthetic redaction fixture.
        let huge = String(repeating: "payload-\(secret)-", count: 2_000)
        let source = event(
            commandLine: "/usr/bin/fixture --token \(secret) \(huge)",
            args: Array(repeating: huge, count: 4),
            enrichments: Dictionary(uniqueKeysWithValues: (0..<20).map {
                ("detail_\($0)", huge)
            })
        )

        let prepared = EventSnapshot.prepare(source)
        #expect(prepared.disposition == .compacted)
        #expect(prepared.disposition != .poison)
        #expect(prepared.snapshotJSON.utf8.count
            <= EventSnapshot.maximumSnapshotBytes)
        let raw = try #require(prepared.eventJSON)
        #expect(raw.utf8.count <= AlertEvidencePolicy.maximumRawPayloadBytes)
        #expect(!raw.contains(secret))
        let decoded = try JSONDecoder().decode(
            Event.self,
            from: Data(raw.utf8)
        )
        #expect(decoded.id == source.id)
        #expect(decoded.timestamp == source.timestamp)
        #expect(prepared.evidenceCandidate?.rawJSON == raw)
    }

    @Test("oversized detection still commits a trigger with explicit journal gap")
    func oversizedDetectionIsNotBypassed() async throws {
        actor EnsureProbe {
            var calls = 0
            func called() { calls += 1 }
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-oversized-detect-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let probe = EnsureProbe()
        let huge = String(repeating: "detect-me-", count: 1_400_000)
        let trigger = event(
            commandLine: "/usr/bin/fixture suspicious",
            args: ["/usr/bin/fixture", "suspicious"],
            enrichments: ["detector_evidence": huge]
        )
        let journalPreparation = try EventJournalAdmissionValidator.prepare(
            trigger
        )
        #expect(journalPreparation.overflow != nil)
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            journalEventEnsurer: { _ in
                await probe.called()
                return .verified
            }
        )
        let alert = Alert(
            id: "oversized-still-detected",
            timestamp: trigger.timestamp,
            ruleId: "test.oversized-detection",
            ruleTitle: "Oversized detection survives",
            severity: .critical,
            eventId: trigger.id.uuidString
        )

        let inserted = try await EventJournalAdmissionContext
            .withForcedNonverifiedStatus(.poisoned) {
                try await sink.submit(alert: alert, event: trigger)
            }
        #expect(inserted)
        #expect(await probe.calls == 0,
                "forced poison must not be relabeled by a universal ensure")
        let rows = try await store.alerts(since: .distantPast, limit: 10)
        let stored = try #require(rows.first)
        let snapshot = try #require(stored.triggeringEventsJson)
        #expect(snapshot.utf8.count <= EventSnapshot.maximumSnapshotBytes)
        #expect(snapshot.contains("journalContext"))
        #expect(snapshot.contains("poisoned"))
        #expect((await sink.triggerSnapshotStats()).journalContextGapTotal == 1)
    }

    @Test("the journal receipt is identity-bound and settled before alert commit")
    func identityBoundPrecommitBarrier() async throws {
        actor Probe {
            var countSeenAtBarrier: Int?
            func record(_ count: Int?) { countSeenAtBarrier = count }
        }

        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-trigger-barrier-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let probe = Probe()
        let trigger = event(commandLine: "/usr/bin/fixture", args: [])
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            journalAdmissionVerifier: { receipt in
                #expect(receipt.eventID == trigger.id)
                #expect(receipt.generation == 17)
                await probe.record(try? await store.count())
                return .verified
            }
        )
        let alert = Alert(
            id: "precommit-order",
            timestamp: trigger.timestamp,
            ruleId: "test.precommit-order",
            ruleTitle: "Precommit ordering",
            severity: .high,
            eventId: trigger.id.uuidString
        )

        #expect(try await sink.submit(
            alert: alert,
            event: trigger,
            journalAdmission: try admission(for: trigger, generation: 17)
        ))
        #expect(await probe.countSeenAtBarrier == 0)
        #expect(try await store.count() == 1)
        let telemetry = await sink.triggerSnapshotStats()
        #expect(telemetry.completeTotal == 1)
        #expect(telemetry.poisonTotal == 0)
        #expect(telemetry.missingJournalAdmissionTotal == 0)
        #expect(telemetry.mismatchedJournalAdmissionTotal == 0)
    }

    @Test("a mismatched receipt never authorizes a journal barrier")
    func mismatchedAdmission() async throws {
        actor Calls {
            var value = 0
            func increment() { value += 1 }
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-trigger-mismatch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let calls = Calls()
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            journalAdmissionVerifier: { _ in
                await calls.increment()
                return .verified
            }
        )
        let trigger = event(commandLine: "/usr/bin/fixture", args: [])
        let alert = Alert(
            id: "mismatched-receipt",
            timestamp: trigger.timestamp,
            ruleId: "test.mismatch",
            ruleTitle: "Mismatch",
            severity: .medium,
            eventId: trigger.id.uuidString
        )
        #expect(try await sink.submit(
            alert: alert,
            event: trigger,
            journalAdmission: EventJournalAdmission(
                eventID: UUID(),
                generation: 9,
                canonicalSHA256: try EventJournalAdmissionValidator
                    .prepare(trigger).canonicalSHA256,
                canonicalByteCount: try EventJournalAdmissionValidator
                    .prepare(trigger).canonicalJSON.count
            )
        ))
        #expect(await calls.value == 0)
        #expect((await sink.triggerSnapshotStats())
            .mismatchedJournalAdmissionTotal == 1)
    }

    @Test("child work inherits the EventLoop admission receipt")
    func taskLocalAdmissionInheritance() async throws {
        actor Probe {
            var receipts: [EventJournalAdmission] = []
            func append(_ receipt: EventJournalAdmission) {
                receipts.append(receipt)
            }
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-trigger-task-local-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let probe = Probe()
        let trigger = event(commandLine: "/usr/bin/fixture", args: [])
        let receipt = try admission(for: trigger, generation: 23)
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            journalAdmissionVerifier: {
                await probe.append($0)
                return .verified
            }
        )
        let alert = Alert(
            id: "task-local-receipt",
            timestamp: trigger.timestamp,
            ruleId: "test.task-local-receipt",
            ruleTitle: "Task-local receipt",
            severity: .high,
            eventId: trigger.id.uuidString
        )

        let inserted = try await EventJournalAdmissionContext
            .withAdmission(receipt) {
                try await Task {
                    try await sink.submit(alert: alert, event: trigger)
                }.value
            }
        #expect(inserted)
        #expect(await probe.receipts == [receipt])
        #expect((await sink.triggerSnapshotStats())
            .missingJournalAdmissionTotal == 0)
    }

    @Test("outside producers use the universal exact-admission path")
    func universalAdmissionForOutsideProducer() async throws {
        actor Probe {
            var eventIDs: [UUID] = []
            func append(_ id: UUID) { eventIDs.append(id) }
        }
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-trigger-universal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let probe = Probe()
        let trigger = event(commandLine: "/usr/bin/outside", args: [])
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 60),
            journalEventEnsurer: { event in
                await probe.append(event.id)
                return .verified
            }
        )
        let alert = Alert(
            id: "outside-producer",
            timestamp: trigger.timestamp,
            ruleId: "test.outside-producer",
            ruleTitle: "Outside producer",
            severity: .medium,
            eventId: trigger.id.uuidString
        )

        #expect(try await sink.submit(alert: alert, event: trigger))
        #expect(await probe.eventIDs == [trigger.id])
        let telemetry = await sink.triggerSnapshotStats()
        #expect(telemetry.journalContextGapTotal == 0)
        #expect(telemetry.missingJournalAdmissionTotal == 0)
    }

    @Test("every non-durable receipt outcome is explicit on the alert")
    func nonDurableReceiptOutcomes() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-trigger-outcomes-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let outcomes: [EventJournalContextStatus] = [
            .filtered, .dropped, .failed, .timedOut, .prefixIncomplete,
        ]
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 0),
            journalAdmissionVerifier: { receipt in
                outcomes[Int(receipt.generation - 1)]
            }
        )

        for (index, outcome) in outcomes.enumerated() {
            let trigger = event(
                timestamp: Date(timeIntervalSince1970: Double(50_000 + index)),
                commandLine: "/usr/bin/fixture",
                args: []
            )
            let id = "receipt-outcome-\(index)"
            #expect(try await sink.submit(
                alert: Alert(
                    id: id,
                    timestamp: trigger.timestamp,
                    ruleId: "test.receipt-outcome.\(index)",
                    ruleTitle: "Receipt outcome",
                    severity: .medium,
                    eventId: trigger.id.uuidString
                ),
                event: trigger,
                journalAdmission: try admission(
                    for: trigger,
                    generation: UInt64(index + 1)
                )
            ))
            let stored = try #require(await store.alert(id: id))
            let snapshot = try #require(stored.triggeringEventsJson)
            #expect(snapshot.contains(#""journalContext":"gap""#))
            #expect(snapshot.contains(#""status":"\#(outcome.rawValue)""#))
        }
        let telemetry = await sink.triggerSnapshotStats()
        #expect(telemetry.journalContextGapTotal == UInt64(outcomes.count))
        #expect(await sink.evidenceStats().prefixBarrierTimeouts == 2)
    }

    @Test("journal admission gaps stay durable when exact context is complete")
    func journalAdmissionGapSurvivesRestart() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "maccrab-trigger-durable-gap-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        let events = try EventStore(directory: directory.path)
        let alerts = try AlertStore(directory: directory.path)
        let triggerTime = Date(timeIntervalSince1970: 60_000)
        let base = event(
            timestamp: triggerTime,
            commandLine: "/usr/bin/fixture base",
            args: ["/usr/bin/fixture", "base"]
        )
        try await events.insert(event: base)
        let exactBefore = try await events.exactAlertEvidenceSnapshot(
            alertTimestamp: triggerTime
        )
        #expect(exactBefore.isComplete)
        #expect(exactBefore.mutationGeneration > 0)

        var trigger = base
        trigger.enrichments["reviewed"] = "true"
        trigger.severity = .critical
        let sink = AlertSink(
            alertStore: alerts,
            deduplicator: AlertDeduplicator(suppressionWindow: 0),
            eventStore: events,
            journalAdmissionVerifier: { _ in .verified }
        )
        #expect(try await sink.submit(
            alert: Alert(
                id: "durable-journal-gap",
                timestamp: trigger.timestamp,
                ruleId: "test.durable-journal-gap",
                ruleTitle: "Durable journal gap",
                severity: .high,
                eventId: trigger.id.uuidString
            ),
            event: trigger,
            // The base is durable, but the alert-time changed value has no
            // terminal receipt: this models a crash in the old enqueue-only
            // window exactly.
            journalAdmission: try admission(for: base, generation: 1)
        ))
        await sink.flushEvidenceCapture()

        let context = try #require(await alerts.evidenceContext(
            alertId: "durable-journal-gap"
        ))
        #expect(context.status == .incomplete)
        #expect(context.journalAdmissionGapCount == 1)
        #expect(context.poisonRecordCount == 0)
        #expect(context.corruptRecordCount == 0)
        #expect(context.inheritedLossCount == 0)
        #expect(context.resourceLimitedCount == 0)
        let captured = try await alerts.evidenceFor(
            alertId: "durable-journal-gap"
        )
        #expect(captured.count == 1)
        #expect(captured[0].id == trigger.id)
        #expect(captured[0].enrichments["reviewed"] == "true",
                "direct trigger must win UUID dedupe over the older base")

        // A new read-only actor models the post-crash/restart heartbeat. The
        // absolute durable counter, not an in-memory sink delta, remains red.
        let reopened = try AlertStore(
            directory: directory.path,
            forceReadOnly: true
        )
        let counts = try await reopened.evidenceContextCounts()
        #expect(counts.incomplete == 1)
        #expect(counts.journalAdmissionGapRecords == 1)
        #expect(counts.unhealthy == 1)
        #expect(counts.reconciles)
    }

    @Test("changed alert-time values require a durable terminal digest")
    func changedTriggerRequiresTerminalReceipt() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(
                "maccrab-trigger-terminal-proof-\(UUID().uuidString)"
            )
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = try AlertStore(directory: directory.path)
        let sink = AlertSink(
            alertStore: store,
            deduplicator: AlertDeduplicator(suppressionWindow: 0),
            journalAdmissionVerifier: { _ in .verified }
        )
        let base = event(
            timestamp: Date(timeIntervalSince1970: 61_000),
            commandLine: "/usr/bin/fixture",
            args: ["/usr/bin/fixture"]
        )
        let baseAdmission = try admission(for: base, generation: 41)
        var terminal = base
        terminal.enrichments["reviewed"] = "true"
        terminal.severity = .critical
        let terminalPreparation = try EventJournalAdmissionValidator.prepare(
            terminal
        )

        #expect(try await sink.submit(
            alert: Alert(
                id: "changed-without-terminal",
                timestamp: terminal.timestamp,
                ruleId: "test.changed-without-terminal",
                ruleTitle: "Changed without terminal",
                severity: .critical,
                eventId: terminal.id.uuidString
            ),
            event: terminal,
            journalAdmission: baseAdmission
        ))
        let missingRow = try #require(await store.alert(
            id: "changed-without-terminal"
        ))
        let missingProof = try #require(missingRow.triggeringEventsJson)
        #expect(missingProof.contains(#""journalContext":"gap""#))
        #expect(missingProof.contains(#""status":"failed""#))

        let terminalProof = EventJournalTerminalAdmission(
            eventID: terminal.id,
            baseGeneration: baseAdmission.generation,
            baseCanonicalSHA256: baseAdmission.canonicalSHA256,
            terminalCanonicalSHA256:
                terminalPreparation.canonicalSHA256,
            terminalCanonicalByteCount:
                terminalPreparation.canonicalJSON.count,
            status: .verified,
            storageMutationGeneration: 9
        )
        let inserted = try await EventJournalAdmissionContext
            .withTerminalRevision(terminalProof) {
                try await sink.submit(
                    alert: Alert(
                        id: "changed-with-terminal",
                        timestamp: terminal.timestamp,
                        ruleId: "test.changed-with-terminal",
                        ruleTitle: "Changed with terminal",
                        severity: .critical,
                        eventId: terminal.id.uuidString
                    ),
                    event: terminal,
                    journalAdmission: baseAdmission
                )
            }
        #expect(inserted)
        let verifiedRow = try #require(await store.alert(
            id: "changed-with-terminal"
        ))
        let verified = try #require(verifiedRow.triggeringEventsJson)
        #expect(!verified.contains(#""journalContext":"gap""#))

        let poisonedProof = EventJournalTerminalAdmission(
            eventID: terminalProof.eventID,
            baseGeneration: terminalProof.baseGeneration,
            baseCanonicalSHA256: terminalProof.baseCanonicalSHA256,
            terminalCanonicalSHA256:
                terminalProof.terminalCanonicalSHA256,
            terminalCanonicalByteCount:
                terminalProof.terminalCanonicalByteCount,
            status: .poisoned,
            storageMutationGeneration: 10
        )
        #expect(try await EventJournalAdmissionContext
            .withTerminalRevision(poisonedProof) {
                try await sink.submit(
                    alert: Alert(
                        id: "changed-with-terminal-poison",
                        timestamp: terminal.timestamp,
                        ruleId: "test.changed-with-terminal-poison",
                        ruleTitle: "Changed with terminal poison",
                        severity: .critical,
                        eventId: terminal.id.uuidString
                    ),
                    event: terminal,
                    journalAdmission: baseAdmission
                )
            })
        let poisonedRow = try #require(await store.alert(
            id: "changed-with-terminal-poison"
        ))
        let poisoned = try #require(poisonedRow.triggeringEventsJson)
        #expect(poisoned.contains(#""status":"poisoned""#))
        #expect((await sink.triggerSnapshotStats()).journalContextGapTotal == 2)
    }

    @Test("an unexpected marker overflow fails safe to marker-only JSON")
    func markerOverflowIsNeverSilent() throws {
        let trigger = event(commandLine: "/usr/bin/fixture", args: [])
        let oversizedPayload = String(
            repeating: "x",
            count: EventSnapshot.maximumSnapshotBytes
        )
        let prepared = PreparedAlertTrigger(
            eventID: trigger.id.uuidString,
            timestamp: trigger.timestamp,
            eventJSON: nil,
            snapshotJSON: "[\"\(oversizedPayload)\"]",
            disposition: .poison
        )
        let marked = prepared.snapshotJSON(journalContext: .failed)
        #expect(marked.utf8.count <= EventSnapshot.maximumSnapshotBytes)
        #expect(marked.contains(#""journalContext":"gap""#))
        #expect(marked.contains(#""status":"failed""#))
        #expect(!marked.contains(oversizedPayload))
        _ = try JSONSerialization.jsonObject(with: Data(marked.utf8))
    }
}

@Suite("Reviewed RuleMatch normalization")
struct ReviewedRuleMatchNormalizationTests {
    private func match(
        id: String,
        tags: [String],
        techniques: [String]
    ) -> RuleMatch {
        RuleMatch(
            ruleId: id,
            ruleName: "Rule \(id)",
            severity: .high,
            description: "match \(id)",
            mitreTechniques: techniques,
            tags: tags,
            suppressible: false
        )
    }

    @Test("permutation, retry, and duplicate tag order converge")
    func converges() {
        let a = match(
            id: "a",
            tags: ["attack.execution", "attack.persistence"],
            techniques: ["attack.t1059", "attack.t1547"]
        )
        let aPermuted = match(
            id: "a",
            tags: ["attack.persistence", "attack.execution", "attack.execution"],
            techniques: ["attack.t1547", "attack.t1059"]
        )
        let b = match(
            id: "b",
            tags: ["attack.discovery"],
            techniques: ["attack.t1087"]
        )

        let first = ReviewedRuleMatches.normalized([b, a, aPermuted, b])
        let second = ReviewedRuleMatches.normalized([aPermuted, b, a])
        #expect(first == second)
        #expect(first.map(\.ruleId) == ["a", "b"])
        #expect(first[0].tags == ["attack.execution", "attack.persistence"])
        #expect(ReviewedRuleMatches.merged([b], [a, b]) == first)
    }
}
