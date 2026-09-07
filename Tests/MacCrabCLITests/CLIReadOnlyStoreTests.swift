import Foundation
import Testing
@testable import MacCrabCore
@testable import maccrabctl
@testable import maccrab_mcp

@Suite("maccrabctl: daemon-owned stores are query-only", .serialized)
struct CLIReadOnlyStoreTests {
    private struct FileSnapshot: Equatable {
        let contents: Data
        let permissions: Int
        let modificationDate: Date?
    }

    private func makeDirectory() throws -> URL {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrabctl-readonly-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        return directory
    }

    private func event(sessionID: String) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 4_242,
            ppid: 1,
            rpid: 1,
            name: "cli-readonly-fixture",
            executable: "/usr/local/bin/cli-readonly-fixture",
            commandLine: "/usr/local/bin/cli-readonly-fixture --query",
            args: ["/usr/local/bin/cli-readonly-fixture", "--query"],
            workingDirectory: "/private/tmp/cli-readonly-project",
            userId: 501,
            userName: "fixture-user",
            groupId: 20,
            startTime: Date(),
            ancestors: [],
            isPlatformBinary: false
        )
        return Event(
            timestamp: Date(),
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: process,
            enrichments: [
                "ai_tool_session_id": sessionID,
                "ai_tool": "codex",
                "agent_tool": "codex",
            ]
        )
    }

    private func alert(
        id: String,
        ruleID: String,
        title: String,
        sessionID: String
    ) -> Alert {
        Alert(
            id: id,
            timestamp: Date(),
            ruleId: ruleID,
            ruleTitle: title,
            severity: .high,
            eventId: UUID().uuidString,
            processPath: "/usr/local/bin/cli-readonly-fixture",
            processName: "cli-readonly-fixture",
            description: "production-shaped read-only CLI fixture",
            mitreTactics: "TA0001,TA0002,TA0003",
            mitreTechniques: "T1059",
            aiTool: "codex",
            aiToolSessionId: sessionID
        )
    }

    private func seedEvents(at directory: URL, sessionID: String) async throws {
        let writer = try EventStore(directory: directory.path)
        try await writer.insert(event: event(sessionID: sessionID))
        #expect(await writer.walCheckpointTruncate())
    }

    private func seedAlerts(at directory: URL, sessionID: String) async throws {
        let writer = try AlertStore(directory: directory.path)
        let fixtures = [
            alert(
                id: "ordinary-alert",
                ruleID: "fixture.exec",
                title: "Ordinary CLI fixture",
                sessionID: sessionID
            ),
            alert(
                id: "ai-alert",
                ruleID: "maccrab.ai-guard.prompt-injection",
                title: "AI Prompt Injection fixture",
                sessionID: sessionID
            ),
            alert(
                id: "intel-alert",
                ruleID: "maccrab.threat-intel.hash-match",
                title: "Threat-intel fixture",
                sessionID: sessionID
            ),
            alert(
                id: "campaign-alert",
                ruleID: "maccrab.campaign.kill-chain",
                title: "Campaign fixture",
                sessionID: sessionID
            ),
            alert(
                id: "privacy-alert",
                ruleID: "maccrab.privacy.tcc-fixture",
                title: "Privacy fixture",
                sessionID: sessionID
            ),
            alert(
                id: "vuln-alert",
                ruleID: "maccrab.vuln.fixture",
                title: "Vulnerability fixture",
                sessionID: sessionID
            ),
        ]
        _ = try await writer.insert(alerts: fixtures)
        #expect(await writer.walCheckpointTruncate())
    }

    private func evidenceFamilyNames(at directory: URL) throws -> [String] {
        try FileManager.default.contentsOfDirectory(atPath: directory.path)
            .filter { $0.hasPrefix("events.db") || $0.hasPrefix("alerts.db") }
            .sorted()
    }

    private func snapshot(at directory: URL) throws -> [String: FileSnapshot] {
        var result: [String: FileSnapshot] = [:]
        for name in try evidenceFamilyNames(at: directory) {
            let url = directory.appendingPathComponent(name)
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            result[name] = FileSnapshot(
                contents: try Data(contentsOf: url),
                permissions: (attributes[.posixPermissions] as? NSNumber)?.intValue ?? -1,
                modificationDate: attributes[.modificationDate] as? Date
            )
        }
        return result
    }

    private func makeOwnerUnwritable(_ directory: URL) throws {
        for name in try evidenceFamilyNames(at: directory) {
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o440],
                ofItemAtPath: directory.appendingPathComponent(name).path
            )
        }
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o550],
            ofItemAtPath: directory.path
        )
    }

    private func restoreOwnerWrite(_ directory: URL) {
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o750],
            ofItemAtPath: directory.path
        )
        guard let names = try? evidenceFamilyNames(at: directory) else { return }
        for name in names {
            try? FileManager.default.setAttributes(
                [.posixPermissions: 0o600],
                ofItemAtPath: directory.appendingPathComponent(name).path
            )
        }
    }

    @Test("status, list, export, intel, watch and session query shapes read an owner-unwritable DB family without changing it")
    func shippedQueryShapesReadWithoutWriting() async throws {
        let directory = try makeDirectory()
        defer {
            restoreOwnerWrite(directory)
            try? FileManager.default.removeItem(at: directory)
        }
        let sessionID = UUID().uuidString
        let liveMemoryBudget = EventPipelineLiveMemoryBudget
            .isolatedProductionEquivalentForTesting()
        let fixtureEvent = event(sessionID: sessionID)
        let rejectedAlert = alert(
            id: "must-not-write",
            ruleID: "fixture.must-not-write",
            title: "Must not write",
            sessionID: sessionID
        )

        try await seedEvents(at: directory, sessionID: sessionID)
        try await seedAlerts(at: directory, sessionID: sessionID)
        try makeOwnerUnwritable(directory)

        let before = try snapshot(at: directory)
        #expect(!before.isEmpty)
        #expect(before.values.allSatisfy { ($0.permissions & 0o222) == 0 })

        do {
            let events = try MacCrabCtl.openEventStoreForReading(
                directory: directory.path,
                liveMemoryBudget: liveMemoryBudget
            )

            // `status` uses physical cardinality and must not decode journal
            // blocks. Explicit evidence commands and all three session readers
            // use the exact query shapes below.
            let statusDecodesBefore = await events
                .journalExactQueryBlockDecodeCount()
            #expect(
                try await MacCrabCtl.retainedEventCountForStatus(events) == 1
            )
            #expect(
                await events.journalExactQueryBlockDecodeCount()
                    == statusDecodesBefore
            )
            #expect(try await events.count() == 1)
            let eventRows = try await events.exactEventsSnapshot(
                since: .distantPast,
                limit: 10
            )
            #expect(eventRows.events.count == 1)
            let search = try await events.searchSnapshot(
                text: "cli-readonly-fixture",
                limit: 10
            )
            #expect(search.events.count == 1)
            #expect(try await events.agentSessions(limit: 10).first?.sessionId == sessionID)
            let sessionEvents = try await events
                .exactEventsForAgentSessionSnapshot(
                    sessionID,
                    since: .distantPast,
                    until: .distantFuture,
                    limit: 10
                )
            #expect(sessionEvents.events.count == 1)
            #expect(try await events.eventCountWithMachineAttribution() == 1)

            // The exact factory used by those commands has no write
            // capability, even though the fixture value itself is valid.
            await #expect(throws: (any Error).self) {
                try await events.insert(event: fixtureEvent)
            }
        }

        do {
            let alerts = try MacCrabCtl.openAlertStoreForReading(
                directory: directory.path
            )

            // Covers status, alerts list/export/watch, campaigns list/watch,
            // intel matches, AI alerts, report, why, tree score, privacy,
            // vulnerabilities, and the session alert rail.
            let all = try await alerts.alerts(since: .distantPast, limit: 100)
            #expect(try await alerts.count() == 6)
            #expect(all.count == 6)
            #expect(try await alerts.alert(id: "ordinary-alert")?.id == "ordinary-alert")
            #expect(try await alerts.campaignCount() == 1)
            #expect(try await alerts.campaigns(before: nil, pageSize: 10).items.count == 1)
            #expect(try await alerts.aiAlerts(since: .distantPast, limit: 10).count == 1)
            #expect(try await alerts.alerts(forAgentSession: sessionID).count == 6)
            #expect(all.filter { $0.ruleId.hasPrefix("maccrab.threat-intel.") }.count == 1)
            #expect(all.filter { $0.ruleId.hasPrefix("maccrab.privacy.") }.count == 1)
            #expect(all.filter { $0.ruleId.hasPrefix("maccrab.vuln.") }.count == 1)

            await #expect(throws: (any Error).self) {
                try await alerts.insert(alert: rejectedAlert)
            }
        }

        do {
            let events = try maccrab_mcp.openMCPEventStoreForReading(
                directory: directory.path,
                liveMemoryBudget: liveMemoryBudget
            )
            #expect(try await events.count() == 1)
            let sessionEvents = try await events
                .exactEventsForAgentSessionSnapshot(
                    sessionID,
                    since: .distantPast,
                    until: .distantFuture,
                    limit: 10
                )
            #expect(sessionEvents.events.count == 1)
            await #expect(throws: (any Error).self) {
                try await events.insert(event: fixtureEvent)
            }
        }

        do {
            let alerts = try maccrab_mcp.openMCPAlertStoreForReading(
                directory: directory.path
            )
            #expect(try await alerts.count() == 6)
            #expect(try await alerts.alert(id: "ordinary-alert")?.id == "ordinary-alert")
            await #expect(throws: (any Error).self) {
                try await alerts.insert(alert: rejectedAlert)
            }
        }

        let after = try snapshot(at: directory)
        #expect(after == before)
    }

    @Test("every direct maccrabctl store constructor is classified as query-only or an intentional writer")
    func everyStoreOpenIsExplicitlyClassified() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceDirectory = root.appendingPathComponent("Sources/maccrabctl")
        let files = try FileManager.default.contentsOfDirectory(
            at: sourceDirectory,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "swift" }

        var eventConstructors: [(String, String)] = []
        var alertConstructors: [(String, String)] = []
        var campaignConstructors: [(String, String)] = []
        var eventReaderCalls = 0
        var alertReaderCalls = 0

        for file in files {
            let source = try String(contentsOf: file, encoding: .utf8)
            for line in source.components(separatedBy: .newlines) {
                if line.contains("EventStore(") {
                    eventConstructors.append((file.lastPathComponent, line))
                }
                if line.contains("AlertStore(") {
                    alertConstructors.append((file.lastPathComponent, line))
                }
                if line.contains("CampaignStore(") {
                    campaignConstructors.append((file.lastPathComponent, line))
                }
                if line.contains("openEventStoreForReading(") {
                    eventReaderCalls += 1
                }
                if line.contains("openAlertStoreForReading(") {
                    alertReaderCalls += 1
                }
            }
        }

        // One direct query-only constructor per evidence store, centralized in
        // ReadOnlyStores.swift. `rollup` is the sole EventStore writer because
        // it deliberately prunes, vacuums, and checkpoints the DB.
        #expect(eventConstructors.count == 2, "classify every new EventStore open")
        #expect(eventConstructors.contains {
            $0.0 == "ReadOnlyStores.swift"
        })
        let eventReaderFactory = try String(
            contentsOf: sourceDirectory.appendingPathComponent(
                "ReadOnlyStores.swift"
            ),
            encoding: .utf8
        )
        #expect(eventReaderFactory.contains("forceReadOnly: true"))
        #expect(eventReaderFactory.contains(
            "liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared"
        ))
        #expect(eventConstructors.contains {
            $0.0 == "RollupCommand.swift" && $0.1.contains("path: dbPath")
                && !$0.1.contains("forceReadOnly: true")
        })
        #expect(alertConstructors.count == 1, "all CLI AlertStore opens are reads")
        #expect(alertConstructors[0].0 == "ReadOnlyStores.swift")
        #expect(alertConstructors[0].1.contains("forceReadOnly: true"))
        #expect(campaignConstructors.isEmpty,
                "maccrabctl currently reads campaign alerts through AlertStore")

        // Seven EventStore and 15 AlertStore shipped callsites, plus each
        // factory declaration, are the complete command surface at this
        // revision (including both watch setup paths).
        #expect(eventReaderCalls == 8)
        #expect(alertReaderCalls == 16)

        // TraceGraph and agent-span query clients already had the correct
        // explicit policy. Keep them in this executable-level audit so a
        // future CLI reader cannot silently regress while the primary stores
        // remain green.
        let traceCommands = try String(
            contentsOf: sourceDirectory.appendingPathComponent("TraceCommands.swift"),
            encoding: .utf8
        )
        // v1.21.6-rc.45: assert the INVARIANT, not argument adjacency. This
        // used to pin the literal "databasePath: path,\n                forceReadOnly: true",
        // so adding the `encryption:` argument between them failed a test whose
        // actual contract — the CLI never opens the causal graph read-write —
        // was untouched. Check every construction instead, which is stricter
        // than the adjacency it replaces.
        #expect(!traceCommands.contains("forceReadOnly: false"))
        let causalOpens = traceCommands.components(
            separatedBy: "SQLiteCausalGraphStore("
        ).dropFirst().map { String($0.prefix(400)) }
        // Exactly two constructions, and each must be classifiable:
        //   - the query surface `openStore()` — read-only;
        //   - `traceDemo` — the ONE intentional writer, a DEBUG seeding path
        //     that must still carry the daemon's footprint and free-space
        //     admission so a developer tool cannot bypass it.
        #expect(causalOpens.count == 2, "a new causal-graph open must be classified here")
        let readOnly = causalOpens.filter { $0.contains("forceReadOnly: true") }
        let writers = causalOpens.filter { !$0.contains("forceReadOnly: true") }
        #expect(readOnly.count == 1, "the query surface must be read-only")
        #expect(writers.count == 1, "traceDemo is the only intentional writer")
        #expect(
            writers[0].contains("maxFootprintBytes:")
                && writers[0].contains("freeSpaceFloorBytes:"),
            "the intentional writer must stay under the daemon's admission budget"
        )
        // The read key is required too: opening keyless decodes nothing, which
        // is what made `trace export` impossible before rc.45.
        #expect(traceCommands.contains("encryption: encryption"))
        let agentSpans = try String(
            contentsOf: sourceDirectory.appendingPathComponent("AgentSpansCommand.swift"),
            encoding: .utf8
        )
        #expect(agentSpans.contains("forceReadOnly: true"))
        let status = try String(
            contentsOf: sourceDirectory.appendingPathComponent("StatusCommand.swift"),
            encoding: .utf8
        )
        #expect(status.contains("TraceStore("))
        #expect(status.contains("forceReadOnly: true"))

        let mcpSourceDirectory = root.appendingPathComponent("Sources/maccrab-mcp")
        let mcpFiles = try FileManager.default.contentsOfDirectory(
            at: mcpSourceDirectory,
            includingPropertiesForKeys: nil
        ).filter { $0.pathExtension == "swift" }
        var mcpEventConstructors: [(String, String)] = []
        var mcpAlertConstructors: [(String, String)] = []
        var mcpCampaignConstructors: [(String, String)] = []
        var mcpEventReaderCalls = 0
        var mcpAlertReaderCalls = 0
        var allMCPSource = ""
        for file in mcpFiles {
            let source = try String(contentsOf: file, encoding: .utf8)
            allMCPSource += source
            for line in source.components(separatedBy: .newlines) {
                if line.contains("EventStore(") {
                    mcpEventConstructors.append((file.lastPathComponent, line))
                }
                if line.contains("AlertStore(") {
                    mcpAlertConstructors.append((file.lastPathComponent, line))
                }
                if line.contains("CampaignStore(") {
                    mcpCampaignConstructors.append((file.lastPathComponent, line))
                }
                if line.contains("openMCPEventStoreForReading(") {
                    mcpEventReaderCalls += 1
                }
                if line.contains("openMCPAlertStoreForReading(") {
                    mcpAlertReaderCalls += 1
                }
            }
        }

        #expect(mcpEventConstructors.count == 1,
                "all MCP EventStore opens are query-only")
        #expect(mcpEventConstructors[0].0 == "ReadOnlyStores.swift")
        let mcpEventReaderFactory = try String(
            contentsOf: mcpSourceDirectory.appendingPathComponent(
                "ReadOnlyStores.swift"
            ),
            encoding: .utf8
        )
        #expect(mcpEventReaderFactory.contains("forceReadOnly: true"))
        #expect(mcpEventReaderFactory.contains(
            "liveMemoryBudget: EventPipelineLiveMemoryBudget = .processShared"
        ))
        #expect(mcpAlertConstructors.count == 1,
                "all MCP AlertStore opens are query-only")
        #expect(mcpAlertConstructors[0].0 == "ReadOnlyStores.swift")
        #expect(mcpAlertConstructors[0].1.contains("forceReadOnly: true"))
        #expect(mcpCampaignConstructors.isEmpty)
        // Five event and eleven alert invocations, plus each declaration.
        // Status now reads through the shared RuntimeStatusDocument, whose
        // constructors are audited below instead of in this executable folder.
        #expect(mcpEventReaderCalls == 6)
        #expect(mcpAlertReaderCalls == 12)

        func constructorCalls(named marker: String, in source: String) -> [String] {
            var calls: [String] = []
            var searchStart = source.startIndex
            while let markerRange = source.range(
                of: marker,
                range: searchStart..<source.endIndex
            ) {
                var depth = 1
                var cursor = markerRange.upperBound
                while cursor < source.endIndex, depth > 0 {
                    switch source[cursor] {
                    case "(": depth += 1
                    case ")": depth -= 1
                    default: break
                    }
                    cursor = source.index(after: cursor)
                }
                guard depth == 0 else { break }
                calls.append(String(source[markerRange.lowerBound..<cursor]))
                searchStart = cursor
            }
            return calls
        }

        let runtimeStatusSource = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabCore/Assessment/RuntimeStatusDocument.swift"
            ),
            encoding: .utf8
        )
        let statusEventCalls = constructorCalls(named: "EventStore(", in: runtimeStatusSource)
        let statusAlertCalls = constructorCalls(named: "AlertStore(", in: runtimeStatusSource)
        #expect(statusEventCalls.count == 1,
                "classify every shared status EventStore open")
        #expect(statusAlertCalls.count == 1,
                "classify every shared status AlertStore open")
        #expect((statusEventCalls + statusAlertCalls).allSatisfy {
            $0.contains("forceReadOnly: true")
        }, "CLI and MCP status must keep both shared evidence stores query-only")

        let graphCalls = constructorCalls(
            named: "SQLiteCausalGraphStore(",
            in: allMCPSource
        )
        #expect(graphCalls.count == 4)
        #expect(graphCalls.allSatisfy { $0.contains("forceReadOnly: true") })
        let traceStoreCalls = constructorCalls(named: "TraceStore(", in: allMCPSource)
        #expect(traceStoreCalls.count == 1)
        #expect(traceStoreCalls[0].contains("forceReadOnly: true"))
    }
}
