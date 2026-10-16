import Foundation
import Testing
@testable import MacCrabCore

@Suite("YARA pre-actor eligibility preserves the original event contract")
struct YARAEligibilityTests {
    private let actions = [
        "create", "creation", "file_create", "notify_create", "CREATE", "Create",
        "create ", "", "unlink", "delete", "write", "rename", "close", "open", "資料",
    ]

    private func event(
        category: EventCategory = .file,
        type: EventType = .creation,
        action: String = "create",
        file: FileInfo? = FileInfo(path: "/synthetic/yara-eligibility/item", action: .create)
    ) -> Event {
        Event(
            id: UUID(uuidString: "11111111-2222-3333-4444-555555555555")!,
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            eventCategory: category, eventType: type, eventAction: action,
            process: MacCrabCore.ProcessInfo(
                pid: 101, ppid: 100, rpid: 100, name: "synthetic-writer",
                executable: "/synthetic/yara-eligibility/writer",
                commandLine: "synthetic-writer item", args: ["item"],
                workingDirectory: "/synthetic/yara-eligibility", userId: 501,
                userName: "synthetic", groupId: 20,
                startTime: Date(timeIntervalSince1970: 1_699_999_000)
            ),
            file: file, enrichments: ["existing": "unchanged", "yara.rules": "prior-value"],
            severity: .high,
            ruleMatches: [.init(ruleId: "synthetic-rule", ruleName: "Synthetic rule",
                                severity: .low, description: "Inert test context", suppressible: false)]
        )
    }

    @Test("Every category/type/action/payload combination matches the old guard")
    func completeEventShapeTruthTable() {
        var checked = 0
        for category in EventCategory.allCases {
            for type in EventType.allCases {
                for action in actions {
                    for payloadPresent in [false, true] {
                        let value = event(category: category, type: type, action: action,
                                          file: payloadPresent ? FileInfo(
                                            path: "/synthetic/yara-eligibility/item", action: .delete
                                          ) : nil)
                        // Keep the previous branch form as an independent oracle.
                        let original: Bool
                        if value.eventCategory == .file,
                           value.eventAction == "create" || value.eventType == .creation,
                           let _ = value.file {
                            original = true
                        } else {
                            original = false
                        }
                        #expect(YARAEnricher.isEligibleEvent(value) == original)
                        checked += 1
                    }
                }
            }
        }
        #expect(checked == EventCategory.allCases.count * EventType.allCases.count * actions.count * 2)
    }

    @Test("Creation type preserves all action aliases, independent of payload action")
    func disjunctionAndPayloadActionStayUnchanged() {
        for payloadAction in FileAction.allCases {
            let payload = FileInfo(path: "", action: payloadAction)
            for action in actions {
                #expect(YARAEnricher.isEligibleEvent(event(type: .creation, action: action, file: payload)))
                #expect(YARAEnricher.isEligibleEvent(event(type: .deletion, action: action, file: payload))
                        == (action == "create"))
            }
        }
        #expect(!YARAEnricher.isEligibleEvent(event(type: .deletion, action: "unlink")))
        #expect(!YARAEnricher.isEligibleEvent(event(file: nil)))
        #expect(!YARAEnricher.isEligibleEvent(event(category: .process)))
    }

    @Test("Event eligibility never enables a privileged or untrusted configuration")
    func availabilityTruthTableRemainsIndependent() {
        #expect(YARAEnricher.isEligibleEvent(event()))
        for uid in [UInt32(0), UInt32(501)] {
            for binaryTrusted in [false, true] {
                for rulesTrusted in [false, true] {
                    #expect(YARAEnricher.shouldEnable(effectiveUID: uid,
                        binaryTrusted: binaryTrusted, rulesTrusted: rulesTrusted)
                        == (uid != 0 && binaryTrusted && rulesTrusted))
                }
            }
        }
    }

    @Test("Disabled actor preserves eligible and ineligible events and zero scan statistics")
    func disabledActorReturnsExactEvent() async throws {
        // Existing initializer resolves account/home metadata, but all supplied
        // paths are inside this owned empty fixture. No installed store, rule
        // tree, executable, scanner, listener or network operation is involved.
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("MacCrabYARAEligibility-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        let enricher = YARAEnricher(rulesPath: root.appendingPathComponent("missing-rules").path,
                                    yaraPath: root.appendingPathComponent("missing-yara").path,
                                    scanPaths: [root.path + "/"])
        #expect(await enricher.isAvailable() == false)
        for type in EventType.allCases {
            for action in actions {
                let original = event(type: type, action: action,
                                     file: FileInfo(path: root.appendingPathComponent("absent-item").path,
                                                    action: .create))
                let returned = await enricher.enrich(original)
                #expect(returned == original)
            }
        }
        let statistics = await enricher.stats()
        #expect(statistics.scanned == 0)
        #expect(statistics.matched == 0)
    }

    @Test("Production caller gates the only YARA await and actor retains enabled-first validation")
    func productionWiringUsesSharedGuard() throws {
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let loop = try String(contentsOf: repository.appendingPathComponent(
            "Sources/MacCrabAgentKit/EventLoop.swift"), encoding: .utf8)
        let actor = try String(contentsOf: repository.appendingPathComponent(
            "Sources/MacCrabCore/Enrichment/YARAEnricher.swift"), encoding: .utf8)
        let call = "enrichedEvent = await state.yaraEnricher.enrich(enrichedEvent)"
        #expect(loop.components(separatedBy: call).count == 2)
        let trimmedLines = loop.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }.joined(separator: "\n")
        #expect(trimmedLines.contains("if YARAEnricher.isEligibleEvent(enrichedEvent) {\n" + call + "\n}"))
        let method = try #require(actor.range(of: "public func enrich(_ event: Event) async -> Event {"))
        let body = actor[method.upperBound...]
        let enabled = try #require(body.range(of: "guard enabled else { return event }"))
        let eligibility = try #require(body.range(of: "guard Self.isEligibleEvent(event),"))
        let pathGate = try #require(body.range(of: "guard matchesScanPaths(filePath) else { return event }"))
        #expect(enabled.lowerBound < eligibility.lowerBound)
        #expect(eligibility.lowerBound < pathGate.lowerBound)
    }
}
