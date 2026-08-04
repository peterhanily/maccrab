import Foundation
import Testing
@testable import MacCrabCore

@Suite("RuleGenerator sustainable review candidates")
struct RuleGeneratorSustainabilityTests {
    typealias Alert = (
        ruleId: String,
        ruleTitle: String,
        processPath: String?,
        tactics: Set<String>,
        timestamp: Date
    )

    private func temporaryDirectory(_ label: String) throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("maccrab-rule-generator-\(label)-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true
        )
        return url
    }

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    private func alerts(at date: Date = Date()) -> [Alert] {
        [
            (
                ruleId: "rule.download",
                ruleTitle: "Download",
                processPath: "/usr/bin/curl",
                tactics: ["attack.command-and-control"],
                timestamp: date
            ),
            (
                ruleId: "rule.execute",
                ruleTitle: "Execute",
                processPath: "/bin/zsh",
                tactics: ["attack.execution"],
                timestamp: date.addingTimeInterval(1)
            ),
        ]
    }

    @Test("Semantic identity survives restart, order, and timestamp changes without clobber")
    func restartDedupeIsStable() async throws {
        let directory = try temporaryDirectory("dedupe")
        let firstGenerator = RuleGenerator(outputDir: directory.path)
        let first = try #require(await firstGenerator.generateFromCampaign(
            campaignType: "download_execute",
            alerts: alerts(at: Date(timeIntervalSince1970: 10))
        ))
        let candidate = directory.appendingPathComponent("auto_generated")
            .appendingPathComponent(first.filename)
        let originalBytes = try Data(contentsOf: candidate)

        let restartedGenerator = RuleGenerator(outputDir: directory.path)
        let replay = await restartedGenerator.generateFromCampaign(
            campaignType: "download_execute",
            alerts: Array(alerts(at: Date(timeIntervalSince1970: 50_000)).reversed())
        )

        #expect(replay == nil)
        #expect(try Data(contentsOf: candidate) == originalBytes)
        let telemetry = await restartedGenerator.telemetrySnapshot()
        #expect(telemetry.offeredTotal == 1)
        #expect(telemetry.duplicateTotal == 1)
        #expect(telemetry.persistedTotal == 0)
        #expect(telemetry.conservationMaintained)
        #expect(telemetry.llmValidationConservationMaintained)
        #expect(telemetry.llmPersistenceConservationMaintained)
    }

    @Test("New grounded evidence earns a distinct bounded candidate")
    func novelEvidenceGetsNewCandidate() async throws {
        let directory = try temporaryDirectory("novel")
        let generator = RuleGenerator(outputDir: directory.path)
        let first = try #require(await generator.generateFromCampaign(
            campaignType: "download_execute",
            alerts: alerts()
        ))
        var evolved = alerts()
        evolved.append((
            ruleId: "rule.persist",
            ruleTitle: "Persist",
            processPath: "/usr/bin/osascript",
            tactics: ["attack.persistence"],
            timestamp: Date()
        ))
        let second = try #require(await generator.generateFromCampaign(
            campaignType: "download_execute",
            alerts: evolved
        ))

        #expect(first.filename != second.filename)
        #expect(first.filename.utf8.count < 128)
        #expect(second.filename.utf8.count < 128)
        #expect(await generator.stats() == 2)
        let telemetry = await generator.telemetrySnapshot()
        #expect(telemetry.persistedTotal == 2)
        #expect(telemetry.deterministicAttemptsTotal == 2)
        #expect(telemetry.conservationMaintained)
    }

    @Test("Ungrounded campaigns do not create placeholder rules")
    func ungroundedCampaignAbstains() async throws {
        let directory = try temporaryDirectory("abstain")
        let generator = RuleGenerator(outputDir: directory.path)
        let ungrounded: [Alert] = [
            ("one", "One", nil, ["attack.execution"], Date()),
            ("two", "Two", nil, ["attack.persistence"], Date()),
        ]

        #expect(await generator.generateFromCampaign(
            campaignType: "unknown",
            alerts: ungrounded
        ) == nil)
        #expect(!FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("auto_generated").path
        ))
        let telemetry = await generator.telemetrySnapshot()
        #expect(telemetry.insufficientSignalTotal == 1)
        #expect(telemetry.deterministicAttemptsTotal == 0)
        #expect(telemetry.conservationMaintained)
    }

    @Test("Hostile campaign labels cannot escape the review directory")
    func hostileFilenameIsContained() async throws {
        let directory = try temporaryDirectory("filename")
        let generator = RuleGenerator(outputDir: directory.path)
        let generated = try #require(await generator.generateFromCampaign(
            campaignType: "../../\nunsafe campaign",
            alerts: alerts()
        ))

        #expect(!generated.filename.contains("/"))
        #expect(!generated.filename.contains(".."))
        #expect(FileManager.default.fileExists(
            atPath: directory.appendingPathComponent("auto_generated")
                .appendingPathComponent(generated.filename).path
        ))
    }

    @Test("Persistence failures are terminal and conserved")
    func persistenceFailureIsVisible() async throws {
        let parent = try temporaryDirectory("failure")
        let blocked = parent.appendingPathComponent("not-a-directory")
        try Data("carrier".utf8).write(to: blocked)
        let generator = RuleGenerator(outputDir: blocked.path)

        #expect(await generator.generateFromCampaign(
            campaignType: "download_execute",
            alerts: alerts()
        ) == nil)
        let telemetry = await generator.telemetrySnapshot()
        #expect(telemetry.writeFailedTotal == 1)
        #expect(telemetry.persistedTotal == 0)
        #expect(telemetry.currentOperations == 0)
        #expect(telemetry.conservationMaintained)
    }

    @Test("production model wiring stays off the detection hot path")
    func productionWiringIsBoundedAndExplicit() throws {
        let setup = try String(contentsOf: repositoryRoot.appendingPathComponent(
            "Sources/MacCrabAgentKit/DaemonSetup.swift"
        ), encoding: .utf8)
        let eventLoop = try String(contentsOf: repositoryRoot.appendingPathComponent(
            "Sources/MacCrabAgentKit/EventLoop.swift"
        ), encoding: .utf8)

        #expect(setup.contains("await ruleGenerator.configureLLMService(llmService)"))
        #expect(eventLoop.contains("label: \"rule-candidate\""))
        #expect(eventLoop.contains("ruleGenerator.generateFromCampaignEnhanced("))
        #expect(!eventLoop.contains("if state.llmService != nil {\n                            _ = await state.ruleGenerator.generateFromCampaignEnhanced"))
    }
}
