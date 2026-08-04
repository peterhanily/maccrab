import Foundation
import Testing

@Suite("AI monitor post-commit wiring")
struct AIMonitorPostCommitWiringTests {
    private func source() throws -> String {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        return try String(
            contentsOf: root.appendingPathComponent(
                "Sources/MacCrabAgentKit/MonitorTasks.swift"
            ),
            encoding: .utf8
        )
    }

    private func section(
        _ source: String,
        from startNeedle: String,
        to endNeedle: String
    ) throws -> String {
        let start = try #require(source.range(of: startNeedle))
        let end = try #require(
            source.range(of: endNeedle, range: start.upperBound..<source.endIndex)
        )
        return String(source[start.lowerBound..<end.lowerBound])
    }

    @Test("SDR and EDR model work requires a committed primary alert")
    func monitorAIChildrenCannotOutlivePrimary() throws {
        let text = try source()
        let sdr = try section(
            text,
            from: "// SDR device + display-hotplug monitoring task",
            to: "// BTM / SMAppService reconciliation task"
        )
        let edr = try section(
            text,
            from: "// EDR/RMM tool monitoring task",
            to: "// DNS event processing task"
        )

        for block in [sdr, edr] {
            let submit = try #require(block.range(
                of: "primaryPersisted = try await state.alertSink.submit"
            ))
            let llm = try #require(block.range(
                of: "if primaryPersisted, let llm = state.llmService"
            ))
            #expect(submit.lowerBound < llm.lowerBound)
            #expect(!block.contains("if let llm = state.llmService"))
        }

        #expect(edr.contains(
            "if primaryPersisted, discovery.category == .insiderThreat"
        ), "EDR notification must share the persisted-primary boundary")
    }
}
