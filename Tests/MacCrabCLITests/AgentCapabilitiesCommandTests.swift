import Foundation
import Testing
@testable import maccrabctl

@Suite("Root-authorized MCP capability CLI")
struct AgentCapabilitiesCommandTests {
    @Test("Boolean parser is explicit and rejects ambiguous input")
    func booleanParser() {
        #expect(parseCapabilityBoolean("on") == true)
        #expect(parseCapabilityBoolean("TRUE") == true)
        #expect(parseCapabilityBoolean("0") == false)
        #expect(parseCapabilityBoolean("no") == false)
        #expect(parseCapabilityBoolean("enable") == nil)
        #expect(parseCapabilityBoolean("") == nil)
    }

    @Test("Changing one tier preserves the other installed grants")
    func oneTierMerge() {
        var document = AgentCapabilitiesDocument(dictionary: [
            "config": true,
            "authoring": false,
            "response": true,
        ])
        let authoringChanged = document.set(tier: "authoring", enabled: true)
        #expect(authoringChanged)
        #expect(document.config)
        #expect(document.authoring)
        #expect(document.response)
        let unknownChanged = document.set(tier: "unknown", enabled: true)
        #expect(!unknownChanged)
    }

    @Test("Source guard pins root ownership and atomic bounded request publication")
    func authoritySourceGuard() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let command = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/maccrabctl/AgentCapabilitiesCommands.swift"),
            encoding: .utf8
        )
        let main = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/maccrabctl/MacCrabCtl.swift"),
            encoding: .utf8
        )
        let help = try String(
            contentsOf: root.appendingPathComponent(
                "Sources/maccrabctl/Helpers.swift"),
            encoding: .utf8
        )

        #expect(command.contains("guard geteuid() == 0"))
        #expect(command.contains("O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC"))
        #expect(command.contains("fsync(fd)"))
        #expect(command.contains("rename(temporaryPath, finalPath)"))
        #expect(command.contains("openedInfo.st_uid == 0"))
        #expect(command.contains("S_IWGRP | S_IWOTH"))
        #expect(main.contains("case \"agent-capabilities\":"))
        #expect(help.contains("agent-capabilities <show|set|disable-all>"))
    }
}
