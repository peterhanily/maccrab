// Tests for PluginManifest.validate() — the runtime gate that
// mirrors audit Pass 2026-A. The two paths intentionally enforce
// the same invariants from different entry points; this test file
// covers the in-source side. Pass 2026-A covers the source-tree-
// scan side.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("PluginManifest validation")
struct PluginManifestValidationTests {

    private func goodManifest(
        id: String = "com.maccrab.forensics.tcc-lite",
        outputs: [OutputSpec] = [
            OutputSpec(contentType: "tcc.grant", privacyClass: .metadata),
            OutputSpec(contentType: "tcc.summary_by_service", privacyClass: .metadata),
        ],
        mcpTools: [MCPToolDescriptor] = [],
        inputs: [InputSpec] = [],
        runtime: PluginRuntime = .tierA,
        version: String = "1.0.0",
        schemaVersion: Int = 1
    ) -> PluginManifest {
        PluginManifest(
            id: id,
            version: version,
            displayName: "TCC-lite",
            description: "Inventory TCC grants on this Mac.",
            type: .collector,
            runtime: runtime,
            tccRequirements: [.fullDiskAccess],
            inputs: inputs,
            outputs: outputs,
            mcpTools: mcpTools,
            schemaVersion: schemaVersion,
            stability: .preview
        )
    }

    @Test("A well-formed first-party manifest passes validation")
    func wellFormedPasses() throws {
        try goodManifest().validate()
    }

    @Test("Empty id is rejected")
    func emptyIDRejected() {
        let m = goodManifest(id: "")
        #expect(throws: PluginManifest.ValidationError.emptyID) {
            try m.validate()
        }
    }

    @Test("Two-segment id is rejected (reverse-DNS requires >= 3)")
    func tooFewSegmentsRejected() {
        let m = goodManifest(id: "com.maccrab")
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("Uppercase in id is rejected")
    func uppercaseInIDRejected() {
        let m = goodManifest(id: "com.maccrab.Forensics.TCC")
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("Underscore in id is rejected (only [a-z0-9-] allowed in segments)")
    func underscoreInIDRejected() {
        let m = goodManifest(id: "com.maccrab.forensics.tcc_lite")
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("First-party id outside reserved kind namespace is rejected")
    func firstPartyOutsideReservedNamespaceRejected() {
        let m = goodManifest(
            id: "com.maccrab.something-unauthorized.foo",
            outputs: [OutputSpec(contentType: "something-unauthorized.event", privacyClass: .metadata)]
        )
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("Third-party id is accepted (validator only enforces shape for non-first-party)")
    func thirdPartyShapeOK() throws {
        let m = goodManifest(
            id: "com.acme.forensics.thing",
            outputs: [OutputSpec(contentType: "thing.event", privacyClass: .metadata)]
        )
        try m.validate()
    }

    @Test("Tier B runtime is rejected in v1.13a")
    func tierBRejected() {
        let m = goodManifest(runtime: .tierB)
        #expect(throws: PluginManifest.ValidationError.unsupportedRuntime(.tierB)) {
            try m.validate()
        }
    }

    @Test("Empty version is rejected")
    func emptyVersionRejected() {
        let m = goodManifest(version: "")
        #expect(throws: PluginManifest.ValidationError.emptyVersion) {
            try m.validate()
        }
    }

    @Test("Non-SemVer version is rejected")
    func nonSemVerRejected() {
        let m = goodManifest(version: "1.0")
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("schemaVersion < 1 is rejected")
    func schemaVersionZeroRejected() {
        let m = goodManifest(schemaVersion: 0)
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("Duplicate contentType in outputs is rejected")
    func duplicateContentTypeRejected() {
        let m = goodManifest(outputs: [
            OutputSpec(contentType: "tcc.grant", privacyClass: .metadata),
            OutputSpec(contentType: "tcc.grant", privacyClass: .metadata),
        ])
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("contentType that doesn't share namespace with plugin id is rejected")
    func contentTypeNamespaceMismatchRejected() {
        let m = goodManifest(outputs: [
            OutputSpec(contentType: "launchd.entry", privacyClass: .metadata),
        ])
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("contentType sharing namespace via hyphenated leaf segment passes (tcc.grant on tcc-lite)")
    func hyphenatedLeafSegmentOK() throws {
        // The plugin id is `com.maccrab.forensics.tcc-lite`; the
        // validator tolerates `tcc` matching the un-hyphenated form
        // of the leaf segment.
        try goodManifest(outputs: [
            OutputSpec(contentType: "tcc.grant", privacyClass: .metadata),
        ]).validate()
    }

    @Test("Duplicate MCP tool name is rejected")
    func duplicateMCPToolNameRejected() {
        let m = goodManifest(mcpTools: [
            MCPToolDescriptor(name: "tcc_grants_for_service", description: "a", exposesPrivacyClass: .metadata),
            MCPToolDescriptor(name: "tcc_grants_for_service", description: "b", exposesPrivacyClass: .metadata),
        ])
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("Duplicate input name is rejected")
    func duplicateInputNameRejected() {
        let m = goodManifest(inputs: [
            InputSpec(name: "foo", description: "first", type: .bool, default: .bool(false)),
            InputSpec(name: "foo", description: "second", type: .bool, default: .bool(true)),
        ])
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }

    @Test("Required input with no default is rejected")
    func requiredInputWithoutDefaultRejected() {
        let m = goodManifest(inputs: [
            InputSpec(name: "baselineCaseId", description: "case id", type: .caseID, default: nil, required: true),
        ])
        #expect(throws: (any Error).self) {
            try m.validate()
        }
    }
}

@Suite("PluginManifest Codable round-trip")
struct PluginManifestCodableTests {

    @Test("Manifest encodes and decodes losslessly")
    func roundTrip() throws {
        let original = PluginManifest(
            id: "com.maccrab.forensics.tcc-lite",
            version: "1.0.0",
            displayName: "TCC-lite",
            description: "Inventory TCC grants.",
            type: .collector,
            runtime: .tierA,
            tccRequirements: [.fullDiskAccess],
            inputs: [
                InputSpec(
                    name: "includeDeniedGrants",
                    description: "Include denied access rows.",
                    type: .bool,
                    default: .bool(true)
                ),
            ],
            outputs: [
                OutputSpec(contentType: "tcc.grant", privacyClass: .metadata),
            ],
            mcpTools: [
                MCPToolDescriptor(
                    name: "tcc_grants_for_service",
                    description: "List clients granted a service.",
                    exposesPrivacyClass: .metadata
                ),
            ],
            schemaVersion: 1,
            stability: .preview
        )
        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(PluginManifest.self, from: data)
        #expect(decoded.id == original.id)
        #expect(decoded.version == original.version)
        #expect(decoded.type == original.type)
        #expect(decoded.runtime == original.runtime)
        #expect(decoded.outputs.count == original.outputs.count)
        #expect(decoded.outputs.first?.contentType == "tcc.grant")
        #expect(decoded.outputs.first?.privacyClass == .metadata)
        #expect(decoded.mcpTools.first?.name == "tcc_grants_for_service")
        #expect(decoded.inputs.first?.default == .bool(true))
    }
}
