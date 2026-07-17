// FileAnalyzerManifestTests — the operator/agent-supplied `path` input is a
// declared manifest input on every file-analyzer collector.
//
// Regression for the HIGH bug where DMG/PKG, Image, Plist, and Office
// analyzers consumed `caseContext.inputs.values["path"]` but declared
// `inputs: []`. buildPluginInputs (MCP) only threads DECLARED inputs, and
// pluginMCPTools builds the tool inputSchema from `manifest.inputs`, so a
// missing declaration meant the caller's target path was dropped and the
// analyzers silently fell back to scanning ~/Downloads.

import Testing
@testable import MacCrabForensics

@Suite("FileAnalyzer manifests declare the path input")
struct FileAnalyzerManifestTests {

    @Test("DMG/PKG, Image, Plist, Office analyzers advertise a `path` input")
    func analyzersDeclarePathInput() {
        let manifests: [PluginManifest] = [
            DMGPKGAnalyzerPlugin.manifest,
            ImageMetadataPlugin.manifest,
            PlistAnalyzerPlugin.manifest,
            OfficeDocumentPlugin.manifest,
        ]
        for m in manifests {
            let pathInput = m.inputs.first { $0.name == "path" }
            #expect(pathInput != nil, "\(m.id) must declare a `path` input")
            #expect(pathInput?.type == .path, "\(m.id) `path` input must be type .path")
        }
    }
}
