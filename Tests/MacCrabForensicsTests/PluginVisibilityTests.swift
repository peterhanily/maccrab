// PluginVisibilityTests — the shared residue classifier hides exactly the on-device
// dev/test/rehearsal leftovers while leaving real built-ins + third-party visible.

import Testing
@testable import MacCrabForensics

@Suite("PluginVisibility (residue classifier)")
struct PluginVisibilityTests {

    static let builtins: Set<String> = ["com.maccrab.forensics.mail", "com.maccrab.enricher.geoip-asn"]

    @Test("the on-device residue ids (com.acme.* + the rehearsal hosts-collector) are all residue")
    func residueIds() {
        #expect(PluginVisibility.isResidue(pluginID: "com.acme.tool", builtinIDs: Self.builtins))
        #expect(PluginVisibility.isResidue(pluginID: "com.acme.heartbeat", builtinIDs: Self.builtins))
        #expect(PluginVisibility.isResidue(pluginID: "com.maccrab.hosts-collector", builtinIDs: Self.builtins))
        // hosts-collector is caught even WITHOUT the built-in set (explicit denylist).
        #expect(PluginVisibility.isResidue(pluginID: "com.maccrab.hosts-collector"))
    }

    @Test("registered built-ins + a real third-party vendor stay visible")
    func legitVisible() {
        #expect(PluginVisibility.isOperatorVisible(pluginID: "com.maccrab.forensics.mail", builtinIDs: Self.builtins))
        #expect(PluginVisibility.isOperatorVisible(pluginID: "com.contoso.scanner", builtinIDs: Self.builtins))
    }

    @Test("positive rule: an unregistered com.maccrab.* impersonator is residue when the built-in set is known")
    func positiveRule() {
        #expect(PluginVisibility.isResidue(pluginID: "com.maccrab.evil", builtinIDs: Self.builtins))
        // Without a known built-in set the positive rule is OFF (don't false-hide a
        // future legit first-party id); the denylist still governs.
        #expect(!PluginVisibility.isResidue(pluginID: "com.maccrab.somethingnew", builtinIDs: []))
    }

    @Test(".json trust entries + fixtures + test vendors are residue")
    func nonPlugins() {
        #expect(PluginVisibility.isResidue(pluginID: "trusted-keys.json"))
        #expect(PluginVisibility.isResidue(pluginID: "com.x.scanner-fixture"))
        #expect(PluginVisibility.isResidue(pluginID: "com.test.daemon"))
    }

    @Test("filterInstalled drops residue, keeps the real third-party")
    func filterInstalled() {
        let installed = [
            InstalledPlugin(pluginID: "com.acme.tool", installRoot: "/x", publicKeyHex: "a"),
            InstalledPlugin(pluginID: "com.maccrab.hosts-collector", installRoot: "/x", publicKeyHex: "b"),
            InstalledPlugin(pluginID: "com.contoso.scanner", installRoot: "/x", publicKeyHex: "c"),
        ]
        let visible = PluginVisibility.filterInstalled(installed, builtinIDs: Self.builtins)
        #expect(visible.map { $0.pluginID } == ["com.contoso.scanner"])
    }
}
