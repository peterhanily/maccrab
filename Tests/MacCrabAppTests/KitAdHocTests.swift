// Kit.adHoc — the ephemeral 1-plugin kit that lets the catalog's "Run on this
// Mac" drive the existing KitRunner with no new run path. Pinning its shape:
// a wrong plugin id or a dropped encrypted flag would silently run the wrong
// scanner or drop personal-comms rows into a plaintext case.

import Testing
import Foundation
@testable import MacCrabApp

@Suite("Kit.adHoc — single-scanner ephemeral kit")
struct KitAdHocTests {

    @Test("wraps exactly one plugin id and carries it through")
    func wrapsOnePlugin() {
        let k = Kit.adHoc(pluginID: "com.maccrab.forensics.tcc-lite",
                          name: "Privacy permissions", encrypted: false)
        #expect(k.plugins.count == 1)
        #expect(k.plugins.first?.pluginID == "com.maccrab.forensics.tcc-lite")
        #expect(k.name == "Privacy permissions")
    }

    @Test("propagates the encrypted flag both ways")
    func propagatesEncrypted() {
        #expect(Kit.adHoc(pluginID: "x", name: "X", encrypted: true).encrypted == true)
        #expect(Kit.adHoc(pluginID: "x", name: "X", encrypted: false).encrypted == false)
    }

    @Test("ad-hoc kit id is namespaced + deterministic for a given plugin")
    func deterministicID() {
        let a = Kit.adHoc(pluginID: "com.maccrab.forensics.mail", name: "Mail", encrypted: true)
        let b = Kit.adHoc(pluginID: "com.maccrab.forensics.mail", name: "Mail", encrypted: true)
        #expect(a.id == b.id)
        #expect(a.id.contains("com.maccrab.forensics.mail"))
    }
}
