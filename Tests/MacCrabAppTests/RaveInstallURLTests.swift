// RaveInstallLink (O3c / S2-07) URL-handler parser tests.
//
// SECURITY CONTRACT under test: the maccrab://install/... handler accepts an
// ID ONLY. Any link that smuggles a digest, URL, path, version, query item,
// fragment, port, or extra path segment is REJECTED (parse returns nil → the
// handler installs nothing). Valid links resolve to a (kind, id) pair and the
// id has passed strict validation. Parsing itself never installs — the only
// path to install is the consent sheet, gated on RaveInstallConsentFacts.canConfirm.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabForensics

@Suite("RaveInstallLink (S2-07 install URL handler)")
struct RaveInstallURLTests {

    private func parse(_ s: String) -> RaveInstallLink? {
        guard let url = URL(string: s) else { return nil }
        return RaveInstallLink.parse(url)
    }

    // MARK: - Accepts well-formed id-only links

    @Test("accepts plugin id-only link")
    func acceptsPlugin() throws {
        let link = try #require(parse("maccrab://install/plugin/com.maccrab.hosts-collector"))
        #expect(link.kind == .plugin)
        #expect(link.id == "com.maccrab.hosts-collector")
    }

    @Test("accepts kit id-only link")
    func acceptsKit() throws {
        let link = try #require(parse("maccrab://install/kit/com.maccrab.kit.ir-quick"))
        #expect(link.kind == .kit)
        #expect(link.id == "com.maccrab.kit.ir-quick")
    }

    // MARK: - Rejects non-id payloads (the whole point)

    @Test("rejects a smuggled query (digest / version / url)")
    func rejectsQuery() {
        #expect(parse("maccrab://install/plugin/com.maccrab.x?digest=deadbeef") == nil)
        #expect(parse("maccrab://install/plugin/com.maccrab.x?version=9.9.9") == nil)
        #expect(parse("maccrab://install/plugin/com.maccrab.x?url=https://evil.example/x.zip") == nil)
    }

    @Test("rejects a fragment")
    func rejectsFragment() {
        #expect(parse("maccrab://install/plugin/com.maccrab.x#frag") == nil)
    }

    @Test("rejects extra path segments (no embedded path/url)")
    func rejectsExtraSegments() {
        #expect(parse("maccrab://install/plugin/com.maccrab.x/extra") == nil)
        #expect(parse("maccrab://install/plugin") == nil)        // missing id
        #expect(parse("maccrab://install/plugin/") == nil)       // empty id
        #expect(parse("maccrab://install") == nil)               // no kind/id
    }

    @Test("rejects path traversal / separators in the id")
    func rejectsTraversal() {
        #expect(parse("maccrab://install/plugin/..") == nil)
        #expect(parse("maccrab://install/plugin/%2e%2e") == nil)         // ".." percent-encoded
        #expect(parse("maccrab://install/plugin/a%2Fb") == nil)          // embedded slash
        #expect(parse("maccrab://install/plugin/.hidden") == nil)        // leading dot
    }

    @Test("rejects unknown kind")
    func rejectsUnknownKind() {
        #expect(parse("maccrab://install/binary/com.maccrab.x") == nil)
        #expect(parse("maccrab://install/script/com.maccrab.x") == nil)
    }

    @Test("rejects userinfo / port authority")
    func rejectsAuthorityExtras() {
        #expect(parse("maccrab://user:pass@install/plugin/com.maccrab.x") == nil)
        #expect(parse("maccrab://install:8080/plugin/com.maccrab.x") == nil)
    }

    @Test("rejects wrong scheme / host")
    func rejectsWrongSchemeOrHost() {
        #expect(parse("https://install/plugin/com.maccrab.x") == nil)
        #expect(parse("maccrab://alerts/plugin/com.maccrab.x") == nil)  // host != install
    }

    // MARK: - Consent gating (no silent install)

    @Test("consent facts gate confirm on the version floor")
    func consentGatesConfirm() {
        // Floor passed → confirm allowed.
        let ok = RaveInstallConsentFacts(
            kind: .plugin, id: "com.maccrab.x", displayName: "x",
            resolvedVersion: "1.0.0", signerPublicKeySHA256: "",
            signerIdentity: "maccrab-rave:first-party", trustTier: "first-party",
            declaredMinVersion: "1.17.0", versionFloorRefusal: nil, officialSource: true
        )
        #expect(ok.canConfirm)
        #expect(ok.verifiedInstallCommand == "maccrabctl plugin install com.maccrab.x")

        // Floor refused → confirm blocked.
        let blocked = RaveInstallConsentFacts(
            kind: .plugin, id: "com.maccrab.y", displayName: "y",
            resolvedVersion: "1.0.0", signerPublicKeySHA256: "",
            signerIdentity: "", trustTier: "unverified",
            declaredMinVersion: "9.9.9",
            versionFloorRefusal: "requires MacCrab 9.9.9 or newer", officialSource: true
        )
        #expect(!blocked.canConfirm)
    }
}
