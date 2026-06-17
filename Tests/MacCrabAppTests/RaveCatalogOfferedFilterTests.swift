// RaveCatalogOfferedFilterTests — Owner-issue-2 (completeness) for the storefront
// DISPLAY filter.
//
// The catalog browser must show EXACTLY the entries the store offers as
// installable apps — `status == "active"` — mirroring the website's go-live
// filter. The honesty bug this guards against is BOTH directions:
//   * a pre-release / placeholder / official-but-not-active entry leaking into
//     the browse grid (showing an app that isn't actually offered), and
//   * an active entry being dropped (hiding a real offering).
//
// `offeredEntries` lived as a private computed var inside V2RaveCatalogBrowserView
// (a SwiftUI View — not unit-testable). It was extracted to a tiny PURE helper,
// `RaveCatalogClient.offeredEntries(_:)`, which the view's computed var now calls,
// so this test exercises the SAME code path the production storefront renders.
//
// Issue 2 framing: we assert set(output) == set(active subset) EXACTLY (nothing
// extra, nothing dropped), and that the empty/deny space is complete (0 active →
// [] drives the ComingSoon panel; no non-active status — pre-release, official,
// draft, "" — is ever included).
//
// Mutation note: if the filter regressed to `status != "pre-release"` (a tempting
// "show everything that isn't pre-release" bug), `excludesEveryNonActiveStatus`
// FAILS because official/draft/empty would leak in. If it inverted to drop
// active, `outputIsExactlyTheActiveSubset` FAILS.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabForensics

@Suite("RaveCatalogClient.offeredEntries — storefront display filter completeness")
struct RaveCatalogOfferedFilterTests {

    static func entry(_ id: String, status: String, trustTier: String = "verified-community") -> RaveCatalogEntry {
        RaveCatalogEntry(
            id: id,
            displayName: id,
            currentVersion: "1.0.0",
            channel: "official",
            trustTier: trustTier,
            signerIdentity: "x",
            signerPublicKeySHA256: "",
            status: status,
            category: "collector",
            tags: [],
            minMaccrabVersion: nil
        )
    }

    private func ids(_ entries: [RaveCatalogEntry]) -> Set<String> { Set(entries.map(\.id)) }

    @Test("output is EXACTLY the active subset — nothing extra, nothing dropped")
    func outputIsExactlyTheActiveSubset() {
        let fixture = [
            Self.entry("com.x.active-a",   status: "active"),
            Self.entry("com.x.prerelease", status: "pre-release"),
            Self.entry("com.x.official",   status: "official"),
            Self.entry("com.x.active-b",   status: "active"),
            Self.entry("com.x.draft",      status: "draft"),
            Self.entry("com.x.empty",      status: ""),
            Self.entry("com.x.active-c",   status: "active"),
        ]
        let out = RaveCatalogClient.offeredEntries(fixture)
        let expectedActive = Set(["com.x.active-a", "com.x.active-b", "com.x.active-c"])

        // Exact set equality — the inverse-completeness assertion.
        #expect(ids(out) == expectedActive)
        // No active entry was dropped.
        #expect(out.count == expectedActive.count)
        // Every emitted entry IS active (nothing non-active leaked).
        #expect(out.allSatisfy { $0.status == "active" })
    }

    @Test("zero active entries → empty output (drives the ComingSoon fallback)")
    func zeroActiveYieldsEmpty() {
        let fixture = [
            Self.entry("com.x.prerelease", status: "pre-release"),
            Self.entry("com.x.official",   status: "official"),
            Self.entry("com.x.draft",      status: "draft"),
        ]
        #expect(RaveCatalogClient.offeredEntries(fixture).isEmpty)
    }

    @Test("empty catalog → empty output")
    func emptyCatalogYieldsEmpty() {
        #expect(RaveCatalogClient.offeredEntries([]).isEmpty)
    }

    @Test("NO pre-release is ever offered — for any trust tier")
    func neverOffersPreRelease() {
        let fixture = [
            Self.entry("com.x.fp",   status: "pre-release", trustTier: "first-party"),
            Self.entry("com.x.vc",   status: "pre-release", trustTier: "verified-community"),
            Self.entry("com.x.unv",  status: "pre-release", trustTier: "unverified"),
        ]
        #expect(RaveCatalogClient.offeredEntries(fixture).isEmpty)
    }

    @Test("EVERY non-active status is excluded — exact-string match, not a 'not pre-release' shortcut")
    func excludesEveryNonActiveStatus() {
        // Each of these is NON-active and must be excluded. If the filter were
        // implemented as `status != "pre-release"`, official/draft/coming-soon/""
        // would leak — this catches that exact mutation.
        let nonActiveStatuses = ["pre-release", "official", "draft", "coming-soon",
                                 "deprecated", "ACTIVE", "Active", " active", "active ", ""]
        for s in nonActiveStatuses {
            let out = RaveCatalogClient.offeredEntries([Self.entry("com.x.one", status: s)])
            #expect(out.isEmpty, "status '\(s)' must NOT be offered (only exact 'active')")
        }
        // And exact "active" IS offered — proving the gate isn't simply always-empty.
        let active = RaveCatalogClient.offeredEntries([Self.entry("com.x.one", status: "active")])
        #expect(active.count == 1)
    }

    @Test("an all-active catalog passes through unchanged (no active is ever dropped)")
    func allActivePassesThrough() {
        let fixture = (0..<5).map { Self.entry("com.x.a\($0)", status: "active") }
        let out = RaveCatalogClient.offeredEntries(fixture)
        #expect(ids(out) == ids(fixture))
        #expect(out.count == 5)
    }
}
