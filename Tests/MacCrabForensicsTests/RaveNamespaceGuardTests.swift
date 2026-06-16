// RaveNamespaceGuard (C-F) — client-side impersonation defense: reserve the
// com.maccrab.* id namespace for first-party plugins + flag confusable names.

import Testing
import Foundation
@testable import MacCrabForensics

@Suite("RaveNamespaceGuard (C-F impersonation defense)")
struct RaveNamespaceGuardTests {

    private let firstPartyNames = ["MacCrab iMessage Collector", "AppleScript Runtime", "TCC Grants"]

    @Test("reserved namespace detection is case-insensitive")
    func reservedDetection() {
        #expect(RaveNamespaceGuard.isReservedNamespace("com.maccrab.forensics.x"))
        #expect(RaveNamespaceGuard.isReservedNamespace("COM.MacCrab.x"))
        #expect(!RaveNamespaceGuard.isReservedNamespace("com.example.maccrab-helper"))
    }

    @Test("non-first-party claiming com.maccrab.* is impersonation")
    func reservedImpersonation() {
        let v = RaveNamespaceGuard.evaluate(
            id: "com.maccrab.forensics.evil", displayName: "Evil",
            isFirstParty: false, firstPartyDisplayNames: firstPartyNames)
        #expect(v == .reservedNamespaceImpersonation(id: "com.maccrab.forensics.evil"))
    }

    @Test("first-party using com.maccrab.* is allowed (not flagged)")
    func firstPartyReservedOK() {
        let v = RaveNamespaceGuard.evaluate(
            id: "com.maccrab.forensics.tcc", displayName: "TCC Grants",
            isFirstParty: true, firstPartyDisplayNames: firstPartyNames)
        #expect(v == .ok)
    }

    @Test("confusable display name (homoglyph / spacing / 1-edit) is flagged")
    func confusableNames() {
        // homoglyph 4→a + the rest normalizes to the first-party key
        let h = RaveNamespaceGuard.evaluate(id: "com.x.a", displayName: "MacCr4b iMessage Collector",
            isFirstParty: false, firstPartyDisplayNames: firstPartyNames)
        #expect(h == .confusableDisplayName(name: "MacCr4b iMessage Collector", matchesFirstParty: "MacCrab iMessage Collector"))
        // punctuation/spacing stripped → exact normalized match
        let p = RaveNamespaceGuard.evaluate(id: "com.x.b", displayName: "Mac-Crab  iMessage!Collector",
            isFirstParty: false, firstPartyDisplayNames: firstPartyNames)
        if case .confusableDisplayName = p {} else { Issue.record("expected confusable, got \(p)") }
        // 1-edit away
        let e = RaveNamespaceGuard.evaluate(id: "com.x.c", displayName: "AppleScript Runtimes",
            isFirstParty: false, firstPartyDisplayNames: firstPartyNames)
        if case .confusableDisplayName = e {} else { Issue.record("expected confusable, got \(e)") }
    }

    @Test("C-F Unicode: Cyrillic / Greek / fullwidth homoglyph names are flagged confusable")
    func unicodeConfusables() {
        // Cyrillic а,С,r,а look-alikes for "MacCrab iMessage Collector".
        let cyr = RaveNamespaceGuard.evaluate(
            id: "com.x.cyr", displayName: "Mа\u{0441}Crab iMessage Collector",
            isFirstParty: false, firstPartyDisplayNames: firstPartyNames)
        if case .confusableDisplayName = cyr {} else { Issue.record("expected confusable (Cyrillic), got \(cyr)") }
        // Fullwidth Latin "ＡｐｐｌｅＳｃｒｉｐｔ Ｒｕｎｔｉｍｅ".
        let fw = RaveNamespaceGuard.evaluate(
            id: "com.x.fw", displayName: "\u{FF21}\u{FF50}\u{FF50}\u{FF4C}\u{FF45}\u{FF33}\u{FF43}\u{FF52}\u{FF49}\u{FF50}\u{FF54} \u{FF32}\u{FF55}\u{FF4E}\u{FF54}\u{FF49}\u{FF4D}\u{FF45}",
            isFirstParty: false, firstPartyDisplayNames: firstPartyNames)
        if case .confusableDisplayName = fw {} else { Issue.record("expected confusable (fullwidth), got \(fw)") }
        // Greek ο look-alike inside "TCC Grants" is distinct enough; use a Greek-folded "TCC Grαnts".
        let gr = RaveNamespaceGuard.evaluate(
            id: "com.x.gr", displayName: "TCC Gr\u{03B1}nts",
            isFirstParty: false, firstPartyDisplayNames: firstPartyNames)
        if case .confusableDisplayName = gr {} else { Issue.record("expected confusable (Greek), got \(gr)") }
    }

    @Test("a genuinely distinct third-party name is OK")
    func distinctNameOK() {
        let v = RaveNamespaceGuard.evaluate(id: "com.acme.scanner", displayName: "Acme Disk Scanner",
            isFirstParty: false, firstPartyDisplayNames: firstPartyNames)
        #expect(v == .ok)
    }

    @Test("a confusable name from a FIRST-PARTY entry is never flagged")
    func firstPartyNeverFlagged() {
        let v = RaveNamespaceGuard.evaluate(id: "com.maccrab.forensics.imsg", displayName: "MacCrab iMessage Collector",
            isFirstParty: true, firstPartyDisplayNames: firstPartyNames)
        #expect(v == .ok)
    }

    @Test("edit distance basics")
    func editDistance() {
        #expect(RaveNamespaceGuard.editDistance("abc", "abc") == 0)
        #expect(RaveNamespaceGuard.editDistance("abc", "abd") == 1)
        #expect(RaveNamespaceGuard.editDistance("abc", "axyc") == 2)
        #expect(RaveNamespaceGuard.editDistance("", "abc") == 3)
    }
}
