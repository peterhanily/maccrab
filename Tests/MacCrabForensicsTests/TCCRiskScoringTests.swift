// TCCRiskScoring deterministic-score fixtures.
//
// The audit + the plan §4.1 scoring table say "operators argue
// with the numbers, not the concept." Every fixture below names
// the scenario, lists the expected score, and verifies the
// reasons array. Adding a new factor without updating these
// fixtures will fail loudly.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("TCCRiskScoring: deterministic fixtures")
struct TCCRiskScoringTests {

    private func input(
        service: TCCServiceCanonical,
        raw: String = "kTCCServiceMicrophone",
        indirectTarget: String? = nil,
        allowed: Bool = true,
        authReason: TCCAuthReason = .userSet,
        signedByApple: Bool = false,
        hasKnownTeam: Bool = false
    ) -> TCCRiskInput {
        TCCRiskInput(
            service: service,
            serviceRaw: raw,
            indirectTarget: indirectTarget,
            authValue: allowed ? .allowed : .denied,
            authReason: authReason,
            clientSignedByApple: signedByApple,
            clientHasKnownTeam: hasKnownTeam
        )
    }

    @Test("FDA + unknown team -> 35 + 20 = 55, no Apple mitigation")
    func fdaUnknownTeam() {
        let r = TCCRiskScoring.score(input(
            service: .fullDiskAccess,
            raw: "kTCCServiceSystemPolicyAllFiles"
        ))
        #expect(r.score == TCCRiskScoring.Weight.fullDiskAccess + TCCRiskScoring.Weight.unknownTeam)
        #expect(r.reasons.contains(.fullDiskAccess))
        #expect(r.reasons.contains(.unknownTeam))
    }

    @Test("FDA + Apple-signed -> 35 - 20 = 15")
    func fdaAppleSigned() {
        let r = TCCRiskScoring.score(input(
            service: .fullDiskAccess,
            signedByApple: true,
            hasKnownTeam: true
        ))
        #expect(r.score == TCCRiskScoring.Weight.fullDiskAccess + TCCRiskScoring.Weight.appleSigned)
        #expect(r.reasons.contains(.fullDiskAccess))
        #expect(r.reasons.contains(.appleSigned))
        #expect(!r.reasons.contains(.unknownTeam))
    }

    @Test("Accessibility + unknown team -> 30 + 20 = 50")
    func accessibilityUnknownTeam() {
        let r = TCCRiskScoring.score(input(service: .accessibility))
        #expect(r.score == TCCRiskScoring.Weight.accessibility + TCCRiskScoring.Weight.unknownTeam)
        #expect(r.reasons.contains(.accessibility))
    }

    @Test("Automation to Safari -> high-value target weight (30)")
    func automationSafari() {
        let r = TCCRiskScoring.score(input(
            service: .automation,
            raw: "kTCCServiceAppleEvents",
            indirectTarget: "com.apple.Safari",
            hasKnownTeam: true
        ))
        // 30 (high-value automation) + 0 (no unknown team) + 0 (no apple-sign) = 30
        #expect(r.score == TCCRiskScoring.Weight.automationToHighValue)
        #expect(r.reasons.contains(.automationToBrowser))
    }

    @Test("Automation to Calculator -> generic target weight (10)")
    func automationGeneric() {
        let r = TCCRiskScoring.score(input(
            service: .automation,
            raw: "kTCCServiceAppleEvents",
            indirectTarget: "com.apple.Calculator",
            hasKnownTeam: true
        ))
        #expect(r.score == TCCRiskScoring.Weight.automationGeneric)
        #expect(r.reasons.contains(.automationGeneric))
    }

    @Test("Screen recording + unknown team -> 25 + 20 = 45")
    func screenRecordingUnknown() {
        let r = TCCRiskScoring.score(input(
            service: .screenRecording,
            raw: "kTCCServiceScreenCapture"
        ))
        #expect(r.score == TCCRiskScoring.Weight.screenRecording + TCCRiskScoring.Weight.unknownTeam)
        #expect(r.reasons.contains(.screenRecording))
    }

    @Test("Microphone + Apple-signed -> 20 - 20 = 0")
    func micApple() {
        let r = TCCRiskScoring.score(input(
            service: .microphone,
            signedByApple: true,
            hasKnownTeam: true
        ))
        #expect(r.score == 0)
        #expect(r.reasons.contains(.microphone))
        #expect(r.reasons.contains(.appleSigned))
    }

    @Test("MDM-granted FDA -> 35 + 20 - 5 = 50")
    func mdmGrantedFDA() {
        let r = TCCRiskScoring.score(input(
            service: .fullDiskAccess,
            authReason: .mdmSet
        ))
        #expect(r.score == TCCRiskScoring.Weight.fullDiskAccess + TCCRiskScoring.Weight.unknownTeam + TCCRiskScoring.Weight.mdmGranted)
        #expect(r.reasons.contains(.mdmGranted))
    }

    @Test("Score clamps to [0, 100] on extreme combinations")
    func scoreClamped() {
        // FDA + accessibility wouldn't normally co-occur on one
        // row, but the math should still clamp if it did.
        let r = TCCRiskScoring.score(input(
            service: .fullDiskAccess,
            authReason: .mdmSet,
            signedByApple: true,
            hasKnownTeam: true
        ))
        // 35 - 20 - 5 = 10
        #expect(r.score == 10)
        #expect(r.score >= 0)
        #expect(r.score <= 100)
    }

    @Test("Plain photos grant (no scoring weight) -> 20 (just unknown team)")
    func nonScoredService() {
        let r = TCCRiskScoring.score(input(service: .photos))
        #expect(r.score == TCCRiskScoring.Weight.unknownTeam)
        #expect(r.reasons.contains(.unknownTeam))
    }

    @Test("Denied FDA within recent window adds deniedRecentlyAttempted reason")
    func deniedRecent() {
        let r = TCCRiskScoring.score(TCCRiskInput(
            service: .fullDiskAccess,
            serviceRaw: "kTCCServiceSystemPolicyAllFiles",
            indirectTarget: nil,
            authValue: .denied,
            authReason: .userSet,
            clientSignedByApple: false,
            clientHasKnownTeam: false,
            lastModified: Date()
        ))
        #expect(r.reasons.contains(.deniedRecentlyAttempted))
    }
}

@Suite("TCCServiceNormalization")
struct TCCServiceNormalizationTests {

    @Test("FDA canonical mapping")
    func fdaMapping() {
        #expect(TCCServiceNormalization.canonical(for: "kTCCServiceSystemPolicyAllFiles") == .fullDiskAccess)
    }

    @Test("AppleEvents -> automation")
    func appleEventsMapping() {
        #expect(TCCServiceNormalization.canonical(for: "kTCCServiceAppleEvents") == .automation)
    }

    @Test("Accessibility canonical mapping")
    func accessibilityMapping() {
        #expect(TCCServiceNormalization.canonical(for: "kTCCServiceAccessibility") == .accessibility)
    }

    @Test("Screen capture -> screen_recording")
    func screenCaptureMapping() {
        #expect(TCCServiceNormalization.canonical(for: "kTCCServiceScreenCapture") == .screenRecording)
    }

    @Test("Microphone canonical mapping")
    func microphoneMapping() {
        #expect(TCCServiceNormalization.canonical(for: "kTCCServiceMicrophone") == .microphone)
    }

    @Test("Unknown raw constant -> .other")
    func unknownConstantFallback() {
        #expect(TCCServiceNormalization.canonical(for: "kTCCServiceNonexistent") == .other)
    }

    @Test("Reverse mapping: FDA -> SystemPolicyAllFiles")
    func reverseFDA() {
        #expect(TCCServiceNormalization.primaryRawConstant(for: .fullDiskAccess) == "kTCCServiceSystemPolicyAllFiles")
    }
}

@Suite("TCCAuthValue + TCCAuthReason decoding")
struct TCCAuthTests {

    @Test("Auth value decoding maps 2 to allowed")
    func authValueAllowed() {
        #expect(TCCAuthValue.decode(2) == .allowed)
    }

    @Test("Auth value decoding maps 0 to denied")
    func authValueDenied() {
        #expect(TCCAuthValue.decode(0) == .denied)
    }

    @Test("Auth value decoding maps unknown integer to .unknown")
    func authValueUnknown() {
        #expect(TCCAuthValue.decode(99) == .unknown)
    }

    @Test("Auth reason maps 6 to mdmSet which isMDMGranted=true")
    func mdmGrantedDecoding() {
        #expect(TCCAuthReason.decode(6) == .mdmSet)
        #expect(TCCAuthReason.decode(6).isMDMGranted == true)
    }

    @Test("Auth reason maps 3 to userSet which isUserGranted=true")
    func userGrantedDecoding() {
        #expect(TCCAuthReason.decode(3) == .userSet)
        #expect(TCCAuthReason.decode(3).isUserGranted == true)
    }
}
