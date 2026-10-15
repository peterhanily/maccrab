import Foundation
import Testing
@testable import MacCrabApp

/// Pure admission/retention bookkeeping only: no reader, store, timer, clock
/// sampling or filesystem access. Every clock boundary is supplied explicitly.
@Suite("Events reader idle-retention policy")
struct EventReaderIdleRetentionPolicyTests {
    @Test("Admission accounts for queued reads and closes before any idle certificate")
    func queuedReadsPreventCertification() throws {
        var policy = EventReaderIdleRetention()
        let firstAdmission = policy.admit(), secondAdmission = policy.admit()
        let first = try #require(firstAdmission), second = try #require(secondAdmission)
        #expect(first != second && policy.admittedReadCount == 2)
        // Neither lease needs to have reached the reader actor yet: both are
        // already work that prevents retention of a supposedly idle reader.
        let pause = policy.closeAdmission(now: 100)
        #expect(pause == nil && !policy.acceptsReads)
        let refused = policy.admit()
        #expect(refused == nil && policy.admittedReadCount == 2)
        policy.finish(first)
        #expect(policy.admittedReadCount == 1)
        policy.finish(second)
        #expect(policy.admittedReadCount == 0)
        let reusable = policy.resume(now: 101)
        #expect(!reusable, "Finishing old work cannot invent an idle certificate")
        #expect(policy.acceptsReads)
    }

    @Test("Pending or negative idle certification cannot authorize cache reuse", arguments: [false, true])
    func missingOrFalseCertificateFailsClosed(attemptCertificate: Bool) throws {
        var policy = EventReaderIdleRetention()
        let closed = policy.closeAdmission(now: 100)
        let token = try #require(closed)
        let refused = policy.admit()
        #expect(policy.matches(token) && refused == nil)
        if attemptCertificate {
            let certified = policy.certify(token, idle: false, now: 101)
            #expect(!certified)
        }
        let reusable = policy.resume(now: 102)
        #expect(!reusable)
        #expect(policy.acceptsReads && !policy.matches(token))
        let delayed = policy.certify(token, idle: true, now: 103)
        #expect(!delayed, "A delayed completion cannot certify a resumed session")
    }

    @Test("Certified reuse is strictly before the exact 60-second boundary")
    func strictIdleDeadline() throws {
        #expect(EventReaderIdleRetention.maximumIdleSeconds == 60)
        for offset in [0.0, 59.999, 60.0, 60.001] {
            var policy = EventReaderIdleRetention()
            let closed = policy.closeAdmission(now: 100)
            let token = try #require(closed)
            #expect(token.startedAt == 100 && token.deadline == 160)
            let certified = policy.certify(token, idle: true, now: 100)
            #expect(certified)
            #expect(policy.expirationDue(token, now: 100 + offset) == (offset >= 60))
            let reusable = policy.resume(now: 100 + offset)
            #expect(reusable == (offset < 60))
            #expect(policy.acceptsReads && !policy.matches(token))
        }
        var late = EventReaderIdleRetention()
        let closed = late.closeAdmission(now: 100)
        let token = try #require(closed)
        let lateCertified = late.certify(token, idle: true, now: 160)
        let lateReusable = late.resume(now: 160)
        #expect(!lateCertified && !lateReusable)
    }

    @Test("Reversed and nonfinite clocks cannot certify or retain a reader")
    func invalidObservationTimesFailClosed() throws {
        for invalidNow in [99.0, Double.nan, Double.infinity, -Double.infinity] {
            var pending = EventReaderIdleRetention()
            let pendingPause = pending.closeAdmission(now: 100)
            let pendingToken = try #require(pendingPause)
            let invalidCertificate = pending.certify(pendingToken, idle: true, now: invalidNow)
            #expect(!invalidCertificate)
            #expect(pending.expirationDue(pendingToken, now: invalidNow))
            let pendingReusable = pending.resume(now: invalidNow)
            #expect(!pendingReusable)

            var certified = EventReaderIdleRetention()
            let certifiedPause = certified.closeAdmission(now: 100)
            let certifiedToken = try #require(certifiedPause)
            let initialCertificate = certified.certify(certifiedToken, idle: true, now: 100)
            #expect(initialCertificate)
            #expect(certified.expirationDue(certifiedToken, now: invalidNow))
            let certifiedReusable = certified.resume(now: invalidNow)
            #expect(!certifiedReusable)
        }
    }

    @Test("A failed recertification cannot retain an earlier successful certificate")
    func failedRecertificationClearsSuccess() throws {
        for (idle, observedAt) in [(false, 101.0), (true, 99.0), (true, Double.nan)] {
            var policy = EventReaderIdleRetention()
            let closed = policy.closeAdmission(now: 100)
            let token = try #require(closed)
            let first = policy.certify(token, idle: true, now: 100)
            #expect(first)
            let failed = policy.certify(token, idle: idle, now: observedAt)
            #expect(!failed)
            let reusable = policy.resume(now: 102)
            #expect(!reusable, "A later ordinary idle observation must supersede earlier certification")
        }
    }

    @Test("An invalid pause time closes admission without creating a reusable token")
    func invalidPauseTimesFailClosed() {
        for invalidNow in [-1.0, Double.nan, Double.infinity, -Double.infinity, Double.greatestFiniteMagnitude] {
            var policy = EventReaderIdleRetention()
            let closed = policy.closeAdmission(now: invalidNow)
            #expect(closed == nil)
            let refused = policy.admit()
            #expect(!policy.acceptsReads && refused == nil)
            let reusable = policy.resume(now: 100)
            #expect(!reusable)
            #expect(policy.acceptsReads)
        }
    }

    @Test("Repeated background notifications cannot extend the original deadline")
    func repeatedPauseDoesNotExtendDeadline() throws {
        var policy = EventReaderIdleRetention()
        let closed = policy.closeAdmission(now: 100)
        let token = try #require(closed)
        let certified = policy.certify(token, idle: true, now: 100)
        #expect(certified)
        let repeated = policy.closeAdmission(now: 150)
        #expect(repeated == nil)
        #expect(policy.matches(token))
        #expect(!policy.expirationDue(token, now: 159))
        #expect(policy.expirationDue(token, now: 160))
        let reusable = policy.resume(now: 160)
        #expect(!reusable)
    }

    @Test("Source invalidation and replacement reject old certificates and expiration callbacks")
    func invalidationRejectsOldTokens() throws {
        var policy = EventReaderIdleRetention()
        let closed = policy.closeAdmission(now: 100)
        let old = try #require(closed)
        let certified = policy.certify(old, idle: true, now: 100)
        #expect(certified)
        policy.invalidate()
        #expect(!policy.acceptsReads && !policy.matches(old))
        let invalidatedCertificate = policy.certify(old, idle: true, now: 101)
        #expect(!invalidatedCertificate)
        #expect(!policy.expirationDue(old, now: 200))
        let invalidatedReusable = policy.resume(now: 101)
        #expect(!invalidatedReusable)
        let replacementPause = policy.closeAdmission(now: 101)
        let replacement = try #require(replacementPause)
        #expect(old != replacement && policy.matches(replacement))
        let staleCertificate = policy.certify(old, idle: true, now: 102)
        #expect(!staleCertificate)
        #expect(!policy.expirationDue(old, now: 200))
        let freshCertificate = policy.certify(replacement, idle: true, now: 102)
        let freshReusable = policy.resume(now: 103)
        #expect(freshCertificate && freshReusable)
    }

    @Test("Old completions cannot release replacement-reader admissions")
    func invalidationPreservesOutstandingLeaseIdentity() throws {
        var policy = EventReaderIdleRetention()
        let admittedOld = policy.admit()
        let old = try #require(admittedOld)
        let oldPause = policy.closeAdmission(now: 100)
        #expect(oldPause == nil)
        policy.invalidate()
        #expect(policy.admittedReadCount == 1)
        let oldReusable = policy.resume(now: 101)
        #expect(!oldReusable)
        let admittedNew = policy.admit()
        let replacement = try #require(admittedNew)
        #expect(old != replacement && policy.admittedReadCount == 2)
        policy.finish(old)
        #expect(policy.admittedReadCount == 1)
        let replacementPause = policy.closeAdmission(now: 102)
        #expect(replacementPause == nil,
                "Replacement admission must still prevent an idle pause after the old reader completes")
        policy.finish(replacement)
        #expect(policy.admittedReadCount == 0)
        let replacementReusable = policy.resume(now: 103)
        #expect(!replacementReusable)
        let idlePause = policy.closeAdmission(now: 104)
        let idle = try #require(idlePause)
        let idleCertified = policy.certify(idle, idle: true, now: 104)
        let idleReusable = policy.resume(now: 105)
        #expect(idleCertified && idleReusable)
    }
}
