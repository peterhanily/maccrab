import Darwin
import EndpointSecurity
import Testing
@testable import MacCrabCore

@Suite("ES callback-to-worker admission")
struct ESCallbackAdmissionTests {
    @Test("ordinary OPEN and unmodified CLOSE never consume worker slots")
    func rejectsTheMeasuredFirehose() {
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: "/usr/lib/libSystem.B.dylib"
        ))
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue,
            path: "/Users/x/project/Sources/main.swift",
            closeModified: false
        ))
    }

    @Test("credential and agent-content OPEN coverage survives callback admission")
    func keepsDetectionRelevantOpens() {
        let kept = [
            "/Users/x/.ssh/id_ed25519",
            "/Users/x/.claude/skills/reviewer/SKILL.md",
            "/Users/x/project/.github/workflows/ci.yml",
        ]
        for path in kept {
            #expect(!ESCollector.shouldDropBeforeWorker(
                eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
                path: path
            ), "callback rejected detection-relevant OPEN: \(path)")
        }
    }

    @Test("platform keychain noise drops but non-platform keychain access survives")
    func keychainPlatformGateParity() {
        let keychain = "/Users/x/Library/Keychains/login.keychain-db"
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: keychain,
            isPlatformBinary: true
        ))
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: keychain,
            isPlatformBinary: false
        ))
    }

    @Test("modified write-family uses the existing conservative log guard")
    func writeFamilyParity() {
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_WRITE.rawValue,
            path: "/private/var/log/service.log"
        ))
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_WRITE.rawValue,
            path: "/Users/x/.ssh/authorized_keys"
        ))
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue,
            path: "/Users/x/project/Sources/main.swift",
            closeModified: true
        ))
    }

    @Test("platform introspection and non-W+X memory events drop before enqueue")
    func cheapBitAndSignerGatesMoveToAdmission() {
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_GET_TASK_READ.rawValue,
            isPlatformBinary: true
        ))
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_GET_TASK_READ.rawValue,
            isPlatformBinary: false
        ))
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_MPROTECT.rawValue,
            protection: Int32(PROT_READ | PROT_EXEC)
        ))
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_MPROTECT.rawValue,
            protection: Int32(PROT_READ | PROT_WRITE | PROT_EXEC)
        ))
    }

    @Test("unrelated event types default to keep")
    func defaultIsDetectionConservative() {
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_EXEC.rawValue
        ))
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_CREATE.rawValue,
            path: "/private/var/log/payload"
        ))
    }
}
