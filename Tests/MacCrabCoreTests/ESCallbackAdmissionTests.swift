import Darwin
import EndpointSecurity
import Testing
@testable import MacCrabCore

@Suite("ES callback-to-worker admission")
struct ESCallbackAdmissionTests {
    private func dynamicRegistry(
        _ snapshot: DynamicAIFileEventDemandSnapshot
    ) -> FileEventInterestPolicyRegistry {
        let registry = FileEventInterestPolicyRegistry()
        _ = registry.install(FileEventInterestDescriptorSnapshot(
            singleEventRules: [],
            sequenceRules: [],
            graphRules: [],
            builtinRequirements: [BuiltinFileEventRequirement(
                id: "test.dynamic-ai-open",
                sources: [.endpointSecurityFile],
                kind: .dynamicAIConsumers
            )]
        ))
        #expect(registry.publishDynamicAI(snapshot))
        return registry
    }

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

    @Test("fresh AI demand retains useful text OPENs without retaining temp binary churn")
    func dynamicAITextOpenAdmission() {
        let registry = dynamicRegistry(.currentCanonical(
            validUntilUptimeNanoseconds: UInt64.max,
            sessions: [DynamicAIFileEventSession(
                rootProcessID: 42,
                childProcessIDs: [43],
                projectRoots: ["/Users/x/project"]
            )]
        ))

        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: "/Users/x/project/README.md",
            processID: 43,
            dynamicAIRegistry: registry
        ))
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: "/private/var/folders/hf/cache.bin",
            processID: 43,
            dynamicAIRegistry: registry
        ))
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: "/Users/x/project/README.md",
            processID: 99,
            dynamicAIRegistry: registry
        ))
    }

    @Test("unknown dynamic state fails open but never bypasses platform keychain drop")
    func dynamicAIFailOpenPreservesKeychainGate() {
        let registry = dynamicRegistry(.unknown)
        #expect(!ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: "/Users/x/project/README.md",
            processID: 42,
            dynamicAIRegistry: registry
        ))
        #expect(ESCollector.shouldDropBeforeWorker(
            eventType: ES_EVENT_TYPE_NOTIFY_OPEN.rawValue,
            path: "/Users/x/Library/Keychains/login.keychain-db",
            isPlatformBinary: true,
            processID: 42,
            dynamicAIRegistry: registry
        ))
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

    // v1.21.7. SETMODE hit `default: return false`, so every chmod on the host
    // was admitted. On an installed rc.7 host that was 35% of all stored events
    // — the largest single category — almost entirely `python3.12` setting
    // 0600/0644 on files it had just created under /private/var/folders/…/T/.
    // A mode change that grants neither execution nor escalation cannot enable
    // anything a rule acts on.
    @Test("chmod granting execute or setuid/setgid is kept; a permissions-only chmod is dropped")
    func setmodeAdmissionKeepsOnlyCapabilityGrants() {
        // The half that MUST survive — download → chmod +x → execute.
        for mode: UInt32 in [0o755, 0o700, 0o111, 0o4755, 0o2755, 0o4644] {
            #expect(!ESCollector.shouldDropBeforeWorker(
                eventType: ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue,
                path: "/private/var/folders/hf/T/payload",
                mode: mode
            ), "chmod \(String(mode, radix: 8)) confers execution or escalation and must be kept")
        }

        // The 35%: tidy-up chmod that confers nothing.
        for mode: UInt32 in [0o600, 0o644, 0o664, 0o666, 0o400, 0o1666] {
            #expect(ESCollector.shouldDropBeforeWorker(
                eventType: ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue,
                path: "/private/var/folders/hf/T/artifactforge-snapshot/x.xml",
                mode: mode
            ), "chmod \(String(mode, radix: 8)) confers no capability and must be dropped")
        }
    }

    // The filter is mode-based ON PURPOSE. A temp-path allowlist would have been
    // the obvious way to kill the same volume, and it would have dropped
    // `chmod +x` on a payload staged in exactly that directory — the event most
    // worth keeping. Malware writing to a temp directory is the normal case.
    @Test("execute grants survive in every location, including the noisy temp paths")
    func setmodeFilterIsModeBasedNotPathBased() {
        for path in [
            "/private/var/folders/ab/c0ffeec0ffeec0ffeec0ffeec0000gn/T/dropper/payload",
            "/tmp/payload",
            "/Users/someone/Downloads/installer",
            "/private/var/log/payload"
        ] {
            #expect(!ESCollector.shouldDropBeforeWorker(
                eventType: ES_EVENT_TYPE_NOTIFY_SETMODE.rawValue,
                path: path,
                mode: 0o755
            ), "chmod +x must survive at \(path)")
        }
    }

    @Test("the sticky bit alone is not a capability grant")
    func stickyBitIsNotEscalation() {
        // S_ISVTX restricts deletion within a directory; it grants the caller
        // nothing, so it must not by itself hold an event in the store.
        #expect(ESCollector.modeGrantsExecutionOrEscalation(0o1666) == false)
        #expect(ESCollector.modeGrantsExecutionOrEscalation(0o1777) == true)   // has +x
        #expect(ESCollector.modeGrantsExecutionOrEscalation(0) == false)
    }
}
