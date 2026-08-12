import Foundation
import Testing
@testable import MacCrabCore

@Suite("Event journal admission validator")
struct EventJournalAdmissionValidatorTests {
    private let fixedID = UUID(
        uuidString: "00112233-4455-6677-8899-AABBCCDDEEFF"
    )!
    private let fixedTime = Date(timeIntervalSince1970: 1_700_000_000.25)

    private func richEvent(
        action: String = "connect",
        commandLine: String = "/usr/bin/curl --token raw-secret",
        args: [String] = ["/usr/bin/curl", "--token", "raw-secret"],
        userName: String = "alice",
        envVars: [String: String]? = ["TOKEN": "raw-secret"],
        enrichments: [String: String] = ["late": "one"],
        severity: Severity = .high,
        ruleMatches: [RuleMatch] = []
    ) -> Event {
        Event(
            id: fixedID,
            timestamp: fixedTime,
            eventCategory: .network,
            eventType: .connection,
            eventAction: action,
            process: ProcessInfo(
                pid: 42,
                ppid: 1,
                rpid: 42,
                name: "curl",
                executable: "/usr/bin/curl",
                commandLine: commandLine,
                args: args,
                workingDirectory: "/private/tmp",
                userId: 501,
                userName: userName,
                groupId: 20,
                startTime: Date(timeIntervalSince1970: 1_699_999_999.5),
                exitCode: 7,
                codeSignature: CodeSignatureInfo(
                    signerType: .devId,
                    teamId: "ABCDEFGHIJ",
                    signingId: "com.example.fixture",
                    authorities: ["Fixture CA"],
                    flags: 1,
                    isNotarized: true
                ),
                ancestors: [
                    ProcessAncestor(
                        pid: 1,
                        executable: "/sbin/launchd",
                        name: "launchd"
                    ),
                ],
                architecture: "arm64",
                isPlatformBinary: false,
                hashes: ProcessHashes(
                    sha256: String(repeating: "a", count: 64),
                    cdhash: String(repeating: "b", count: 40),
                    md5: String(repeating: "c", count: 32)
                ),
                session: SessionInfo(
                    sessionId: 123,
                    tty: "/dev/ttys001",
                    loginUser: "alice",
                    sshRemoteIP: "10.0.0.5",
                    launchSource: .ssh
                ),
                envVars: envVars,
                auditIdentity: AuditIdentity(
                    auid: 501,
                    euid: 502,
                    egid: 20,
                    ruid: 501,
                    rgid: 20,
                    pid: 42,
                    pidversion: 9,
                    asid: 77
                )
            ),
            file: FileInfo(
                path: "/private/tmp/a.txt",
                name: "a.txt",
                directory: "/private/tmp",
                extension_: "txt",
                size: 99,
                action: .write,
                sourcePath: "/private/tmp/old.txt"
            ),
            network: NetworkInfo(
                sourceIp: "10.0.0.5",
                sourcePort: 54_321,
                destinationIp: "203.0.113.8",
                destinationPort: 443,
                destinationHostname: "example.test",
                direction: .outbound,
                transport: "tcp"
            ),
            tcc: TCCInfo(
                service: "kTCCServiceCamera",
                client: "com.example.client",
                clientPath: "/Applications/Client.app",
                allowed: true,
                authReason: "user_consent"
            ),
            enrichments: enrichments,
            severity: severity,
            ruleMatches: ruleMatches
        )
    }

    private func hex(_ bytes: Data) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    @Test("raw immutable source identity has a cross-build golden vector")
    func sourceIdentityGoldenVector() {
        let digest = EventJournalAdmissionValidator.sourceIdentityDigest(
            richEvent()
        )
        #expect(digest.count == 32)
        #expect(
            hex(digest)
                == "346d6d05efd5236d3f78eeb08f67f1a21d135c564db42d639e0e81f21f1bf700"
        )
    }

    @Test("source identity excludes late mutable fields and includes source")
    func sourceIdentityFieldContract() throws {
        let base = richEvent()
        let changedLateFields = richEvent(
            userName: "resolved-later",
            envVars: ["OTHER": "late-value"],
            enrichments: ["late": "two"],
            severity: .critical,
            ruleMatches: [
                RuleMatch(
                    ruleId: "late.rule",
                    ruleName: "Late Rule",
                    severity: .critical,
                    description: "reviewed later"
                ),
            ]
        )
        #expect(
            EventJournalAdmissionValidator.sourceIdentityDigest(base)
                == EventJournalAdmissionValidator.sourceIdentityDigest(
                    changedLateFields
                )
        )

        let changedAction = richEvent(action: "disconnect")
        let changedArgument = richEvent(
            commandLine: "/usr/bin/curl --token another-secret",
            args: ["/usr/bin/curl", "--token", "another-secret"]
        )
        #expect(
            EventJournalAdmissionValidator.sourceIdentityDigest(base)
                != EventJournalAdmissionValidator.sourceIdentityDigest(
                    changedAction
                )
        )
        #expect(
            EventJournalAdmissionValidator.sourceIdentityDigest(base)
                != EventJournalAdmissionValidator.sourceIdentityDigest(
                    changedArgument
                )
        )

        let prepared = try EventJournalAdmissionValidator.prepare(base)
        #expect(
            prepared.sourceIdentitySHA256
                == EventJournalAdmissionValidator.sourceIdentityDigest(base)
        )
    }

    @Test("structural overflow map identity is insertion-order independent")
    func structuralMapOrderIsStable() throws {
        let oversized = String(
            repeating: "Z",
            count: EventJournalAdmissionValidator.maximumPreflightStringBytes + 1
        )
        var firstMap: [String: String] = [:]
        firstMap["a"] = oversized
        firstMap["b"] = "small"
        var secondMap: [String: String] = [:]
        secondMap["b"] = "small"
        secondMap["a"] = oversized

        let first = try EventJournalAdmissionValidator.prepare(
            richEvent(enrichments: firstMap)
        )
        let second = try EventJournalAdmissionValidator.prepare(
            richEvent(enrichments: secondMap)
        )
        #expect(first.overflow != nil)
        #expect(first.overflow?.digestKind == .structuralPreflight)
        #expect(
            first.overflow?.originalSHA256
                == second.overflow?.originalSHA256
        )
        #expect(
            first.overflow?.originalBytes == second.overflow?.originalBytes
        )
    }

    @Test("equal-size hostile strings cannot collapse to one identity")
    func equalSizeOverflowConflicts() throws {
        let count = EventJournalAdmissionValidator.maximumPreflightStringBytes
            + 1
        let first = try EventJournalAdmissionValidator.prepare(
            richEvent(enrichments: ["payload": String(repeating: "A", count: count)])
        )
        let second = try EventJournalAdmissionValidator.prepare(
            richEvent(enrichments: ["payload": String(repeating: "B", count: count)])
        )
        #expect(first.overflow?.originalBytes == second.overflow?.originalBytes)
        #expect(
            first.overflow?.originalSHA256
                != second.overflow?.originalSHA256
        )
    }

    @Test("same UUID cannot reuse stale preflight for mutated content")
    func preflightIsBoundToExactValue() throws {
        let original = richEvent(enrichments: ["state": "original"])
        let preflight = try EventJournalAdmissionValidator.preflight(original)
        let changed = richEvent(
            commandLine: String(
                repeating: "M",
                count: EventJournalAdmissionValidator
                    .maximumPreflightStringBytes + 1
            ),
            args: [],
            enrichments: ["state": "changed"]
        )
        #expect(changed.id == original.id)
        #expect(throws: EventJournalAdmissionValidatorError.mismatchedPreflight) {
            _ = try EventJournalAdmissionValidator.prepare(
                changed,
                preflight: preflight
            )
        }
    }

    @Test("64 MiB source is fully measured and replaced without source JSON")
    func hugeSourceUsesBoundedOverflowPath() throws {
        let sourceByteCount = 64 * 1_024 * 1_024
        let source = richEvent(
            commandLine: String(repeating: "Q", count: sourceByteCount),
            args: []
        )
        let preflight = try EventJournalAdmissionValidator.preflight(source)
        #expect(preflight.structurallyOverflowed)
        #expect(preflight.sourceRetainedByteEstimate >= sourceByteCount)
        #expect(preflight.sourceRetainedByteEstimate != Int.max)
        #expect(preflight.structuralSourceSHA256?.count == 32)

        let prepared = try EventJournalAdmissionValidator.prepare(
            source,
            preflight: preflight
        )
        let overflow = try #require(prepared.overflow)
        #expect(overflow.originalBytes == preflight.sourceRetainedByteEstimate)
        #expect(overflow.originalSHA256 == preflight.structuralSourceSHA256)
        #expect(prepared.canonicalJSON.count < 64 * 1_024)
        #expect(prepared.event.process.commandLine == "<canonical-journal-overflow>")
        let replacementJSON = String(
            decoding: prepared.canonicalJSON,
            as: UTF8.self
        )
        #expect(!replacementJSON.contains(String(repeating: "Q", count: 1_024)))
    }
}
