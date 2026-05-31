// EsloggerTests.swift
// Comprehensive unit tests for EsloggerParser JSON→Event mapping.
// Tests parsing without needing root or a subprocess.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - Shared Fixtures

private let execJSON: [String: Any] = [
    "schema_version": 1,
    "version": 7,
    "time": "2024-01-15T10:30:45.123456Z",
    "mach_time": 123456789012,
    "event_type": 9,
    "global_seq_num": 1,
    "seq_num": 1,
    "process": [
        "audit_token": ["pid": 100, "euid": 501],
        "ppid": 1,
        "executable": ["path": "/bin/bash"],
        "signing_id": "com.apple.bash",
        "team_id": "",
        "codesigning_flags": 570522385,
        "is_platform_binary": true,
    ] as [String: Any],
    "event": [
        "exec": [
            "target": [
                "audit_token": ["pid": 100, "euid": 501],
                "ppid": 1,
                "executable": ["path": "/usr/bin/curl"],
                "signing_id": "com.apple.curl",
                "team_id": "",
                "codesigning_flags": 570522385,
                "is_platform_binary": true,
                "start_time": "2024-01-15T10:30:45.000000Z",
            ] as [String: Any],
            "args": ["/usr/bin/curl", "-s", "https://example.com"],
            "cwd": ["path": "/Users/admin"],
            "image_cputype": 16777228,
        ] as [String: Any]
    ] as [String: Any]
]

/// Helper to build a full eslogger JSON envelope around an event payload.
private func makeEsloggerJSON(eventName: String, payload: [String: Any], process: [String: Any]? = nil) -> [String: Any] {
    let proc: [String: Any] = process ?? [
        "audit_token": ["pid": 200, "euid": 501],
        "ppid": 1,
        "executable": ["path": "/usr/bin/test"],
        "signing_id": "com.apple.test",
        "team_id": "",
        "codesigning_flags": 1,
        "is_platform_binary": false,
    ] as [String: Any]

    return [
        "schema_version": 1,
        "version": 7,
        "time": "2024-01-15T10:30:45.123456Z",
        "mach_time": 123456789012,
        "event_type": 0,
        "global_seq_num": 1,
        "seq_num": 1,
        "process": proc,
        "event": [eventName: payload] as [String: Any],
    ]
}

// MARK: - Exec Events

@Suite("Eslogger Parser: Exec Events")
struct EsloggerExecTests {

    @Test("Parses exec event with correct process fields")
    func execProcessFields() {
        let event = EsloggerParser.parse(execJSON)
        #expect(event != nil, "Exec JSON should parse to an Event")
        guard let event else { return }

        #expect(event.process.pid == 100)
        #expect(event.process.executable == "/usr/bin/curl")
        #expect(event.process.name == "curl")
        #expect(event.process.commandLine == "/usr/bin/curl -s https://example.com")
        #expect(event.process.args == ["/usr/bin/curl", "-s", "https://example.com"])
        #expect(event.eventAction == "exec")
        #expect(event.eventCategory == .process)
        #expect(event.eventType == .start)
    }

    @Test("Extracts ARM64 architecture from image_cputype")
    func architectureArm64() {
        let event = EsloggerParser.parse(execJSON)
        #expect(event != nil)
        #expect(event?.process.architecture == "arm64")
    }

    @Test("Extracts x86_64 architecture from image_cputype")
    func architectureX86() {
        // Build an exec JSON variant with x86_64 cputype (12)
        var json = execJSON
        var eventDict = json["event"] as! [String: Any]
        var execDict = eventDict["exec"] as! [String: Any]
        execDict["image_cputype"] = 12
        eventDict["exec"] = execDict
        json["event"] = eventDict

        let event = EsloggerParser.parse(json)
        #expect(event != nil)
        #expect(event?.process.architecture == "x86_64")
    }

    @Test("Uses exec target process, not source process")
    func usesTargetNotSource() {
        // The top-level "process" has /bin/bash; exec.target has /usr/bin/curl.
        // Parser should use the target.
        let event = EsloggerParser.parse(execJSON)
        #expect(event != nil)
        #expect(event?.process.executable == "/usr/bin/curl",
                "Should use exec target (/usr/bin/curl), not source (/bin/bash)")
    }
}

// MARK: - Code Signing

@Suite("Eslogger Parser: Code Signing")
struct EsloggerCodeSigningTests {

    @Test("Apple-signed binary detected correctly")
    func appleSigned() {
        // CS_VALID + is_platform_binary (kernel-attested) → .apple. This is
        // the ONLY signal trusted for .apple; team_id / signing_id are not.
        let processDict: [String: Any] = [
            "audit_token": ["pid": 10, "euid": 0],
            "ppid": 1,
            "executable": ["path": "/bin/ls"],
            "signing_id": "com.apple.ls",
            "team_id": "apple",
            "codesigning_flags": 570522385,
            "is_platform_binary": true,
        ]
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.codeSignature?.signerType == .apple)
    }

    @Test("Apple PLATFORM binary with empty team_id classifies as .apple")
    func applePlatformBinaryEmptyTeam() {
        // /usr/libexec/nehelper-style: valid Apple signature, EMPTY team_id,
        // kernel platform-binary flag set. Must be .apple (regression: this
        // class was previously mis-tagged .adHoc on the eslogger path).
        let processDict: [String: Any] = [
            "audit_token": ["pid": 11, "euid": 0],
            "ppid": 1,
            "executable": ["path": "/usr/libexec/nehelper"],
            "signing_id": "com.apple.nehelper",
            "team_id": "",
            "codesigning_flags": 570522385,
            "is_platform_binary": true,
        ]
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.codeSignature?.signerType == .apple)
    }

    @Test("Apple app with com.apple.* identifier + team (Xcode/iWork, non-platform) is .apple")
    func appleAppComAppleIdentifierClassifiesApple() {
        // Apple's own NON-platform apps (Xcode, Pages, Keynote) are signed
        // with a com.apple.* identifier under an Apple team and are NOT
        // platform binaries. They must classify .apple, else they trip the
        // ~126 SignerType:apple-negated rules. NOTE: signing_id is
        // developer-chosen, so this same path is the known (pre-existing)
        // devId-cert spoof gap documented on SignerType.classify — closing it
        // needs cert-authority validation and is a tracked follow-up.
        let processDict: [String: Any] = [
            "audit_token": ["pid": 12, "euid": 501],
            "ppid": 1,
            "executable": ["path": "/Applications/Xcode.app/Contents/MacOS/Xcode"],
            "signing_id": "com.apple.dt.Xcode",
            "team_id": "59GAB85EFG",
            "codesigning_flags": 1,
            "is_platform_binary": false,
        ]
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.codeSignature?.signerType == .apple)
    }

    @Test("Ad-hoc com.apple.* signing_id (empty team_id, not platform) is .adHoc, NOT .apple")
    func spoofedAppleSigningIdAdHocIsAdHoc() {
        // Same spoof via an ad-hoc signature (empty team_id, no platform
        // flag). The hoisted Apple check must not promote this to .apple.
        let processDict: [String: Any] = [
            "audit_token": ["pid": 13, "euid": 501],
            "ppid": 1,
            "executable": ["path": "/tmp/evil"],
            "signing_id": "com.apple.totally.legit",
            "team_id": "",
            "codesigning_flags": 1,
            "is_platform_binary": false,
        ]
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.codeSignature?.signerType == .adHoc)
    }

    @Test("Developer ID detected with team_id")
    func developerID() {
        // CS_VALID + team_id "ABCD1234" + signing_id "com.example.app" → .devId
        let processDict: [String: Any] = [
            "audit_token": ["pid": 20, "euid": 501],
            "ppid": 1,
            "executable": ["path": "/Applications/MyApp.app/Contents/MacOS/MyApp"],
            "signing_id": "com.example.app",
            "team_id": "ABCD1234",
            "codesigning_flags": 1,
            "is_platform_binary": false,
        ]
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.codeSignature?.signerType == .devId)
        #expect(info.codeSignature?.teamId == "ABCD1234")
    }

    @Test("Ad-hoc signature detected without team_id")
    func adHocSignature() {
        // CS_VALID + empty team_id + signing_id present → .adHoc
        let processDict: [String: Any] = [
            "audit_token": ["pid": 30, "euid": 501],
            "ppid": 1,
            "executable": ["path": "/tmp/mybuild"],
            "signing_id": "mybuild-adhoc",
            "team_id": "",
            "codesigning_flags": 1,
            "is_platform_binary": false,
        ]
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.codeSignature?.signerType == .adHoc)
    }

    @Test("Unsigned binary detected")
    func unsignedBinary() {
        // codesigning_flags without CS_VALID (bit 0 not set) → .unsigned
        let processDict: [String: Any] = [
            "audit_token": ["pid": 40, "euid": 501],
            "ppid": 1,
            "executable": ["path": "/tmp/sketch"],
            "signing_id": "",
            "team_id": "",
            "codesigning_flags": 0,
            "is_platform_binary": false,
        ]
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.codeSignature?.signerType == .unsigned)
    }
}

// MARK: - Numeric Robustness (v1.17.1 crash-safety)

/// eslogger JSON is attacker-influenceable; out-of-range / negative / NaN
/// numbers must NOT trap (SIGTRAP) the collector. These would have crashed
/// the daemon before the non-trapping int()/uint32() helpers landed.
@Suite("Eslogger Parser: numeric robustness")
struct EsloggerNumericRobustnessTests {

    @Test("Negative group_id does not crash; clamps to 0")
    func negativeGroupId() {
        let processDict: [String: Any] = [
            "audit_token": ["pid": 50, "euid": 501],
            "ppid": 1,
            "executable": ["path": "/usr/bin/true"],
            "signing_id": "", "team_id": "",
            "codesigning_flags": 1,
            "is_platform_binary": false,
            "group_id": -5,
        ]
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.groupId == 0)
    }

    @Test("NaN / infinite / out-of-range numeric fields do not crash")
    func nonFiniteAndOutOfRange() {
        let processDict: [String: Any] = [
            "audit_token": ["pid": 51, "euid": 501],
            "ppid": 1,
            "executable": ["path": "/usr/bin/true"],
            "signing_id": "", "team_id": "",
            "codesigning_flags": Double.nan,
            "is_platform_binary": false,
            "group_id": Double.infinity,
        ]
        // The assertion is simply that this returns without trapping.
        let info = EsloggerParser.extractProcess(from: processDict)
        #expect(info.pid == 51)
    }
}
