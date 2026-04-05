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
        // CS_VALID + team_id "apple" + signing_id "com.apple.ls" → .apple
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

// MARK: - File Events

@Suite("Eslogger Parser: File Events")
struct EsloggerFileTests {

    @Test("Parses create event with new_path")
    func createNewPath() {
        let payload: [String: Any] = [
            "destination_type": 1,
            "destination": [
                "new_path": [
                    "dir": ["path": "/Users/admin/Documents"],
                    "filename": "secret.txt",
                ] as [String: Any]
            ] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "create", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "create")
        #expect(event?.eventCategory == .file)
        #expect(event?.file?.path == "/Users/admin/Documents/secret.txt")
    }

    @Test("Parses write event")
    func writeEvent() {
        let payload: [String: Any] = [
            "target": ["path": "/var/log/system.log"] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "write", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "write")
        #expect(event?.file?.path == "/var/log/system.log")
    }

    @Test("Close event with modified=true emits event")
    func closeModified() {
        let payload: [String: Any] = [
            "modified": true,
            "target": ["path": "/tmp/output.dat"] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "close", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "close_modified")
    }

    @Test("Close event with modified=false returns nil")
    func closeUnmodified() {
        let payload: [String: Any] = [
            "modified": false,
            "target": ["path": "/tmp/output.dat"] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "close", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event == nil, "Close with modified=false should be dropped")
    }

    @Test("Parses rename event with source and destination")
    func renameEvent() {
        let payload: [String: Any] = [
            "source": ["path": "/tmp/old.txt"] as [String: Any],
            "destination_type": 1,
            "destination": [
                "new_path": [
                    "dir": ["path": "/tmp"],
                    "filename": "new.txt",
                ] as [String: Any]
            ] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "rename", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "rename")
        #expect(event?.file?.path == "/tmp/new.txt")
        #expect(event?.file?.sourcePath == "/tmp/old.txt")
    }

    @Test("Parses unlink event")
    func unlinkEvent() {
        let payload: [String: Any] = [
            "target": ["path": "/tmp/doomed.txt"] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "unlink", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "unlink")
        #expect(event?.eventType == .deletion)
    }
}

// MARK: - Process Lifecycle

@Suite("Eslogger Parser: Process Lifecycle")
struct EsloggerProcessLifecycleTests {

    @Test("Parses fork event using child process")
    func forkUsesChild() {
        let payload: [String: Any] = [
            "child": [
                "audit_token": ["pid": 999, "euid": 501],
                "ppid": 200,
                "executable": ["path": "/usr/bin/git"],
                "signing_id": "com.apple.git",
                "team_id": "",
                "codesigning_flags": 1,
                "is_platform_binary": true,
            ] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "fork", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "fork")
        // Should use fork.child (pid 999), not top-level process (pid 200)
        #expect(event?.process.pid == 999)
        #expect(event?.process.executable == "/usr/bin/git")
    }

    @Test("Parses exit event")
    func exitEvent() {
        let payload: [String: Any] = [:]
        let json = makeEsloggerJSON(eventName: "exit", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "exit")
        #expect(event?.eventType == .end)
    }
}

// MARK: - Signal Events

@Suite("Eslogger Parser: Signal Events")
struct EsloggerSignalTests {

    @Test("Parses signal event with target enrichments")
    func signalEvent() {
        let payload: [String: Any] = [
            "sig": 9,
            "target": [
                "audit_token": ["pid": 555, "euid": 0],
                "ppid": 1,
                "executable": ["path": "/usr/sbin/httpd"],
                "signing_id": "com.apple.httpd",
                "team_id": "",
                "codesigning_flags": 1,
                "is_platform_binary": true,
            ] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "signal", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "signal(9)")
        #expect(event?.enrichments["target.pid"] == "555")
        #expect(event?.enrichments["target.executable"] == "/usr/sbin/httpd")
    }
}

// MARK: - Memory Protection Events

@Suite("Eslogger Parser: Memory Protection")
struct EsloggerMemoryProtectionTests {

    @Test("mmap W+X emits event")
    func mmapWX() {
        let payload: [String: Any] = [
            "protection": 6,  // PROT_WRITE (2) | PROT_EXEC (4)
            "source": ["path": "/tmp/payload.dylib"] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "mmap", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "mmap_wx")
        #expect(event?.severity == .high)
    }

    @Test("mmap without W+X returns nil")
    func mmapReadOnly() {
        let payload: [String: Any] = [
            "protection": 1,  // PROT_READ only
            "source": ["path": "/usr/lib/libSystem.B.dylib"] as [String: Any]
        ]
        let json = makeEsloggerJSON(eventName: "mmap", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event == nil, "mmap with PROT_READ only should be dropped")
    }

    @Test("mprotect W+X emits event")
    func mprotectWX() {
        let payload: [String: Any] = [
            "protection": 6,  // PROT_WRITE | PROT_EXEC
        ]
        let json = makeEsloggerJSON(eventName: "mprotect", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "mprotect_wx")
        #expect(event?.severity == .high)
    }

    @Test("mprotect without W+X returns nil")
    func mprotectExecOnly() {
        let payload: [String: Any] = [
            "protection": 4,  // PROT_EXEC only
        ]
        let json = makeEsloggerJSON(eventName: "mprotect", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event == nil, "mprotect with PROT_EXEC only should be dropped")
    }
}

// MARK: - Edge Cases

@Suite("Eslogger Parser: Edge Cases")
struct EsloggerEdgeCaseTests {

    @Test("Returns nil for unknown event type")
    func unknownEventType() {
        let json = makeEsloggerJSON(eventName: "unknown_event", payload: ["foo": "bar"])
        let event = EsloggerParser.parse(json)
        #expect(event == nil, "Unknown event type should return nil")
    }

    @Test("Handles missing optional fields gracefully")
    func minimalJSON() {
        // Minimal exec: target with only executable path, no args, no cwd
        let json: [String: Any] = [
            "time": "2024-01-15T10:30:45Z",
            "process": [
                "audit_token": ["pid": 1, "euid": 0],
                "executable": ["path": "/sbin/launchd"],
            ] as [String: Any],
            "event": [
                "exec": [
                    "target": [
                        "audit_token": ["pid": 50, "euid": 501],
                        "executable": ["path": "/usr/bin/true"],
                    ] as [String: Any]
                ] as [String: Any]
            ] as [String: Any]
        ]
        let event = EsloggerParser.parse(json)
        #expect(event != nil, "Minimal JSON should still parse")
        #expect(event?.process.pid == 50)
        #expect(event?.process.executable == "/usr/bin/true")
        #expect(event?.process.name == "true")
        #expect(event?.process.commandLine == "")
        #expect(event?.process.args == [])
    }

    @Test("Parses kextload event")
    func kextloadEvent() {
        let payload: [String: Any] = [
            "identifier": "com.example.kext.driver"
        ]
        let json = makeEsloggerJSON(eventName: "kextload", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "kextload")
        #expect(event?.severity == .medium)
        #expect(event?.file?.path == "com.example.kext.driver")
    }

    @Test("Parses setowner event with uid/gid enrichments")
    func setownerEvent() {
        let payload: [String: Any] = [
            "target": ["path": "/etc/passwd"] as [String: Any],
            "uid": 0,
            "gid": 0,
        ]
        let json = makeEsloggerJSON(eventName: "setowner", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "setowner")
        #expect(event?.enrichments["file.uid"] == "0")
        #expect(event?.enrichments["file.gid"] == "0")
    }

    @Test("Parses setmode event with octal mode enrichment")
    func setmodeEvent() {
        let payload: [String: Any] = [
            "target": ["path": "/tmp/script.sh"] as [String: Any],
            "mode": 493,  // 0o755 in decimal
        ]
        let json = makeEsloggerJSON(eventName: "setmode", payload: payload)
        let event = EsloggerParser.parse(json)

        #expect(event != nil)
        #expect(event?.eventAction == "setmode")
        #expect(event?.enrichments["file.mode"] == "755")
    }
}
