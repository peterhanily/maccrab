// EnvCaptureTests.swift
// Parser + filter logic for reading and sanitizing process env vars.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("EnvCapture parser")
struct EnvCaptureParserTests {

    /// Build a KERN_PROCARGS2-shaped buffer: [argc:Int32][exe\0][padding\0]
    /// [argv0\0]...[argvN-1\0][env0\0]...[envN-1\0][\0]
    private func makeBuf(
        argc: Int32,
        exePath: String,
        argv: [String],
        env: [String]
    ) -> Data {
        var d = Data()
        var argcCopy = argc
        withUnsafeBytes(of: &argcCopy) { d.append(contentsOf: $0) }
        d.append(Data(exePath.utf8))
        d.append(0)
        // A couple of padding zero bytes — real buffers often have these.
        d.append(contentsOf: [0, 0])
        for a in argv {
            d.append(Data(a.utf8))
            d.append(0)
        }
        for e in env {
            d.append(Data(e.utf8))
            d.append(0)
        }
        d.append(0)  // double-null terminator
        return d
    }

    @Test("parses a well-formed KERN_PROCARGS2 buffer")
    func parsesBuffer() {
        let buf = makeBuf(
            argc: 2,
            exePath: "/usr/bin/curl",
            argv: ["/usr/bin/curl", "https://example.com"],
            env: [
                "PATH=/usr/bin:/bin",
                "HOME=/Users/alice",
                "DYLD_INSERT_LIBRARIES=/tmp/mal.dylib",
            ]
        )
        let env = EnvCapture.parseEnv(from: buf)
        #expect(env["PATH"] == "/usr/bin:/bin")
        #expect(env["HOME"] == "/Users/alice")
        #expect(env["DYLD_INSERT_LIBRARIES"] == "/tmp/mal.dylib")
        #expect(env.count == 3)
    }

    @Test("Tolerates values containing '=' in the middle")
    func equalsInValue() {
        let buf = makeBuf(
            argc: 1,
            exePath: "/bin/ls",
            argv: ["/bin/ls"],
            env: ["SSH_CONNECTION=1.2.3.4 5678 10.0.0.1 22"]
        )
        let env = EnvCapture.parseEnv(from: buf)
        #expect(env["SSH_CONNECTION"] == "1.2.3.4 5678 10.0.0.1 22")
    }

    @Test("Empty buffer returns empty dict")
    func emptyBuffer() {
        #expect(EnvCapture.parseEnv(from: Data()).isEmpty)
    }

    @Test("Handles large env var sets")
    func manyEnvVars() {
        let envs = (0..<50).map { "VAR\($0)=value\($0)" }
        let buf = makeBuf(
            argc: 1, exePath: "/bin/bash", argv: ["/bin/bash"], env: envs
        )
        let env = EnvCapture.parseEnv(from: buf)
        #expect(env.count == 50)
        #expect(env["VAR0"] == "value0")
        #expect(env["VAR49"] == "value49")
    }
}

@Suite("EnvCapture filter")
struct EnvCaptureFilterTests {

    @Test("Allowlisted keys pass through")
    func allowlistPasses() {
        let raw: [String: String] = [
            "PATH": "/usr/bin",
            "HOME": "/Users/alice",
            "DYLD_INSERT_LIBRARIES": "/tmp/x.dylib",
        ]
        let out = EnvCapture.filter(raw, allowlist: EnvCapture.defaultAllowlist)
        #expect(out.count == 3)
        #expect(out["DYLD_INSERT_LIBRARIES"] == "/tmp/x.dylib")
    }

    @Test("Secrets in explicit deny list are dropped")
    func explicitDenyDrops() {
        let raw: [String: String] = [
            "PATH": "/usr/bin",
            "AWS_SECRET_ACCESS_KEY": "AKIA...secret...",
            "GITHUB_TOKEN": "ghp_...",
            "OPENAI_API_KEY": "sk-...",
        ]
        let out = EnvCapture.filter(raw, allowlist: EnvCapture.defaultAllowlist)
        #expect(out["AWS_SECRET_ACCESS_KEY"] == nil)
        #expect(out["GITHUB_TOKEN"] == nil)
        #expect(out["OPENAI_API_KEY"] == nil)
        #expect(out["PATH"] == "/usr/bin")
    }

    @Test("Secret-substring keys are dropped even if allowlist accidentally includes them")
    func substringDeny() {
        let raw: [String: String] = [
            "MY_APP_SECRET": "s3cret",
            "MY_APP_TOKEN": "t0ken",
            "MY_APP_PASSWORD": "p@ss",
            "MY_APP_PRIVATE_KEY": "bunch of bytes",
        ]
        let widened: Set<String> = [
            "MY_APP_SECRET", "MY_APP_TOKEN",
            "MY_APP_PASSWORD", "MY_APP_PRIVATE_KEY",
        ]
        let out = EnvCapture.filter(raw, allowlist: widened)
        #expect(out.isEmpty, "secret-substring keys must be unconditionally denied")
    }

    @Test("Non-allowlisted keys are dropped by default")
    func defaultAllowlistIsNarrow() {
        let raw: [String: String] = [
            "SOME_RANDOM_VAR": "value",
            "PATH": "/usr/bin",
        ]
        let out = EnvCapture.filter(raw, allowlist: EnvCapture.defaultAllowlist)
        #expect(out["SOME_RANDOM_VAR"] == nil)
        #expect(out["PATH"] == "/usr/bin")
    }
}
