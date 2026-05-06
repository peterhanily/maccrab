// TraceExtractorTests.swift
// Tests for v1.9 Agent Traces — W3C TRACEPARENT parser + bounded env scanner.
//
// Plan v3 review-mandated coverage. Parser is strict-on-v00, drop-on-anything-
// else; the env scanner is bounded at 256 vars / 16 KB whichever first.

import Testing
import Foundation
@testable import MacCrabCore

// MARK: - W3C parser

@Suite("TraceExtractor: W3C TRACEPARENT parser")
struct TraceparentParserTests {

    // A canonical valid v00 traceparent: version=00, non-zero trace_id,
    // non-zero span_id, sampled flag set.
    private static let validV00 =
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    @Test("Valid v00 round-trip")
    func validV00RoundTrip() {
        let ctx = TraceExtractor.parseTraceparent(Self.validV00, tracestatePresent: false)
        #expect(ctx?.traceId == "4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(ctx?.parentSpanId == "00f067aa0ba902b7")
        #expect(ctx?.flagsByte == 0x01)
        #expect(ctx?.sampled == true)
        #expect(ctx?.tracestatePresent == false)
    }

    @Test("All-zero trace_id is rejected")
    func allZeroTraceIdRejected() {
        let bad = "00-00000000000000000000000000000000-00f067aa0ba902b7-01"
        #expect(TraceExtractor.parseTraceparent(bad, tracestatePresent: false) == nil)
    }

    @Test("All-zero parent_span_id is rejected")
    func allZeroSpanIdRejected() {
        let bad = "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"
        #expect(TraceExtractor.parseTraceparent(bad, tracestatePresent: false) == nil)
    }

    @Test("Version ff is rejected (W3C reserves it as forever-invalid)")
    func versionFFRejected() {
        let bad = "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        #expect(TraceExtractor.parseTraceparent(bad, tracestatePresent: false) == nil)
    }

    // TODO: remove this test when W3C ratifies v01 and we add v01 support to
    // TraceExtractor. Until then v01 is rejected by the strict-on-v00 policy.
    @Test("Version 01 is rejected (strict-on-v00; revisit when W3C ratifies v01)")
    func version01Rejected() {
        let bad = "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        #expect(TraceExtractor.parseTraceparent(bad, tracestatePresent: false) == nil)
    }

    @Test("Length greater than 55 is rejected")
    func lengthOver55Rejected() {
        // A v00-prefixed value with extra bytes appended; future-version
        // parsers might tolerate this, but v1.9 is strict.
        let bad = Self.validV00 + "-extra"
        #expect(TraceExtractor.parseTraceparent(bad, tracestatePresent: false) == nil)
    }

    @Test("Length less than 55 is rejected")
    func lengthUnder55Rejected() {
        let bad = String(Self.validV00.dropLast(2))
        #expect(TraceExtractor.parseTraceparent(bad, tracestatePresent: false) == nil)
    }

    @Test("Uppercase hex is rejected (no tolerant mode in v1.9)")
    func uppercaseHexRejected() {
        let bad = "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"
        #expect(TraceExtractor.parseTraceparent(bad, tracestatePresent: false) == nil)
    }

    @Test("Non-hex characters are rejected")
    func nonHexRejected() {
        // 'g' is not a hex digit
        let bad = "00-gbf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        #expect(TraceExtractor.parseTraceparent(bad, tracestatePresent: false) == nil)
    }

    @Test("Sampled flag is read via bit-mask, not integer compare")
    func sampledIsBitmask() {
        // flags = 0x09 → bit 0 is set, bit 3 is set. Sampled must be true,
        // unaffected by the higher bits.
        let raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-09"
        let ctx = TraceExtractor.parseTraceparent(raw, tracestatePresent: false)
        #expect(ctx?.flagsByte == 0x09)
        #expect(ctx?.sampled == true)

        // flags = 0x02 → bit 1 set, bit 0 clear. Sampled must be false.
        let raw2 = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-02"
        let ctx2 = TraceExtractor.parseTraceparent(raw2, tracestatePresent: false)
        #expect(ctx2?.flagsByte == 0x02)
        #expect(ctx2?.sampled == false)
    }

    @Test("TRACESTATE presence is recorded but value is not stored")
    func tracestatePresenceFlag() {
        let ctx = TraceExtractor.parseTraceparent(Self.validV00, tracestatePresent: true)
        #expect(ctx?.tracestatePresent == true)
        // No field exists for tracestate value; the type's stored properties
        // are the entire scope of what gets persisted.
    }
}

// MARK: - Bounded env scanner

@Suite("TraceExtractor: bounded env scan")
struct TraceExtractorEnvScanTests {

    private static let validRaw =
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
    private static let validEntry = "TRACEPARENT=" + validRaw

    @Test("Finds TRACEPARENT in a small env")
    func findsTraceparent() {
        let env = ["PATH=/usr/bin", Self.validEntry, "USER=alice"]
        let ctx = TraceExtractor.scanEnv(count: env.count) { env[$0] }
        #expect(ctx?.traceId == "4bf92f3577b34da6a3ce929d0e0e4736")
    }

    @Test("Records TRACESTATE presence without storing its value")
    func tracestateFlagSetButValueIgnored() {
        let env = [
            Self.validEntry,
            "TRACESTATE=vendor=opaque-routing-state-do-not-store",
        ]
        let ctx = TraceExtractor.scanEnv(count: env.count) { env[$0] }
        #expect(ctx?.tracestatePresent == true)
        // There is no stored field on TraceContext that holds the raw
        // TRACESTATE value — its absence from the type IS the contract.
    }

    @Test("Scan stops exactly at maxEnvVarsScanned (256)")
    func scanCapsAtMaxVars() {
        // Build an env where TRACEPARENT lives at index 256 (the first
        // index beyond the cap). Scan should not find it.
        var env = [String]()
        for i in 0..<TraceExtractor.maxEnvVarsScanned {
            env.append("PADDING_\(i)=x")
        }
        env.append(Self.validEntry)
        #expect(env.count == TraceExtractor.maxEnvVarsScanned + 1)
        let ctx = TraceExtractor.scanEnv(count: env.count) { env[$0] }
        #expect(ctx == nil)
    }

    @Test("Scan stops exactly at maxEnvBytesScanned (16 KB)")
    func scanCapsAtMaxBytes() {
        // First a single huge entry that crosses the byte cap, then the
        // valid TRACEPARENT. The byte budget should be exhausted before
        // reaching the trace var.
        let huge = String(repeating: "x", count: TraceExtractor.maxEnvBytesScanned + 1)
        let env = ["BIG=" + huge, Self.validEntry]
        let ctx = TraceExtractor.scanEnv(count: env.count) { env[$0] }
        #expect(ctx == nil)
    }

    @Test("Secret-looking neighbour vars are never copied")
    func secretsAreNotTouched() {
        // The scanner only reads TRACEPARENT/TRACESTATE prefixes — secret
        // vars are walked past without being interpreted, copied, or
        // logged. This test pins the contract by checking that the
        // returned TraceContext contains zero bytes from the secret env
        // var (its value is not part of the parsed type at all).
        let env = [
            "ANTHROPIC_API_KEY=sk-ant-api03-DO-NOT-LEAK",
            "AWS_SECRET_ACCESS_KEY=DO-NOT-LEAK-AWS",
            Self.validEntry,
        ]
        let ctx = TraceExtractor.scanEnv(count: env.count) { env[$0] }
        let dump = String(describing: ctx)
        #expect(!dump.contains("sk-ant"))
        #expect(!dump.contains("LEAK"))
        #expect(!dump.contains("AWS"))
    }

    @Test("Log-injection (newline) in env value does not pollute parsed output")
    func logInjectionResistance() {
        // An attacker-controlled env value containing newlines and
        // pseudo-log-fragments must not cause the parser to accept it
        // (it's not a valid TRACEPARENT) nor end up reflected via the
        // parsed type.
        let injected =
            "TRACEPARENT=00-4bf92f35\n[FAKE LOG ENTRY] root: success\n77b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
        let env = [injected]
        let ctx = TraceExtractor.scanEnv(count: env.count) { env[$0] }
        // Length contains a newline → not 55 bytes of clean ASCII →
        // parser must reject.
        #expect(ctx == nil)
    }
}

// MARK: - AttributionEvidence

@Suite("AttributionEvidence: schema versioning + JSON")
struct AttributionEvidenceTests {

    @Test("Round-trip preserves all fields and schemaVersion=1")
    func roundTrip() {
        let ev = AttributionEvidence(
            source: .traceparentEnv,
            confidence: .traceparent,
            agentTool: .claudeCode,
            traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
            spanId: "00f067aa0ba902b7",
            parentSpanId: "00f067aa0ba902b7",
            matchedPid: 12345,
            matchedAncestorPid: 12000,
            hopCount: 2
        )
        #expect(ev.schemaVersion == 1)
        let json = ev.jsonString()
        #expect(json != nil)

        let decoded = AttributionEvidence.from(jsonString: json)
        #expect(decoded?.schemaVersion == 1)
        #expect(decoded?.source == .traceparentEnv)
        #expect(decoded?.confidence == .traceparent)
        #expect(decoded?.agentTool == .claudeCode)
        #expect(decoded?.traceId == "4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(decoded?.spanId == "00f067aa0ba902b7")
        #expect(decoded?.matchedPid == 12345)
        #expect(decoded?.matchedAncestorPid == 12000)
        #expect(decoded?.hopCount == 2)
    }

    @Test("Decoder treats missing schemaVersion as legacy (0)")
    func legacyDecoderFallback() {
        // Hand-rolled JSON simulating a hypothetical pre-versioned writer.
        let legacyJson = """
        {
          "source": "traceparent_env",
          "confidence": "traceparent",
          "matchedPid": 99
        }
        """
        let decoded = AttributionEvidence.from(jsonString: legacyJson)
        #expect(decoded != nil)
        #expect(decoded?.schemaVersion == 0)
        #expect(decoded?.source == .traceparentEnv)
        #expect(decoded?.confidence == .traceparent)
        #expect(decoded?.matchedPid == 99)
    }

    @Test("Unknown future enum values decode as .unknown rather than failing")
    func tolerantEnumDecode() {
        // A future writer adds a new Source case; the v1.9 decoder must not
        // drop the entire row over it.
        let futureJson = """
        {
          "schemaVersion": 99,
          "source": "future_quantum_correlator",
          "confidence": "future_super_high",
          "matchedPid": 5
        }
        """
        let decoded = AttributionEvidence.from(jsonString: futureJson)
        #expect(decoded?.source == .unknown)
        #expect(decoded?.confidence == .unknown)
        #expect(decoded?.matchedPid == 5)
    }
}

// MARK: - ProcessIdentity

@Suite("ProcessIdentity: identity vs display fields")
struct ProcessIdentityTests {

    private static func makeAuditIdentity(pid: Int32, pidversion: UInt32) -> AuditIdentity {
        AuditIdentity(
            auid: 501, euid: 501, egid: 20, ruid: 501, rgid: 20,
            pid: pid, pidversion: pidversion, asid: 100200
        )
    }

    @Test("Two identities with same audit but different display fields are equal")
    func displayFieldsExcludedFromEquality() {
        let audit = Self.makeAuditIdentity(pid: 12345, pidversion: 7)
        let pathHash = ProcessIdentity.fnv1a64("/usr/local/bin/claude")

        let a = ProcessIdentity(
            auditIdentity: audit, pathHash: pathHash,
            pid: 12345, startTime: 1_700_000_000
        )
        let b = ProcessIdentity(
            auditIdentity: audit, pathHash: pathHash,
            pid: 12345, startTime: 1_700_999_999  // different display only
        )
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test("PID-recycle pin: same pid but different pidversion is NOT equal")
    func pidRecyclePin() {
        // The canonical anti-pid-recycle scenario the registry must defend
        // against: a fresh process inherits a freed pid but carries a
        // different pidversion. ProcessIdentity must treat these as distinct.
        let audit1 = Self.makeAuditIdentity(pid: 12345, pidversion: 7)
        let audit2 = Self.makeAuditIdentity(pid: 12345, pidversion: 8)
        let pathHash = ProcessIdentity.fnv1a64("/usr/local/bin/claude")

        let original = ProcessIdentity(
            auditIdentity: audit1, pathHash: pathHash,
            pid: 12345, startTime: 1_700_000_000
        )
        let recycled = ProcessIdentity(
            auditIdentity: audit2, pathHash: pathHash,
            pid: 12345, startTime: 1_700_000_500
        )
        #expect(original != recycled)
        #expect(original.hashValue != recycled.hashValue)
    }

    @Test("Different pathHash makes identities distinct (defence-in-depth)")
    func pathHashGuard() {
        let audit = Self.makeAuditIdentity(pid: 12345, pidversion: 7)
        let claudeHash = ProcessIdentity.fnv1a64("/usr/local/bin/claude")
        let bashHash = ProcessIdentity.fnv1a64("/bin/bash")

        let a = ProcessIdentity(
            auditIdentity: audit, pathHash: claudeHash,
            pid: 12345, startTime: 0
        )
        let b = ProcessIdentity(
            auditIdentity: audit, pathHash: bashHash,
            pid: 12345, startTime: 0
        )
        #expect(a != b)
    }

    @Test("FNV-1a is stable and non-trivial")
    func fnv1aSanity() {
        let h1 = ProcessIdentity.fnv1a64("/bin/bash")
        let h2 = ProcessIdentity.fnv1a64("/bin/bash")
        let h3 = ProcessIdentity.fnv1a64("/bin/zsh")
        #expect(h1 == h2)
        #expect(h1 != h3)
        #expect(h1 != 0)
    }
}
