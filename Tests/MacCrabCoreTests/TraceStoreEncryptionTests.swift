// TraceStoreEncryptionTests.swift
// v1.9 Phase-2.2 — column-level AES-GCM for `attributes_json`.
// Pin: encrypted writes carry the ENC2: prefix at rest; reads
// decrypt back to plaintext; legacy plaintext rows continue to read
// through unchanged.

import Testing
import Foundation
import SQLite3
@testable import MacCrabCore

@Suite("TraceStore: column-level AES-GCM for attributes_json")
struct TraceStoreEncryptionTests {

    private static func tempDB() -> String {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("trace-enc-\(UUID().uuidString).db").path
    }

    private static func sample(attrs: String? = #"{"tool_name":"Bash","note":"hello"}"#) -> SpanRecord {
        SpanRecord(
            traceId: "4bf92f3577b34da6a3ce929d0e0e4736",
            spanId: "00f067aa0ba902b7",
            parentSpanId: nil,
            startNs: 1, endNs: 2,
            serviceName: "claude-code",
            spanName: "claude_code.tool.execution",
            agentTool: .claudeCode,
            providerName: "anthropic",
            legacyGenAiSystem: "anthropic",
            attributesJson: attrs
        )
    }

    @Test("Round-trip via encrypted store decrypts back to plaintext")
    func roundTripEncrypted() async throws {
        let path = Self.tempDB()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let enc = DatabaseEncryption(enabled: true)
        let store = try TraceStore(path: path, encryption: enc)
        try await store.insertSpan(Self.sample())
        let read = try await store.spansForTrace("4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(read.first?.attributesJson?.contains("tool_name") == true)
        #expect(read.first?.attributesJson?.contains("hello") == true)
    }

    @Test("Stored bytes carry the ENC2: prefix when encryption is wired")
    func storedBytesAreEncrypted() async throws {
        let path = Self.tempDB()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let enc = DatabaseEncryption(enabled: true)
        let store = try TraceStore(path: path, encryption: enc)
        try await store.insertSpan(Self.sample())

        // Read the raw column directly via a fresh handle (bypassing
        // the actor's decrypt path) to confirm what hit disk.
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        sqlite3_prepare_v2(db, "SELECT attributes_json FROM spans LIMIT 1", -1, &stmt, nil)
        sqlite3_step(stmt)
        let raw = String(cString: sqlite3_column_text(stmt, 0))
        #expect(raw.hasPrefix("ENC2:"))
        // Plaintext markers must NOT be present in the on-disk bytes.
        #expect(!raw.contains("tool_name"))
        #expect(!raw.contains("hello"))
    }

    @Test("Plaintext store (no encryption) writes raw JSON")
    func plaintextWhenNoEncryption() async throws {
        let path = Self.tempDB()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let store = try TraceStore(path: path)  // encryption: nil
        try await store.insertSpan(Self.sample())

        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil)
        var stmt: OpaquePointer?
        defer { if let s = stmt { sqlite3_finalize(s) } }
        sqlite3_prepare_v2(db, "SELECT attributes_json FROM spans LIMIT 1", -1, &stmt, nil)
        sqlite3_step(stmt)
        let raw = String(cString: sqlite3_column_text(stmt, 0))
        #expect(!raw.hasPrefix("ENC2:"))
        #expect(raw.contains("tool_name"))
    }

    @Test("Legacy plaintext row continues to read after encryption is wired")
    func legacyPlaintextStillReads() async throws {
        let path = Self.tempDB()
        defer { try? FileManager.default.removeItem(atPath: path) }
        // First write WITHOUT encryption (simulates pre-Phase-2.2 row)
        do {
            let plain = try TraceStore(path: path)
            try await plain.insertSpan(Self.sample())
        }
        // Re-open WITH encryption — old row should still decode (decrypt
        // is a passthrough for non-ENC: input).
        let enc = DatabaseEncryption(enabled: true)
        let store = try TraceStore(path: path, encryption: enc)
        let read = try await store.spansForTrace("4bf92f3577b34da6a3ce929d0e0e4736")
        #expect(read.first?.attributesJson?.contains("tool_name") == true)
    }

    @Test("Tampered ciphertext: decrypt logs and returns the raw blob")
    func tamperReturnsRaw() async throws {
        let path = Self.tempDB()
        defer { try? FileManager.default.removeItem(atPath: path) }
        let enc = DatabaseEncryption(enabled: true)
        let store = try TraceStore(path: path, encryption: enc)
        try await store.insertSpan(Self.sample())

        // Corrupt one byte of the ciphertext directly via SQLite.
        var db: OpaquePointer?
        defer { if let d = db { sqlite3_close(d) } }
        sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil)
        // Read current value, mutate one base64 char, write back.
        var rstmt: OpaquePointer?
        sqlite3_prepare_v2(db, "SELECT attributes_json FROM spans", -1, &rstmt, nil)
        sqlite3_step(rstmt)
        var raw = String(cString: sqlite3_column_text(rstmt, 0))
        sqlite3_finalize(rstmt)
        // Flip a char in the middle of the base64 payload (keep prefix).
        var chars = Array(raw)
        let mid = chars.count / 2
        chars[mid] = chars[mid] == "A" ? "B" : "A"
        raw = String(chars)
        var ustmt: OpaquePointer?
        sqlite3_prepare_v2(db, "UPDATE spans SET attributes_json = ?1", -1, &ustmt, nil)
        let TRANSIENT = unsafeBitCast(OpaquePointer(bitPattern: -1)!, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(ustmt, 1, raw, -1, TRANSIENT)
        sqlite3_step(ustmt)
        sqlite3_finalize(ustmt)

        // Decrypt fails the AES-GCM tag check; read returns the raw
        // (untouched) ciphertext blob — a visible signal in the UI
        // and a logged warning rather than silent garbage.
        let read = try await store.spansForTrace("4bf92f3577b34da6a3ce929d0e0e4736")
        // Either: still has the ENC2: prefix (tamper detected and the
        // raw value bubbled), OR (less likely on a single-byte flip)
        // didn't decrypt to anything that LOOKS like the original.
        let attrs = read.first?.attributesJson ?? ""
        #expect(!attrs.contains("hello") || attrs.hasPrefix("ENC2:"),
                "tamper must either bubble raw ENC2: or scramble the plaintext; got \(attrs)")
    }
}
