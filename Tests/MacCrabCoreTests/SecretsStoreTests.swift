// SecretsStoreTests.swift
//
// Contract tests for SecretsStore. These tests write real items to the
// test process's Keychain and clean up after themselves.
//
// # Why they're opt-in
//
// macOS prompts the user to approve Keychain access the first time any
// unsigned (or newly-signed) binary touches it. In CI, Claude Code's
// Bash sandbox, or any headless SSH session that lacks a user window
// server, that prompt lands somewhere nobody can click and the test
// hangs. Setting MACCRAB_RUN_KEYCHAIN_TESTS=1 opts in — the author
// runs these manually on their signing Mac.
//
// The SecretsStore API itself is verified by the swift build step
// (type-checking, link errors), which catches the majority of
// breakages. These tests exercise real Keychain round-trips when we
// have a user session to authorise them.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SecretsStore")
struct SecretsStoreTests {

    /// Use a throwaway SecretKey across every test so we don't pollute
    /// whatever keys the running user actually has configured.
    /// `.urlScanKey` is picked arbitrarily — same Keychain item class,
    /// and the suite deletes it in every test's setup + teardown so
    /// there's no interference with real data even on a dev machine.
    private let testKey = SecretKey.urlScanKey
    private let store = SecretsStore()

    /// Opt-in guard. macOS prompts for Keychain access the first time a
    /// freshly-built binary touches it; in CI, Claude Code's sandbox, or
    /// any headless SSH session the prompt lands somewhere no-one can
    /// click and the test hangs. Running locally: set
    /// `MACCRAB_RUN_KEYCHAIN_TESTS=1` and the suite executes for real.
    private static var isEnabled: Bool {
        ProcessInfo.processInfo.environment["MACCRAB_RUN_KEYCHAIN_TESTS"] == "1"
    }

    private func cleanup() {
        try? store.delete(testKey)
    }

    @Test("set then get round-trips the value")
    func roundTrip() throws {
        guard Self.isEnabled else { return }
        cleanup()
        defer { cleanup() }

        try store.set(testKey, value: "test-secret-value-42")
        #expect(try store.get(testKey) == "test-secret-value-42")
    }

    @Test("get on missing key returns nil (not throw)")
    func missingKeyReturnsNil() throws {
        guard Self.isEnabled else { return }
        cleanup()
        #expect(try store.get(testKey) == nil)
    }

    @Test("set overwrites an existing value")
    func overwriteSemantics() throws {
        guard Self.isEnabled else { return }
        cleanup()
        defer { cleanup() }

        try store.set(testKey, value: "first")
        try store.set(testKey, value: "second")
        #expect(try store.get(testKey) == "second")
    }

    @Test("set with empty string deletes the item")
    func emptyStringDeletes() throws {
        guard Self.isEnabled else { return }
        cleanup()
        defer { cleanup() }

        try store.set(testKey, value: "something")
        #expect(store.exists(testKey))
        try store.set(testKey, value: "")
        #expect(!store.exists(testKey))
        #expect(try store.get(testKey) == nil)
    }

    @Test("delete is idempotent")
    func deleteIsIdempotent() throws {
        guard Self.isEnabled else { return }
        cleanup()
        try store.delete(testKey)
        try store.delete(testKey)
        // If we got here, both deletes returned without throwing.
    }

    @Test("exists reflects storage state without throwing")
    func existsContract() throws {
        guard Self.isEnabled else { return }
        cleanup()
        defer { cleanup() }

        #expect(!store.exists(testKey))
        try store.set(testKey, value: "x")
        #expect(store.exists(testKey))
        try store.delete(testKey)
        #expect(!store.exists(testKey))
    }

    @Test("storedKeys lists only the keys we've set")
    func storedKeysListing() throws {
        guard Self.isEnabled else { return }
        cleanup()
        defer { cleanup() }

        // Preserve any pre-existing keys so the test doesn't touch user state.
        let before = Set(store.storedKeys())
        try store.set(testKey, value: "x")
        let after = Set(store.storedKeys())
        #expect(after.contains(testKey))
        #expect(after.subtracting(before) == [testKey])
    }

    @Test("unicode values survive the round trip")
    func unicodeRoundTrip() throws {
        guard Self.isEnabled else { return }
        cleanup()
        defer { cleanup() }

        let value = "🦀 κεψ  — ωιθ  emoji + greek + em-dash"
        try store.set(testKey, value: value)
        #expect(try store.get(testKey) == value)
    }
}
