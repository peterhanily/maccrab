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

    // The account enum is shared with production, so isolation must come from
    // a unique service per test instance. Never touch the production namespace.
    private let testKey = SecretKey.urlScanKey
    private let store = SecretsStore(
        accessGroup: nil,
        service: "com.maccrab.tests.secrets." + UUID().uuidString
    )

    /// Opt-in guard. macOS prompts for Keychain access the first time a
    /// freshly-built binary touches it; in CI, Claude Code's sandbox, or
    /// any headless SSH session the prompt lands somewhere no-one can
    /// click and the test hangs. Running locally: set
    /// `MACCRAB_RUN_KEYCHAIN_TESTS=1` and the suite executes for real.
    /// Internal (not private): a Swift Testing `.enabled(if:)` trait expression
    /// is expanded outside this type's scope and cannot see a private member.
    static var isEnabled: Bool {
        ProcessInfo.processInfo.environment["MACCRAB_RUN_KEYCHAIN_TESTS"] == "1"
    }

    private func cleanup() {
        try? store.delete(testKey)
    }

    // `.enabled(if:)` rather than `guard … else { return }`: the guard made a
    // SKIP report as a PASS, inflating the suite headline with eight tests that
    // assert nothing in every environment that does not set the opt-in.
    @Test("set then get round-trips the value", .enabled(if: SecretsStoreTests.isEnabled))
    func roundTrip() throws {
        cleanup()
        defer { cleanup() }

        try store.set(testKey, value: "test-secret-value-42")
        #expect(try store.get(testKey) == "test-secret-value-42")
    }

    @Test("get on missing key returns nil (not throw)", .enabled(if: SecretsStoreTests.isEnabled))
    func missingKeyReturnsNil() throws {
        cleanup()
        #expect(try store.get(testKey) == nil)
    }

    @Test("set overwrites an existing value", .enabled(if: SecretsStoreTests.isEnabled))
    func overwriteSemantics() throws {
        cleanup()
        defer { cleanup() }

        try store.set(testKey, value: "first")
        try store.set(testKey, value: "second")
        #expect(try store.get(testKey) == "second")
    }

    @Test("set with empty string deletes the item", .enabled(if: SecretsStoreTests.isEnabled))
    func emptyStringDeletes() throws {
        cleanup()
        defer { cleanup() }

        try store.set(testKey, value: "something")
        #expect(store.exists(testKey))
        try store.set(testKey, value: "")
        #expect(!store.exists(testKey))
        #expect(try store.get(testKey) == nil)
    }

    @Test("delete is idempotent", .enabled(if: SecretsStoreTests.isEnabled))
    func deleteIsIdempotent() throws {
        cleanup()
        try store.delete(testKey)
        try store.delete(testKey)
        // If we got here, both deletes returned without throwing.
    }

    @Test("exists reflects storage state without throwing", .enabled(if: SecretsStoreTests.isEnabled))
    func existsContract() throws {
        cleanup()
        defer { cleanup() }

        #expect(!store.exists(testKey))
        try store.set(testKey, value: "x")
        #expect(store.exists(testKey))
        try store.delete(testKey)
        #expect(!store.exists(testKey))
    }

    @Test("storedKeys lists only the keys we've set", .enabled(if: SecretsStoreTests.isEnabled))
    func storedKeysListing() throws {
        cleanup()
        defer { cleanup() }

        // This unique service starts empty; no production keys are queried.
        #expect(store.storedKeys().isEmpty)
        try store.set(testKey, value: "x")
        let after = Set(store.storedKeys())
        #expect(after == [testKey])
    }

    @Test("unicode values survive the round trip", .enabled(if: SecretsStoreTests.isEnabled))
    func unicodeRoundTrip() throws {
        cleanup()
        defer { cleanup() }

        let value = "🦀 κεψ  — ωιθ  emoji + greek + em-dash"
        try store.set(testKey, value: value)
        #expect(try store.get(testKey) == value)
    }
}
