// CaseRetentionTests.swift
// v1.18 — tests for CaseManager.pruneCases(olderThan:), the enforcement
// behind the "Scan retention" setting (forensics.retentionDays). Before
// v1.18 only the manual "Run cleanup now" button invoked retention;
// nothing ran it automatically, so forensic cases accumulated forever.

import Foundation
import Testing
@testable import MacCrabForensics

@Suite("CaseManager: scan retention (v1.18)")
struct CaseRetentionTests {

    private func makeRoot() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("cases-gc-\(UUID().uuidString)", isDirectory: true)
    }

    @Test("Deletes cases older than the cutoff and reports them")
    func deletesOld() async throws {
        let root = makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        _ = try await mgr.createCase(name: "a")
        _ = try await mgr.createCase(name: "b")
        _ = try await mgr.createCase(name: "c")
        #expect(try await mgr.listCases().count == 3)

        // Cutoff one day in the future → all three (created "now") are older.
        let result = await mgr.pruneCases(olderThan: Date().addingTimeInterval(86_400))
        #expect(result.deleted.count == 3)
        #expect(try await mgr.listCases().isEmpty)
    }

    @Test("Keeps cases newer than the cutoff")
    func keepsRecent() async throws {
        let root = makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        _ = try await mgr.createCase(name: "a")
        _ = try await mgr.createCase(name: "b")

        // Cutoff a year ago → nothing is that old.
        let result = await mgr.pruneCases(olderThan: Date().addingTimeInterval(-365 * 86_400))
        #expect(result.deleted.isEmpty)
        #expect(try await mgr.listCases().count == 2)
    }

    @Test("Empty Cases root is a no-op")
    func emptyRoot() async throws {
        let root = makeRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let mgr = CaseManager(casesRoot: root, dekVault: InMemoryDEKVault())
        let result = await mgr.pruneCases(olderThan: Date())
        #expect(result.deleted.isEmpty)
        #expect(result.freedBytes == 0)
    }
}
