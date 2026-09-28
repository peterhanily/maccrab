import Foundation
import Testing
import CSQLCipher
@testable import MacCrabCore
@testable import MacCrabAgentKit

@Suite("Explicit storage maintenance diagnostics")
struct SQLiteIntegrityDiagnosticTests {
    @Test("ordinary check reads an existing database without changing its bytes")
    func checksExistingStoreWithoutMigration() throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-quick-check-\(UUID().uuidString).db")
        defer { try? FileManager.default.removeItem(at: path) }
        var database: OpaquePointer?
        try #require(sqlite3_open(path.path, &database) == SQLITE_OK)
        try #require(sqlite3_exec(database,
            "CREATE TABLE ordinary(id INTEGER PRIMARY KEY, label TEXT); INSERT INTO ordinary VALUES(1, 'kept');",
            nil, nil, nil) == SQLITE_OK)
        sqlite3_close(database)
        let original = try Data(contentsOf: path)
        let result = SQLiteIntegrityDiagnostic.check(database: path)
        #expect(result.status == "passed")
        #expect(result.issueCount == 0)
        #expect(result.elapsedSeconds >= 0)
        #expect(try Data(contentsOf: path) == original)
        let exhausted = SQLiteIntegrityDiagnostic.check(database: path, timeoutSeconds: 1e-9)
        #expect(exhausted.status == "incomplete")
        #expect(try Data(contentsOf: path) == original)
    }

    @Test("missing stores and invalid budgets never create a database or pass")
    func missingIsUnverified() {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("missing-\(UUID().uuidString).db")
        #expect(SQLiteIntegrityDiagnostic.check(database: path).status == "unavailable")
        #expect(SQLiteIntegrityDiagnostic.check(database: path, timeoutSeconds: .infinity)
            .status == "invalid_budget")
        #expect(!FileManager.default.fileExists(atPath: path.path))
    }

    @Test("startup support reasons use typed failures rather than message text")
    func startupReasons() {
        #expect(DaemonSetup.startupFailureReason(
            DatabaseEncryptionAvailabilityError.persistentKeyUnavailable(nil)) == "key_unavailable")
        #expect(DaemonSetup.startupFailureReason(
            SQLitePersistentStoreAdmissionError.footprintLimit(
                footprintBytes: 100, reserveBytes: 20, maxFootprintBytes: 110)) == "storage_pressure")
        #expect(DaemonSetup.startupFailureReason(
            EventStoreError.storageNotReady("integrity_failure: storage_pressure")) == "initialization_failed")
    }

    @Test("TraceGraph pre-producer failures say whether storage capacity was the cause")
    func traceGraphStartupReasons() {
        typealias Failure = DaemonSetup.TraceGraphStartupStorageError
        func result(_ reason: CausalGraphStartupRecoveryNonconvergenceReason) -> CausalGraphStartupRecoveryResult {
            CausalGraphStartupRecoveryResult(
                disposition: .nonconverged(reason), initiallyBlocked: true, passes: 1,
                attemptedCutoffHours: [1], finalAdmission: nil, lastRecovery: nil, failureDetail: nil)
        }
        for reason: CausalGraphStartupRecoveryNonconvergenceReason in [
            .protectedEvidenceFloor, .boundedPassLimit, .incrementalVacuumUnavailable,
            .noRecoverableProgress, .admissionRemainsBlocked,
        ] {
            #expect(DaemonSetup.startupFailureReason(Failure(recovery: result(reason))) == "storage_pressure")
        }
        for reason: CausalGraphStartupRecoveryNonconvergenceReason in [
            .storeUnavailable, .writableHandleUnavailable, .pinnedReader,
            .admissionMeasurementUnavailable, .recoveryFailed,
        ] {
            #expect(DaemonSetup.startupFailureReason(Failure(recovery: result(reason))) == "initialization_failed")
        }
        #expect(DaemonSetup.startupFailureReason(Failure(block: .footprintLimit)) == "storage_pressure")
        #expect(DaemonSetup.startupFailureReason(Failure(block: .lowFreeSpace)) == "storage_pressure")
        #expect(DaemonSetup.startupFailureReason(Failure(block: .probeFailure)) == "initialization_failed")
    }
}
