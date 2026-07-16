// V2TrustSubstrateInfoTests.swift
// MacCrabAppTests
//
// Pin the Trust-substrate card's three-state contract. The deep audit
// flagged that on a RELEASE install the card sat permanently dead on
// "Not generated" — the sysext creates `keys/` as 0o700 root-owned, so
// the uid-501 menubar app can't traverse the dir to reach the (0o644)
// public key even though the key exists. `.status`/`.classify` must tell
// that "root-protected, not readable here" case (`.managedByEngine`) apart
// from a genuinely-absent key (`.notGenerated`), and still surface full
// detail (`.available`) when the key IS readable (dev/root installs).

import Testing
import Foundation
@testable import MacCrabApp

@Suite("V2TrustSubstrateInfo")
struct V2TrustSubstrateInfoTests {

    // MARK: - Pure classifier

    @Test("Readable key → .available with the DER bytes + mode")
    func classifyAvailable() {
        let der = Data([0x30, 0x59, 0x01, 0x02, 0x03])
        let when = Date(timeIntervalSince1970: 1_700_000_000)
        let status = V2TrustSubstrateInfo.classify(
            der: der, mode: "filesystem_degraded", activatedAt: when,
            keysDirExistsButUnreadable: false)
        guard case .available(let info) = status else {
            Issue.record("expected .available, got \(status)"); return
        }
        #expect(info.derBytes == der)
        #expect(info.mode == "filesystem_degraded")
        #expect(info.modeLabel == "Filesystem (degraded)")
        #expect(status.info == info)
    }

    @Test("Unreadable key but root-owned keys/ present → .managedByEngine (not 'Not generated')")
    func classifyManaged() {
        let status = V2TrustSubstrateInfo.classify(
            der: nil, mode: "", activatedAt: .distantPast,
            keysDirExistsButUnreadable: true)
        #expect(status == .managedByEngine)
        #expect(status.info == nil)
    }

    @Test("Empty DER is treated as no key, not a zero-length available key")
    func classifyEmptyDER() {
        let status = V2TrustSubstrateInfo.classify(
            der: Data(), mode: "secure_enclave", activatedAt: Date(),
            keysDirExistsButUnreadable: true)
        #expect(status == .managedByEngine)
    }

    @Test("No key and a readable/absent keys dir → .notGenerated")
    func classifyNotGenerated() {
        let status = V2TrustSubstrateInfo.classify(
            der: nil, mode: "", activatedAt: .distantPast,
            keysDirExistsButUnreadable: false)
        #expect(status == .notGenerated)
        #expect(status.info == nil)
    }

    // MARK: - Disk-facing status (temp-dir seams)

    private func makeTempDataDir() throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-trust-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.path
    }

    @Test("status() reads a present, readable key → .available and round-trips the DER")
    func statusReadsRealKey() throws {
        let dataDir = try makeTempDataDir()
        let keysDir = dataDir + "/keys"
        try FileManager.default.createDirectory(atPath: keysDir, withIntermediateDirectories: true)
        let der = Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0xDE, 0xAD])
        try der.write(to: URL(fileURLWithPath: keysDir + "/trace-signing.pub"))
        let stateJSON = try JSONSerialization.data(withJSONObject: ["mode": "secure_enclave"])
        try stateJSON.write(to: URL(fileURLWithPath: keysDir + "/trust-substrate.json"))

        let status = V2TrustSubstrateInfo.status(dataDir: dataDir)
        guard case .available(let info) = status else {
            Issue.record("expected .available, got \(status)"); return
        }
        #expect(info.derBytes == der)
        #expect(info.mode == "secure_enclave")
        // Fingerprint is a deterministic SHA-256 over the DER bytes.
        #expect(info.fingerprintFull.count == 64)
    }

    @Test("status() with an empty, readable keys/ dir → .notGenerated (not managed)")
    func statusEmptyKeysDir() throws {
        let dataDir = try makeTempDataDir()
        try FileManager.default.createDirectory(atPath: dataDir + "/keys", withIntermediateDirectories: true)
        // We own the dir → traversable → the absence is a genuine "not generated",
        // NOT the release "root-protected" case.
        #expect(V2TrustSubstrateInfo.status(dataDir: dataDir) == .notGenerated)
    }

    @Test("status() with no keys/ dir at all → .notGenerated")
    func statusNoKeysDir() throws {
        let dataDir = try makeTempDataDir()
        #expect(V2TrustSubstrateInfo.status(dataDir: dataDir) == .notGenerated)
    }

    @Test("read() back-compat shim returns detail only for a readable key")
    func readShim() throws {
        let dataDir = try makeTempDataDir()
        let keysDir = dataDir + "/keys"
        try FileManager.default.createDirectory(atPath: keysDir, withIntermediateDirectories: true)
        #expect(V2TrustSubstrateInfo.read(dataDir: dataDir) == nil)   // nothing there yet
        try Data([0x01, 0x02, 0x03]).write(to: URL(fileURLWithPath: keysDir + "/trace-signing.pub"))
        #expect(V2TrustSubstrateInfo.read(dataDir: dataDir)?.derBytes == Data([0x01, 0x02, 0x03]))
    }
}
