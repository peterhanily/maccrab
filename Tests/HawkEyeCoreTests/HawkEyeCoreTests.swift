import XCTest
@testable import HawkEyeCore

final class HawkEyeCoreTests: XCTestCase {

    // MARK: - Event Model Tests

    func testEventCategoryCodable() throws {
        let category = EventCategory.process
        let data = try JSONEncoder().encode(category)
        let decoded = try JSONDecoder().decode(EventCategory.self, from: data)
        XCTAssertEqual(category, decoded)
    }

    func testSeverityComparable() {
        XCTAssertTrue(Severity.low < Severity.high)
        XCTAssertTrue(Severity.informational < Severity.critical)
        XCTAssertFalse(Severity.critical < Severity.medium)
    }

    func testSeverityAllCases() {
        XCTAssertEqual(Severity.allCases.count, 5)
    }

    func testSignerTypeCodable() throws {
        let signer = SignerType.devId
        let data = try JSONEncoder().encode(signer)
        let decoded = try JSONDecoder().decode(SignerType.self, from: data)
        XCTAssertEqual(signer, decoded)
    }

    func testFileActionCodable() throws {
        let action = FileAction.create
        let data = try JSONEncoder().encode(action)
        let decoded = try JSONDecoder().decode(FileAction.self, from: data)
        XCTAssertEqual(action, decoded)
    }

    // MARK: - Alert Model Tests

    func testAlertCodable() throws {
        let alert = Alert(
            id: "test-id",
            timestamp: Date(),
            ruleId: "rule-001",
            ruleTitle: "Test Rule",
            severity: .high,
            eventId: "event-001",
            processPath: "/usr/bin/curl",
            processName: "curl",
            description: "Test alert",
            mitreTactics: "attack.execution",
            mitreTechniques: "attack.t1059.004",
            suppressed: false
        )
        let data = try JSONEncoder().encode(alert)
        let decoded = try JSONDecoder().decode(Alert.self, from: data)
        XCTAssertEqual(alert.id, decoded.id)
        XCTAssertEqual(alert.severity, decoded.severity)
        XCTAssertEqual(alert.ruleTitle, decoded.ruleTitle)
    }

    // MARK: - NetworkInfo Tests

    func testNetworkInfoPrivateIPDetection() {
        let privateNet = NetworkInfo(
            sourceIp: "192.168.1.100",
            sourcePort: 54321,
            destinationIp: "10.0.0.1",
            destinationPort: 443,
            destinationHostname: nil,
            direction: .outbound,
            transport: "tcp"
        )
        XCTAssertTrue(privateNet.destinationIsPrivate)

        let publicNet = NetworkInfo(
            sourceIp: "192.168.1.100",
            sourcePort: 54321,
            destinationIp: "8.8.8.8",
            destinationPort: 443,
            destinationHostname: "dns.google",
            direction: .outbound,
            transport: "tcp"
        )
        XCTAssertFalse(publicNet.destinationIsPrivate)
    }
}
