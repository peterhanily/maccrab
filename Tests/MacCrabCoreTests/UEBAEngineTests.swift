// UEBAEngineTests.swift
// Per-user baseline + anomaly detection.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("UEBA engine")
struct UEBAEngineTests {

    private func procEvent(
        user: String = "alice",
        path: String = "/usr/bin/ls",
        sshIP: String? = nil,
        at date: Date = Date()
    ) -> Event {
        let session = sshIP.map {
            SessionInfo(
                sessionId: nil, tty: nil, loginUser: user,
                sshRemoteIP: $0, launchSource: .ssh
            )
        }
        let proc = MacCrabCore.ProcessInfo(
            pid: Int32.random(in: 1000..<9000),
            ppid: 1, rpid: 1,
            name: (path as NSString).lastPathComponent,
            executable: path,
            commandLine: path,
            args: [path],
            workingDirectory: "/Users/\(user)",
            userId: 501, userName: user, groupId: 20,
            startTime: date,
            session: session
        )
        return Event(
            eventCategory: .process, eventType: .start,
            eventAction: "exec", process: proc
        )
    }

    // MARK: - Cold start

    @Test("No anomalies emitted during cold-start window")
    func coldStartSilent() async {
        let engine = UEBAEngine(minObservationsForScoring: 10)
        // 9 observations — still cold.
        for _ in 0..<9 {
            let e = procEvent(user: "alice", path: "/usr/bin/ls")
            let anomalies = await engine.observe(event: e)
            #expect(anomalies.isEmpty)
        }
    }

    @Test("First post-threshold observation can trigger novel-tool anomaly")
    func firstScoredObservation() async {
        let engine = UEBAEngine(minObservationsForScoring: 5)
        // Baseline: /usr/bin/ls used repeatedly at hour X.
        for _ in 0..<5 {
            _ = await engine.observe(event: procEvent(path: "/usr/bin/ls"))
        }
        // Next observation with a NEW tool path — novelTool fires.
        let anomalies = await engine.observe(
            event: procEvent(path: "/tmp/never_seen_before")
        )
        #expect(anomalies.contains { $0.kind == .novelTool })
    }

    // MARK: - Login hour

    @Test("Unusual login hour flagged after strong baseline")
    func unusualLoginHour() async {
        let engine = UEBAEngine(minObservationsForScoring: 50, hourAnomalyThreshold: 0.05)

        // Baseline: 50 observations at hour 10 (morning).
        let baseline = Calendar.current.date(bySettingHour: 10, minute: 0, second: 0, of: Date())!
        for _ in 0..<50 {
            _ = await engine.observe(event: procEvent(path: "/usr/bin/ls"), now: baseline)
        }

        // New observation at hour 3 (middle of night) — strong anomaly.
        let midnight = Calendar.current.date(bySettingHour: 3, minute: 0, second: 0, of: Date())!
        let anomalies = await engine.observe(event: procEvent(path: "/usr/bin/ls"), now: midnight)
        #expect(anomalies.contains { $0.kind == .unusualLoginHour })
    }

    @Test("Hour frequency query returns 0 for unseen hours")
    func hourFrequency() async {
        let engine = UEBAEngine(minObservationsForScoring: 10)
        let baseline = Calendar.current.date(bySettingHour: 14, minute: 0, second: 0, of: Date())!
        for _ in 0..<20 {
            _ = await engine.observe(event: procEvent(), now: baseline)
        }
        let profile = try? #require(await engine.profile(for: "alice"))
        #expect(profile?.hourFrequency(14) == 1.0)
        #expect(profile?.hourFrequency(3) == 0.0)
    }

    // MARK: - SSH

    @Test("New SSH source IP triggers high-severity anomaly")
    func newSSHSource() async {
        let engine = UEBAEngine(minObservationsForScoring: 3)
        // Baseline from one IP
        for _ in 0..<3 {
            _ = await engine.observe(event: procEvent(sshIP: "10.0.0.5"))
        }
        // New IP
        let anomalies = await engine.observe(
            event: procEvent(sshIP: "203.0.113.42")
        )
        let ssh = anomalies.first { $0.kind == .newSSHSource }
        #expect(ssh != nil)
        #expect(ssh?.severity == .high)
        #expect(ssh?.detail.contains("203.0.113.42") == true)
    }

    @Test("Known SSH source IP does not trigger anomaly")
    func knownSSHSource() async {
        let engine = UEBAEngine(minObservationsForScoring: 3)
        for _ in 0..<5 {
            _ = await engine.observe(event: procEvent(sshIP: "10.0.0.5"))
        }
        let anomalies = await engine.observe(
            event: procEvent(sshIP: "10.0.0.5")
        )
        #expect(!anomalies.contains { $0.kind == .newSSHSource })
    }

    // MARK: - Profile isolation per user

    @Test("Profiles are tracked separately per user")
    func perUserIsolation() async {
        let engine = UEBAEngine(minObservationsForScoring: 3)

        // Alice baseline
        for _ in 0..<5 {
            _ = await engine.observe(event: procEvent(user: "alice", path: "/usr/bin/ls"))
        }
        // Bob first-ever observation with the SAME tool — novel for him.
        let bobAnomalies = await engine.observe(
            event: procEvent(user: "bob", path: "/usr/bin/ls")
        )
        // Cold start — no anomalies for bob.
        #expect(bobAnomalies.isEmpty)

        // Stats
        let s = await engine.stats()
        #expect(s.users == 2)
    }

    // MARK: - Non-process events

    @Test("Non-process events are ignored")
    func ignoresNonProcessEvents() async {
        let engine = UEBAEngine(minObservationsForScoring: 1)
        // Build a file event
        let proc = MacCrabCore.ProcessInfo(
            pid: 1234, ppid: 1, rpid: 1,
            name: "ls", executable: "/usr/bin/ls",
            commandLine: "ls", args: [], workingDirectory: "/",
            userId: 501, userName: "alice", groupId: 20,
            startTime: Date()
        )
        let event = Event(
            eventCategory: .file, eventType: .creation,
            eventAction: "create", process: proc,
            file: FileInfo(
                path: "/tmp/x", name: "x", directory: "/tmp",
                extension_: nil, size: 0, action: .create
            )
        )
        let anomalies = await engine.observe(event: event)
        #expect(anomalies.isEmpty)

        let stats = await engine.stats()
        #expect(stats.totalObservations == 0)
    }

    // MARK: - Empty username

    @Test("Empty username is skipped")
    func emptyUserSkipped() async {
        let engine = UEBAEngine(minObservationsForScoring: 1)
        let anomalies = await engine.observe(event: procEvent(user: ""))
        #expect(anomalies.isEmpty)
        #expect(await engine.stats().users == 0)
    }

    // MARK: - Persistence

    @Test("Profiles save atomically and round-trip through explicit readiness")
    func persistence() async throws {
        let path = NSTemporaryDirectory() + "maccrab_ueba_\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }

        let first = UEBAEngine(minObservationsForScoring: 5, persistencePath: path)
        #expect(await first.loadPersistedProfiles())
        for _ in 0..<10 {
            _ = await first.observe(event: procEvent(user: "alice", sshIP: "10.0.0.5"))
        }
        #expect(await first.save())
        let persisted = try Data(contentsOf: URL(fileURLWithPath: path))
        #expect(!persisted.isEmpty)

        let loaded = await UEBAEngine.loaded(
            minObservationsForScoring: 5,
            persistencePath: path
        )
        let second = try #require(loaded)

        let profile = await second.profile(for: "alice")
        #expect(profile?.totalObservations == 10)
        #expect(profile?.sshRemoteIPs.contains("10.0.0.5") == true)
    }

    @Test("Corrupt persistence is rejected and never clobbered by save")
    func corruptPersistenceIsNotClobbered() async throws {
        let path = NSTemporaryDirectory()
            + "maccrab_ueba_corrupt_\(UUID().uuidString).json"
        let corrupt = Data("{not-valid-json".utf8)
        try corrupt.write(to: URL(fileURLWithPath: path), options: .atomic)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let engine = UEBAEngine(persistencePath: path)
        #expect(await engine.loadPersistedProfiles() == false)
        #expect(await engine.save() == false)
        #expect(try Data(contentsOf: URL(fileURLWithPath: path)) == corrupt)
    }

    @Test("Bare-array persistence migrates through the explicit loader")
    func legacyPersistenceArrayLoads() async throws {
        let path = NSTemporaryDirectory()
            + "maccrab_ueba_legacy_\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }

        var legacy = UserEntityProfile(userName: "alice")
        legacy.totalObservations = 1
        legacy.loginHourCounts[12] = 1
        legacy.weekdayHourCounts[12] = 1
        legacy.weekdayObservations = 1
        legacy.toolUsage["/usr/bin/ls"] = 1
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode([legacy]).write(
            to: URL(fileURLWithPath: path), options: .atomic
        )

        let engine = UEBAEngine(persistencePath: path)
        #expect(await engine.loadPersistedProfiles())
        #expect(await engine.profile(for: "alice")?.totalObservations == 1)
    }

    @Test("Non-regular persistence is rejected without replacement")
    func unreadablePersistenceIsNotReplaced() async throws {
        let path = NSTemporaryDirectory()
            + "maccrab_ueba_directory_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: path) }

        let engine = UEBAEngine(persistencePath: path)
        #expect(await engine.loadPersistedProfiles() == false)
        #expect(await engine.save() == false)
        var isDirectory: ObjCBool = false
        #expect(FileManager.default.fileExists(
            atPath: path,
            isDirectory: &isDirectory
        ))
        #expect(isDirectory.boolValue)
    }

    @Test("Persisted engine has an explicit readiness boundary")
    func persistedReadinessIsExplicit() async {
        let path = NSTemporaryDirectory()
            + "maccrab_ueba_missing_\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }

        let engine = UEBAEngine(
            minObservationsForScoring: 1,
            persistencePath: path
        )
        _ = await engine.observe(event: procEvent(user: "before-ready"))
        #expect(await engine.stats().totalObservations == 0)

        #expect(await engine.loadPersistedProfiles())
        _ = await engine.observe(event: procEvent(user: "after-ready"))
        #expect(await engine.stats().totalObservations == 1)
    }

    @Test("save() with no persistencePath is a safe no-op")
    func saveWithoutPath() async {
        let engine = UEBAEngine(minObservationsForScoring: 5)
        for _ in 0..<3 {
            _ = await engine.observe(event: procEvent())
        }
        // Shouldn't crash or error.
        #expect(await engine.save())
        #expect(await engine.stats().totalObservations == 3)
    }

    @Test("Profile, tool, and SSH entity state stays bounded")
    func entityStateIsBounded() async {
        let engine = UEBAEngine(
            minObservationsForScoring: 100,
            maxProfiles: 2,
            maxToolsPerProfile: 2,
            maxSSHRemoteIPsPerProfile: 2,
            maxAggregateToolEntries: 4,
            maxAggregateSSHRemoteIPEntries: 4,
            maxAggregateEntityUTF8Bytes: 1_024
        )

        for user in ["alice", "bob", "carol"] {
            for index in 0..<3 {
                _ = await engine.observe(event: procEvent(
                    user: user,
                    path: "/tmp/tool-\(index)",
                    sshIP: "192.0.2.\(index + 1)"
                ))
            }
        }

        let profiles = await engine.allProfiles()
        #expect(!profiles.isEmpty && profiles.count <= 2)
        #expect(profiles.allSatisfy { $0.toolUsage.count <= 2 })
        #expect(profiles.allSatisfy { $0.sshRemoteIPs.count <= 2 })
        #expect(profiles.allSatisfy { $0.toolHistorySaturated })
        #expect(profiles.allSatisfy { $0.sshHistorySaturated })
        let capacity = await engine.capacityStats()
        #expect(capacity.profileHistorySaturated)
        #expect(capacity.rejectedProfiles > 0)
        #expect(capacity.evictedTools > 0)
        #expect(capacity.evictedSSHRemoteIPs > 0)
        #expect(capacity.toolEntries <= capacity.maxAggregateToolEntries)
        #expect(
            capacity.sshRemoteIPEntries
                <= capacity.maxAggregateSSHRemoteIPEntries
        )
        #expect(capacity.entityUTF8Bytes <= capacity.maxAggregateEntityUTF8Bytes)
    }

    @Test("Saturated history never turns an evicted entity into false novelty")
    func saturationSuppressesFalseNovelty() async {
        let engine = UEBAEngine(
            minObservationsForScoring: 2,
            maxToolsPerProfile: 2,
            maxSSHRemoteIPsPerProfile: 2,
            maxAggregateToolEntries: 20,
            maxAggregateSSHRemoteIPEntries: 20,
            maxAggregateEntityUTF8Bytes: 4_096
        )

        for _ in 0..<2 {
            _ = await engine.observe(event: procEvent(
                path: "/tmp/tool-a", sshIP: "192.0.2.1"
            ))
        }
        _ = await engine.observe(event: procEvent(
            path: "/tmp/tool-b", sshIP: "192.0.2.2"
        ))

        let saturationEvent = await engine.observe(event: procEvent(
            path: "/tmp/tool-c", sshIP: "192.0.2.3"
        ))
        #expect(!saturationEvent.contains { $0.kind == .novelTool })
        #expect(!saturationEvent.contains { $0.kind == .newSSHSource })

        // The low-water replacement evicted tool-a and 192.0.2.1. Their
        // return must not be described as first-ever after history loss.
        let returningHistory = await engine.observe(event: procEvent(
            path: "/tmp/tool-a", sshIP: "192.0.2.1"
        ))
        #expect(!returningHistory.contains { $0.kind == .novelTool })
        #expect(!returningHistory.contains { $0.kind == .newSSHSource })

        let profile = await engine.profile(for: "alice")
        #expect(profile?.toolHistorySaturated == true)
        #expect(profile?.sshHistorySaturated == true)
        let capacity = await engine.capacityStats()
        #expect(capacity.modelSaturated)
        #expect(capacity.saturatedToolProfiles == 1)
        #expect(capacity.saturatedSSHProfiles == 1)
        #expect(capacity.saturationEvents == 2)
    }

    @Test("Aggregate model budget survives adversarial identity churn")
    func aggregateModelBudgetSurvivesChurn() async {
        let engine = UEBAEngine(
            minObservationsForScoring: 1,
            maxProfiles: 3,
            maxToolsPerProfile: 100,
            maxSSHRemoteIPsPerProfile: 100,
            maxAggregateToolEntries: 3,
            maxAggregateSSHRemoteIPEntries: 2,
            maxAggregateEntityUTF8Bytes: 160
        )

        var firstFullyBoundObservation: [UEBAAnomaly] = []
        for index in 0..<200 {
            let anomalies = await engine.observe(event: procEvent(
                user: "alice",
                path: "/tmp/adversarial-tool-\(index)",
                sshIP: "192.0.2.\(index)"
            ))
            if index == 3 { firstFullyBoundObservation = anomalies }
        }
        for index in 0..<20 {
            _ = await engine.observe(event: procEvent(
                user: "churn-user-\(index)",
                path: "/tmp/user-tool-\(index)"
            ))
        }

        let capacity = await engine.capacityStats()
        let retainedProfiles = await engine.allProfiles()
        let retainedToolEntries = retainedProfiles.reduce(0) {
            $0 + $1.toolUsage.count
        }
        let retainedSSHEntries = retainedProfiles.reduce(0) {
            $0 + $1.sshRemoteIPs.count
        }
        let retainedUTF8Bytes = retainedProfiles.reduce(0) { total, profile in
            total
                + profile.userName.utf8.count
                + profile.toolUsage.keys.reduce(0) { $0 + $1.utf8.count }
                + profile.sshRemoteIPs.reduce(0) { $0 + $1.utf8.count }
        }
        #expect(capacity.profiles <= capacity.maxProfiles)
        #expect(capacity.toolEntries <= 3)
        #expect(capacity.sshRemoteIPEntries <= 2)
        #expect(capacity.entityUTF8Bytes <= 160)
        #expect(capacity.toolEntries == retainedToolEntries)
        #expect(capacity.sshRemoteIPEntries == retainedSSHEntries)
        #expect(capacity.entityUTF8Bytes == retainedUTF8Bytes)
        #expect(capacity.rejectedTools > 0)
        #expect(capacity.rejectedSSHRemoteIPs > 0)
        #expect(capacity.rejectedProfiles > 0)
        #expect(capacity.modelSaturated)
        #expect(capacity.profileHistorySaturated)
        #expect(!firstFullyBoundObservation.contains { $0.kind == .novelTool })
        #expect(!firstFullyBoundObservation.contains { $0.kind == .newSSHSource })

        let rejectedEntityReturns = await engine.observe(event: procEvent(
            user: "alice",
            path: "/tmp/adversarial-tool-199",
            sshIP: "192.0.2.199"
        ))
        #expect(!rejectedEntityReturns.contains { $0.kind == .novelTool })
        #expect(!rejectedEntityReturns.contains { $0.kind == .newSSHSource })
    }

    @Test("Persisted models are re-bounded and retain saturation semantics")
    func persistedModelsRespectAggregateBudget() async throws {
        let path = NSTemporaryDirectory()
            + "maccrab_ueba_aggregate_\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }

        let writer = UEBAEngine(
            minObservationsForScoring: 1,
            persistencePath: path,
            maxProfiles: 10,
            maxToolsPerProfile: 10,
            maxSSHRemoteIPsPerProfile: 10,
            maxAggregateToolEntries: 100,
            maxAggregateSSHRemoteIPEntries: 100,
            maxAggregateEntityUTF8Bytes: 16_384
        )
        #expect(await writer.loadPersistedProfiles())
        for user in ["alice", "bob"] {
            for index in 0..<4 {
                _ = await writer.observe(event: procEvent(
                    user: user,
                    path: "/tmp/loaded-tool-\(index)",
                    sshIP: "198.51.100.\(index)"
                ))
            }
        }
        #expect(await writer.save())

        let loaded = await UEBAEngine.loaded(
            minObservationsForScoring: 1,
            persistencePath: path,
            maxProfiles: 10,
            maxToolsPerProfile: 10,
            maxSSHRemoteIPsPerProfile: 10,
            maxAggregateToolEntries: 2,
            maxAggregateSSHRemoteIPEntries: 1,
            maxAggregateEntityUTF8Bytes: 512
        )
        let reader = try #require(loaded)
        let capacity = await reader.capacityStats()
        let retained = await reader.allProfiles()
        #expect(capacity.toolEntries <= 2)
        #expect(capacity.sshRemoteIPEntries <= 1)
        #expect(capacity.entityUTF8Bytes <= 512)
        #expect(capacity.toolEntries == retained.reduce(0) {
            $0 + $1.toolUsage.count
        })
        #expect(capacity.sshRemoteIPEntries == retained.reduce(0) {
            $0 + $1.sshRemoteIPs.count
        })
        #expect(capacity.entityUTF8Bytes == retained.reduce(0) { total, profile in
            total
                + profile.userName.utf8.count
                + profile.toolUsage.keys.reduce(0) { $0 + $1.utf8.count }
                + profile.sshRemoteIPs.reduce(0) { $0 + $1.utf8.count }
        })
        #expect(capacity.evictedTools > 0)
        #expect(capacity.evictedSSHRemoteIPs > 0)
        #expect(capacity.saturatedToolProfiles > 0)
        #expect(capacity.saturatedSSHProfiles > 0)

        #expect(await reader.save())
        let reloaded = try #require(await UEBAEngine.loaded(
            minObservationsForScoring: 1,
            persistencePath: path,
            maxProfiles: 10,
            maxToolsPerProfile: 10,
            maxSSHRemoteIPsPerProfile: 10,
            maxAggregateToolEntries: 2,
            maxAggregateSSHRemoteIPEntries: 1,
            maxAggregateEntityUTF8Bytes: 512
        ))
        let reloadedProfiles = await reloaded.allProfiles()
        #expect(reloadedProfiles.contains { $0.toolHistorySaturated })
        #expect(reloadedProfiles.contains { $0.sshHistorySaturated })
    }

    @Test("Profile-admission saturation survives restart and larger limits")
    func profileSaturationPersists() async throws {
        let path = NSTemporaryDirectory()
            + "maccrab_ueba_profile_saturation_\(UUID().uuidString).json"
        defer { try? FileManager.default.removeItem(atPath: path) }

        let writer = UEBAEngine(
            minObservationsForScoring: 1,
            persistencePath: path,
            maxProfiles: 1
        )
        #expect(await writer.loadPersistedProfiles())
        _ = await writer.observe(event: procEvent(user: "alice"))
        _ = await writer.observe(event: procEvent(user: "bob"))
        let writerCapacity = await writer.capacityStats()
        #expect(writerCapacity.profileHistorySaturated)
        #expect(await writer.save())

        // A larger cap after restart must not silently relearn identities whose
        // earlier history was refused; that would make old activity novel.
        let loaded = try #require(await UEBAEngine.loaded(
            minObservationsForScoring: 1,
            persistencePath: path,
            maxProfiles: 10
        ))
        _ = await loaded.observe(event: procEvent(user: "charlie"))
        #expect(await loaded.profile(for: "charlie") == nil)
        let capacity = await loaded.capacityStats()
        #expect(capacity.profileHistorySaturated)
        #expect(capacity.rejectedProfiles > 0)
    }

    // MARK: - Off-hours severity escalation

    @Test("Unusual login hour at 3 AM fires high severity")
    func offHoursNightSeverity() async {
        let engine = UEBAEngine(minObservationsForScoring: 20, hourAnomalyThreshold: 0.05)
        let noonBaseline = Calendar.current.date(bySettingHour: 12, minute: 0, second: 0, of: Date())!
        for _ in 0..<20 {
            _ = await engine.observe(event: procEvent(path: "/usr/bin/ls"), now: noonBaseline)
        }
        let nightTime = Calendar.current.date(bySettingHour: 3, minute: 0, second: 0, of: Date())!
        let anomalies = await engine.observe(event: procEvent(path: "/usr/bin/ls"), now: nightTime)
        let hourAnomaly = anomalies.first { $0.kind == .unusualLoginHour }
        #expect(hourAnomaly != nil)
        #expect(hourAnomaly?.severity == .high)
    }

    @Test("Unusual login hour during core hours fires low severity")
    func offHoursCoreSeverity() async {
        // Baseline only at hour 23 — so hour 10 (core hours) is flagged at .low.
        let engine = UEBAEngine(minObservationsForScoring: 20, hourAnomalyThreshold: 0.05)
        let lateNightBaseline = Calendar.current.date(bySettingHour: 23, minute: 0, second: 0, of: Date())!
        for _ in 0..<20 {
            _ = await engine.observe(event: procEvent(path: "/usr/bin/ls"), now: lateNightBaseline)
        }
        let coreHour = Calendar.current.date(bySettingHour: 10, minute: 0, second: 0, of: Date())!
        let anomalies = await engine.observe(event: procEvent(path: "/usr/bin/ls"), now: coreHour)
        let hourAnomaly = anomalies.first { $0.kind == .unusualLoginHour }
        #expect(hourAnomaly != nil)
        #expect(hourAnomaly?.severity == .low)
    }

    // MARK: - Weekday/weekend split

    @Test("Weekday and weekend observation counts are tracked separately")
    func weekdayWeekendSplit() async {
        let engine = UEBAEngine(minObservationsForScoring: 5)
        // Use a known Monday (2026-04-20) for weekday observations.
        var comps = DateComponents()
        comps.year = 2026; comps.month = 4; comps.day = 20; comps.hour = 9
        let monday = Calendar.current.date(from: comps)!
        // Use a known Saturday (2026-04-18) for weekend observations.
        comps.day = 18; comps.hour = 11
        let saturday = Calendar.current.date(from: comps)!

        for _ in 0..<10 {
            _ = await engine.observe(event: procEvent(), now: monday)
        }
        for _ in 0..<6 {
            _ = await engine.observe(event: procEvent(), now: saturday)
        }
        let profile = await engine.profile(for: "alice")
        #expect(profile?.weekdayObservations == 10)
        #expect(profile?.weekendObservations == 6)
        #expect(profile?.weekdayHourCounts[9] == 10)
        #expect(profile?.weekendHourCounts[11] == 6)
    }

    @Test("Old JSON without weekday/weekend fields deserializes gracefully")
    func backwardCompatibleDecode() throws {
        let legacyJSON = """
        [{
            "userName": "alice",
            "firstSeen": "2026-01-01T00:00:00Z",
            "lastObserved": "2026-01-02T00:00:00Z",
            "loginHourCounts": [0,0,0,0,0,0,0,0,0,5,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
            "sshRemoteIPs": [],
            "toolUsage": {"/usr/bin/ls": 5},
            "totalObservations": 5
        }]
        """.data(using: .utf8)!
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let profiles = try decoder.decode([UserEntityProfile].self, from: legacyJSON)
        let p = try #require(profiles.first)
        #expect(p.userName == "alice")
        #expect(p.totalObservations == 5)
        #expect(p.weekdayHourCounts == Array(repeating: 0, count: 24))
        #expect(p.weekendHourCounts == Array(repeating: 0, count: 24))
        #expect(p.weekdayObservations == 0)
        #expect(p.weekendObservations == 0)
        #expect(p.toolHistorySaturated == false)
        #expect(p.sshHistorySaturated == false)
    }

    // MARK: - Anomaly → alert mapping (v1.21.4 EventLoop wiring)

    @Test("Anomaly maps to a stable rule id, title, and MITRE tags per kind")
    func anomalyAlertMapping() {
        let ssh = UEBAAnomaly(kind: .newSSHSource, userName: "alice", detail: "d", severity: .high)
        #expect(ssh.alertRuleId == "maccrab.ueba.newSSHSource")
        #expect(ssh.alertTitle.contains("SSH"))
        #expect(ssh.mitreTactics == "attack.initial_access,attack.lateral_movement")
        #expect(ssh.mitreTechniques == "attack.t1078")

        let hour = UEBAAnomaly(kind: .unusualLoginHour, userName: "alice", detail: "d", severity: .medium)
        #expect(hour.alertRuleId == "maccrab.ueba.unusualLoginHour")
        #expect(hour.mitreTactics == "attack.initial_access")
        #expect(hour.mitreTechniques == "attack.t1078")

        // novelTool is low-signal on its own — no MITRE over-claim.
        let novel = UEBAAnomaly(kind: .novelTool, userName: "alice", detail: "d", severity: .low)
        #expect(novel.alertRuleId == "maccrab.ueba.novelTool")
        #expect(novel.mitreTactics == nil)
        #expect(novel.mitreTechniques == nil)
    }

    @Test("A real observed novel-tool anomaly carries non-empty alert fields")
    func observedAnomalyMapsToAlert() async {
        let engine = UEBAEngine(minObservationsForScoring: 5)
        for _ in 0..<5 { _ = await engine.observe(event: procEvent(path: "/usr/bin/ls")) }
        let anomalies = await engine.observe(event: procEvent(path: "/tmp/never_seen_before"))
        let novel = anomalies.first { $0.kind == .novelTool }
        // These are exactly the fields EventLoop threads into Alert(...).
        #expect(novel != nil)
        #expect(novel?.alertRuleId == "maccrab.ueba.novelTool")
        #expect(novel?.alertTitle.isEmpty == false)
        #expect(novel?.detail.isEmpty == false)
        #expect(novel?.severity == .low)
    }
}
