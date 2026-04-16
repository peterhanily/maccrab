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
}
