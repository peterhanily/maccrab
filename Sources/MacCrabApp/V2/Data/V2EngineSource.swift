import Foundation
import MacCrabCore

/// One directory owns the engine's stores, heartbeat and diagnostic snapshots.
/// Select once per app session; individual reads and automatic reconnects must
/// never switch sources because another daemon wrote a newer file.
public struct V2EngineSource: Equatable, Sendable {
    public let directory: String

    public init(directory: String) {
        self.directory = URL(fileURLWithPath: directory).standardizedFileURL.path
    }

    public static let session: V2EngineSource = {
        let fm = FileManager.default
        if CommandLine.arguments.contains("-ui-testing"),
           let fixture = ProcessInfo.processInfo.environment["MACCRAB_DATA_DIR"],
           fm.fileExists(atPath: fixture) {
            return V2EngineSource(directory: fixture)
        }
        let user = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first?.appendingPathComponent("MacCrab").path
            ?? NSHomeDirectory() + "/Library/Application Support/MacCrab"
        return select(systemDirectory: "/Library/Application Support/MacCrab",
                      userDirectory: user)
    }()

    static let canonicalFiles = ["heartbeat.json", "heartbeat_rich.json", "sysext_started.json",
                                 "last_crash.json", "alerts.db", "events.db", "campaigns.db",
                                 "tracegraph.db", "traces.db"]

    static func select(systemDirectory: String, userDirectory: String) -> V2EngineSource {
        let fm = FileManager.default
        if canonicalFiles.contains(where: { fm.fileExists(atPath: systemDirectory + "/" + $0) }) {
            return V2EngineSource(directory: systemDirectory)
        }
        if canonicalFiles.contains(where: { fm.fileExists(atPath: userDirectory + "/" + $0) }) {
            return V2EngineSource(directory: userDirectory)
        }
        // First run watches the installed engine's expected location, even
        // before its first heartbeat or database exists.
        return V2EngineSource(directory: systemDirectory)
    }

    func heartbeat(now: Date = Date()) -> V2HeartbeatSnapshot? {
        V2HeartbeatSnapshot.read(directory: directory, now: now)
    }

    /// Read only the small process heartbeat. Missing/stale telemetry must not
    /// indefinitely prevent historical investigation of a stopped engine.
    func defersEventReads(now: Date = Date()) -> Bool {
        guard let data = try? RuntimeConfigurationFiles.readControlData(
            at: directory + "/heartbeat.json", maximumBytes: 64 * 1024),
              let raw = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let written = raw["written_at_unix"] as? Double else { return false }
        return Self.defersEventReads(
            phase: raw["boot_phase"] as? String,
            writtenAt: Date(timeIntervalSince1970: written),
            identity: EngineTelemetryIdentity(heartbeat: raw), now: now)
    }

    static func defersEventReads(
        phase: String?, writtenAt: Date?, identity: EngineTelemetryIdentity?, now: Date
    ) -> Bool {
        guard identity != nil, let writtenAt,
              ["starting", "upgrading_store", "stores_ready", "rules_loaded", "collectors_started"].contains(phase ?? "")
        else { return false }
        let age = now.timeIntervalSince(writtenAt)
        return age.isFinite && age >= 0 && age <= 120
    }
}
