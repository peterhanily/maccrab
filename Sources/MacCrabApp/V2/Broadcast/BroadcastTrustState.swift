// BroadcastTrustState.swift
//
// Client-side anti-rollback high-water mark for the broadcast feed (docs spec
// §6). Mirrors the catalog's RaveTrustStateStore.decide policy (monotonic
// serial; a strictly-lower sequence on a validly-signed feed is a rollback and
// is rejected) but lives in its OWN small file so the security-critical catalog
// trust store is never touched by this dormant feature.
//
//   <supportDir>/broadcast_trust_state.json  { "schema_version": 1,
//                                              "broadcast_serial": <int>,
//                                              "updated_at": "<ISO8601>" }

import Foundation

enum BroadcastSerialDecision: Equatable {
    case firstSeen
    case accepted
    case rollback(stored: Int, incoming: Int)
}

struct BroadcastTrustStateStore {
    private let path: String

    init(path: String) { self.path = path }

    static func `default`(supportDir: String) -> BroadcastTrustStateStore {
        BroadcastTrustStateStore(path: (supportDir as NSString).appendingPathComponent("broadcast_trust_state.json"))
    }

    var filePath: String { path }

    /// Highest broadcast sequence ever accepted from a signature-verified feed,
    /// or nil if none. A missing/garbage file reads as nil (first-seen).
    func currentSerial() -> Int? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return (obj["broadcast_serial"] as? NSNumber)?.intValue
    }

    /// Pure decision against the persisted mark. Does NOT persist — the caller
    /// advances the mark only after fully accepting the feed.
    func evaluate(incoming: Int) -> BroadcastSerialDecision {
        Self.decide(stored: currentSerial(), incoming: incoming)
    }

    /// Advance the mark to `serial` if greater (idempotent; never lowers it).
    func record(serial: Int) throws {
        if let stored = currentSerial(), stored >= serial { return }
        let payload: [String: Any] = [
            "schema_version": 1,
            "broadcast_serial": serial,
            "updated_at": ISO8601DateFormatter().string(from: Date()),
        ]
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try data.write(to: URL(fileURLWithPath: path), options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }

    static func decide(stored: Int?, incoming: Int) -> BroadcastSerialDecision {
        guard let stored = stored else { return .firstSeen }
        if incoming < stored { return .rollback(stored: stored, incoming: incoming) }
        return .accepted
    }
}
