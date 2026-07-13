// ESForensicMuteTargetsTests.swift
// v1.21.4 Phase-1 Mitigation A — unit coverage for the observer-effect
// TARGET-mute prefix builder. The live es_mute_path_events call is ES-only
// (needs a root, entitled es_client_t), but the path logic that decides WHICH
// prefixes to target-mute is pure and testable: the fixed root support dir
// plus each console user's home MacCrab dir (where the dashboard writes
// forensic Cases snapshots).

import Testing
import Foundation
import EndpointSecurity
@testable import MacCrabCore

@Suite("Mitigation A: forensic-copy target-mute prefixes")
struct ESForensicMuteTargetsTests {

    @Test("always includes the root support dir prefix")
    func includesRootSupportDir() {
        let prefixes = ESCollector.forensicCopyMuteTargetPrefixes(userHomes: [])
        #expect(prefixes.contains("/Library/Application Support/MacCrab/"))
        #expect(prefixes.count == 1)
    }

    @Test("adds each user home's MacCrab dir (the dashboard's Cases snapshot root)")
    func addsPerUserHomes() {
        let prefixes = ESCollector.forensicCopyMuteTargetPrefixes(
            userHomes: ["/Users/alice", "/Users/bob"]
        )
        #expect(prefixes.contains("/Library/Application Support/MacCrab/"))
        #expect(prefixes.contains("/Users/alice/Library/Application Support/MacCrab/"))
        #expect(prefixes.contains("/Users/bob/Library/Application Support/MacCrab/"))
        #expect(prefixes.count == 3)
    }

    @Test("a trailing slash on a user home is normalized (no doubled slash)")
    func normalizesTrailingSlash() {
        let prefixes = ESCollector.forensicCopyMuteTargetPrefixes(userHomes: ["/Users/carol/"])
        #expect(prefixes.contains("/Users/carol/Library/Application Support/MacCrab/"))
        #expect(!prefixes.contains { $0.contains("//Library") })
    }

    @Test("muted event set is the write-family only (never NOTIFY_OPEN — decoy reads must survive)")
    func mutedEventSetIsWriteFamilyOnly() {
        let events = ESCollector.forensicCopyMutedEventTypes
        #expect(events.contains(ES_EVENT_TYPE_NOTIFY_CREATE))
        #expect(events.contains(ES_EVENT_TYPE_NOTIFY_WRITE))
        #expect(events.contains(ES_EVENT_TYPE_NOTIFY_CLOSE))
        #expect(events.contains(ES_EVENT_TYPE_NOTIFY_RENAME))
        #expect(events.contains(ES_EVENT_TYPE_NOTIFY_UNLINK))
        #expect(!events.contains(ES_EVENT_TYPE_NOTIFY_OPEN))
        #expect(events.count == 5)
    }
}
