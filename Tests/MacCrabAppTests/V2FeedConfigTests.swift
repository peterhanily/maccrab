// V2FeedConfigTests.swift
// MacCrabAppTests
//
// The Intelligence feed sheet must describe the download contract the engine
// actually enforces: URLhaus and MalwareBazaar refuse to fetch without an
// abuse.ch Auth-Key, and only Feodo's public list is keyless.

import Testing
import Foundation
@testable import MacCrabApp
@testable import MacCrabCore

@Suite("V2FeedConfig — feed key requirements")
struct V2FeedConfigTests {

    private func contractFeed(_ feed: V2FeedConfig) -> ThreatIntelDownloadContract.Feed {
        switch feed {
        case .urlhaus: return .urlhaus
        case .malwareBazaar: return .malwareBazaar
        case .feodoTracker: return .feodo
        }
    }

    @Test("requiresAuthKey matches the engine's download contract")
    func authKeyFlagMatchesContract() {
        for feed in V2FeedConfig.allCases {
            let keylessRequestBuilds = (try? ThreatIntelDownloadContract.request(
                feed: contractFeed(feed), authKey: nil
            )) != nil
            #expect(feed.requiresAuthKey == !keylessRequestBuilds, "\(feed.label)")
        }
    }

    @Test("descriptions call only keyless feeds keyless")
    func descriptionsMatchKeyRequirement() {
        for feed in V2FeedConfig.allCases {
            #expect(feed.description.contains("Keyless") == !feed.requiresAuthKey, "\(feed.label)")
            #expect(feed.description.contains("Auth-Key") == feed.requiresAuthKey, "\(feed.label)")
        }
    }

    @Test("status chip claims fetching for a keyed feed only when a key is stored")
    func fetchStatusFollowsStoredKey() {
        let storedKeyStates: [Bool?] = [true, false, nil]
        for feed in V2FeedConfig.allCases {
            for stored in storedKeyStates {
                #expect(feed.fetchStatus(enrichmentEnabled: false, hasStoredAuthKey: stored) == .optIn)
            }
        }
        #expect(V2FeedConfig.urlhaus.fetchStatus(enrichmentEnabled: true, hasStoredAuthKey: true) == .active)
        #expect(V2FeedConfig.urlhaus.fetchStatus(enrichmentEnabled: true, hasStoredAuthKey: false) == .needsAuthKey)
        // An unreadable Keychain is not proof of a key: state the requirement.
        #expect(V2FeedConfig.malwareBazaar.fetchStatus(enrichmentEnabled: true, hasStoredAuthKey: nil) == .needsAuthKey)
        for stored in storedKeyStates {
            #expect(V2FeedConfig.feodoTracker.fetchStatus(enrichmentEnabled: true, hasStoredAuthKey: stored) == .active)
        }
    }
}
