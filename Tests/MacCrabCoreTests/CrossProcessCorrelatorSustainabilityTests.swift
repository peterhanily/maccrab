import Foundation
import Testing
@testable import MacCrabCore

@Suite("Cross-process correlator sustainability and truth")
struct CrossProcessCorrelatorSustainabilityTests {
    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
    }

    @Test("Every unique file insertion enforces the hard artifact cap")
    func fileArtifactFloodIsBoundedAndConserved() async {
        let cap = 32
        let offered = 1_000
        let correlator = CrossProcessCorrelator(
            correlationWindow: 100_000,
            minFileChainLength: offered + 1,
            maxArtifactsPerMap: cap
        )
        let timestamp = Date().addingTimeInterval(60)

        for index in 0..<offered {
            _ = await correlator.recordFileEvent(
                path: "/Users/test/correlation-flood/artifact-\(index)",
                action: "write",
                pid: Int32(index + 1),
                processName: "writer-\(index)",
                processPath: "/opt/flood/writer-\(index)",
                timestamp: timestamp
            )
            #expect(await correlator.trackedFileCount <= cap)
        }

        let snapshot = await correlator.telemetrySnapshot()
        #expect(snapshot.file.acceptedEvents == UInt64(offered))
        #expect(snapshot.file.uniqueArtifactInsertions == UInt64(offered))
        #expect(snapshot.file.trackedArtifacts == cap)
        #expect(snapshot.file.recencyIndexEntries == cap)
        #expect(snapshot.filePIDIndexEntries == cap)
        #expect(snapshot.file.peakTrackedArtifacts == cap)
        #expect(snapshot.file.capacityArtifactsEvicted == UInt64(offered - cap))
        #expect(snapshot.file.evictionSelectionOperations == UInt64(offered - cap))
        #expect(snapshot.file.artifactConservationMaintained)
        #expect(snapshot.file.eventConservationMaintained)
        #expect(snapshot.file.indexConservationMaintained)
        #expect(snapshot.file.constantWorkEvictionMaintained)
        #expect(snapshot.capacityMaintained)
        #expect(snapshot.conservationMaintained)
    }

    @Test("Every unique IP and domain insertion enforces its independent cap")
    func networkAndDomainFloodsAreBoundedAndConserved() async {
        let cap = 17
        let offered = 500
        let correlator = CrossProcessCorrelator(
            correlationWindow: 100_000,
            minChainLength: offered + 1,
            maxArtifactsPerMap: cap
        )
        let timestamp = Date().addingTimeInterval(60)

        for index in 0..<offered {
            _ = await correlator.recordNetworkEvent(
                destinationIP: "198.18.\(index / 250).\((index % 250) + 1)",
                destinationPort: 8443,
                destinationDomain: "host-\(index).attacker.invalid",
                pid: Int32(index + 1),
                processName: "client-\(index)",
                processPath: "/opt/flood/client-\(index)",
                timestamp: timestamp
            )
            #expect(await correlator.trackedNetworkCount <= cap)
            #expect(await correlator.trackedDomainCount <= cap)
        }

        let snapshot = await correlator.telemetrySnapshot()
        for map in [snapshot.network, snapshot.domain] {
            #expect(map.acceptedEvents == UInt64(offered))
            #expect(map.uniqueArtifactInsertions == UInt64(offered))
            #expect(map.trackedArtifacts == cap)
            #expect(map.recencyIndexEntries == cap)
            #expect(map.peakTrackedArtifacts == cap)
            #expect(map.capacityArtifactsEvicted == UInt64(offered - cap))
            #expect(map.evictionSelectionOperations == UInt64(offered - cap))
            #expect(map.artifactConservationMaintained)
            #expect(map.eventConservationMaintained)
            #expect(map.indexConservationMaintained)
            #expect(map.constantWorkEvictionMaintained)
        }
        #expect(snapshot.capacityMaintained)
        #expect(snapshot.conservationMaintained)
    }

    @Test("LRU eviction is deterministic and a touch preserves the artifact")
    func deterministicLRUEviction() async {
        let correlator = CrossProcessCorrelator(
            correlationWindow: 1_000,
            maxArtifactsPerMap: 3
        )
        let now = Date()

        func write(_ path: String, pid: Int32) async {
            _ = await correlator.recordFileEvent(
                path: path,
                action: "write",
                pid: pid,
                processName: "writer-\(pid)",
                processPath: "/opt/writers/writer-\(pid)",
                timestamp: now
            )
        }

        await write("/Users/test/a", pid: 1)
        await write("/Users/test/b", pid: 2)
        await write("/Users/test/c", pid: 3)
        await write("/Users/test/a", pid: 1) // A becomes most-recently used.
        await write("/Users/test/d", pid: 4) // B is the deterministic victim.

        let beforeProbe = await correlator.telemetrySnapshot()
        #expect(beforeProbe.file.trackedArtifacts == 3)
        #expect(beforeProbe.file.capacityArtifactsEvicted == 1)

        let retainedA = await correlator.recordFileEvent(
            path: "/Users/test/a",
            action: "execute",
            pid: 10,
            processName: "payload-a",
            processPath: "/private/tmp/payload-a",
            timestamp: now.addingTimeInterval(1)
        )
        #expect(retainedA != nil, "a touch must keep A resident across the next insertion")
        #expect(retainedA?.distinctPIDCount == 2)

        let evictedB = await correlator.recordFileEvent(
            path: "/Users/test/b",
            action: "execute",
            pid: 20,
            processName: "payload-b",
            processPath: "/private/tmp/payload-b",
            timestamp: now.addingTimeInterval(2)
        )
        #expect(evictedB == nil, "B's original write must have been evicted before this new insertion")
    }

    @Test("Per-artifact trimming participates in exact event conservation")
    func perArtifactEventCapIsConserved() async {
        let correlator = CrossProcessCorrelator(
            correlationWindow: 1_000,
            minFileChainLength: 100,
            maxArtifactsPerMap: 4,
            maxEventsPerArtifact: 4
        )
        let now = Date()

        for index in 0..<20 {
            _ = await correlator.recordFileEvent(
                path: "/Users/test/hot-artifact",
                action: "write",
                pid: Int32(index + 1),
                processName: "hot-writer",
                processPath: "/opt/hot-writer",
                timestamp: now.addingTimeInterval(Double(index))
            )
        }

        let file = await correlator.telemetrySnapshot().file
        #expect(file.acceptedEvents == 20)
        #expect(file.retainedEvents == 4)
        #expect(file.perArtifactEventsEvicted == 16)
        #expect(file.eventConservationMaintained)
        #expect(file.artifactConservationMaintained)
    }

    @Test("Trusted domains require an exact host or DNS label boundary")
    func trustedDomainBoundary() {
        #expect(CrossProcessCorrelator.isTrustedCloudDomain("openai.com"))
        #expect(CrossProcessCorrelator.isTrustedCloudDomain("api.openai.com"))
        #expect(CrossProcessCorrelator.isTrustedCloudDomain("API.OPENAI.COM."))
        #expect(CrossProcessCorrelator.isTrustedCloudDomain("clients2.google.com"))

        #expect(!CrossProcessCorrelator.isTrustedCloudDomain("evilopenai.com"))
        #expect(!CrossProcessCorrelator.isTrustedCloudDomain("openai.com.attacker.invalid"))
        #expect(!CrossProcessCorrelator.isTrustedCloudDomain("evil-openai.com"))
        #expect(!CrossProcessCorrelator.isTrustedCloudDomain(".openai.com"))
        #expect(!CrossProcessCorrelator.isTrustedCloudDomain("openai..com"))
        #expect(!CrossProcessCorrelator.isTrustedCloudDomain("openai.com.."))
    }

    @Test("Lookalike trusted-domain suffix still produces a domain correlation")
    func lookalikeDomainIsNotSuppressed() async {
        let correlator = CrossProcessCorrelator(
            correlationWindow: 300,
            minChainLength: 3
        )
        let now = Date()
        let participants: [(Int32, String, String)] = [
            (101, "dropper", "/private/tmp/dropper"),
            (202, "python", "/Users/test/bin/python"),
            (303, "payload", "/opt/unknown/payload"),
        ]
        var chain: CrossProcessCorrelator.CorrelationChain?
        for (index, participant) in participants.enumerated() {
            chain = await correlator.recordNetworkEvent(
                // Trusted IP prefix suppresses the IP-key result, isolating
                // the domain decision exercised by this test.
                destinationIP: "104.16.10.20",
                destinationPort: 443,
                destinationDomain: "evilopenai.com",
                pid: participant.0,
                processName: participant.1,
                processPath: participant.2,
                timestamp: now.addingTimeInterval(Double(index))
            )
        }

        #expect(chain?.artifactType == "domain")
        #expect(chain?.sharedArtifact == "evilopenai.com")
        #expect(chain?.description.contains("3 distinct PIDs resolved") == true)
    }

    @Test("Source guards preserve bounded state, boundary matching, and truthful copy")
    func sourceAndCopyGuards() throws {
        let source = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabCore/Detection/CrossProcessCorrelator.swift"
            ),
            encoding: .utf8
        )

        #expect(source.contains("private struct ArtifactRecencyIndex"))
        #expect(source.contains("if eventsByKey.count >= maximumArtifacts"))
        #expect(source.contains("recency.removeOldest()"))
        #expect(source.contains("host == trusted || host.hasSuffix(\".\" + trusted)"))
        #expect(!source.contains("lower.hasSuffix(suffix)"))

        #expect(source.contains("public let distinctPIDCount: Int"))
        #expect(source.contains("distinct PIDs contacted"))
        #expect(source.contains("distinct PIDs resolved"))
        #expect(!source.contains("unrelated processes contacted"))
        #expect(!source.contains("unrelated processes resolved"))
        #expect(!source.contains("flagship cross-tree signal"))
        #expect(source.contains("does not claim the PIDs belong to"))
    }
}
