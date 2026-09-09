import Foundation
import Testing
@testable import MacCrabCore

@Suite("Cross-process file correlation execution signal")
struct CrossProcessCorrelatorExecutionSignalTests {
    @Test("Every rename and cleanup offer stays non-alerting without execution")
    func renameCleanupDoesNotAlert() async {
        // Include the ordinary two-tool shape and unrelated arbitrary actors.
        // No tool-name or path trust exception should be needed for either.
        let actorPairs = [
            [("mv", "/bin/mv"), ("find", "/usr/bin/find")],
            [("producer", "/opt/producer/bin/tool"),
             ("cleaner", "/var/tmp/cleaner/bin/tool")],
        ]
        let now = Date()
        for actors in actorPairs {
            let correlator = CrossProcessCorrelator()
            for (index, action) in ["rename", "unlink"].enumerated() {
                let chain = await correlator.recordFileEvent(
                    path: "/Users/test/correlation/document",
                    action: action,
                    pid: Int32(100 + index),
                    processName: actors[index].0,
                    processPath: actors[index].1,
                    timestamp: now.addingTimeInterval(Double(index))
                )
                #expect(chain == nil, "Every offer must stay non-alerting, including the second PID")
            }
            let snapshot = await correlator.telemetrySnapshot()
            #expect(snapshot.file.acceptedEvents == 2)
            #expect(snapshot.file.retainedEvents == 2)
            #expect(snapshot.file.trackedArtifacts == 1)
            #expect(snapshot.capacityMaintained)
            #expect(snapshot.conservationMaintained)
        }
    }

    @Test("Write, read and unlink remain conserved until a later execution")
    func laterExecutionUsesRetainedObservations() async throws {
        let correlator = CrossProcessCorrelator()
        let path = "/Users/test/correlation/shared-artifact"
        let now = Date()
        let actions = ["write", "read", "unlink"]
        for (index, action) in actions.enumerated() {
            let chain = await correlator.recordFileEvent(
                path: path,
                action: action,
                pid: Int32(200 + index),
                processName: "actor-\(index)",
                processPath: "/opt/actor-\(index)/bin/tool",
                timestamp: now.addingTimeInterval(Double(index))
            )
            #expect(chain == nil)
            let snapshot = await correlator.telemetrySnapshot()
            #expect(snapshot.file.acceptedEvents == UInt64(index + 1))
            #expect(snapshot.file.retainedEvents == index + 1)
            #expect(snapshot.conservationMaintained)
        }

        let result = await correlator.recordFileEvent(
            path: path,
            action: "execute",
            pid: 204,
            processName: "runner",
            processPath: "/opt/runner/bin/tool",
            timestamp: now.addingTimeInterval(3)
        )
        let chain = try #require(result)
        #expect(chain.events.map(\.action) == actions + ["execute"])
        #expect(chain.sharedArtifact == path)
        #expect(chain.distinctPIDCount == 4)
        #expect(chain.severity == .high)
        let snapshot = await correlator.telemetrySnapshot()
        #expect(snapshot.file.acceptedEvents == 4)
        #expect(snapshot.file.retainedEvents == 4)
        #expect(snapshot.filePIDIndexEntries == 1)
        #expect(snapshot.file.capacityEventsEvicted == 0)
        #expect(snapshot.file.perArtifactEventsEvicted == 0)
        #expect(snapshot.capacityMaintained)
        #expect(snapshot.conservationMaintained)
    }

    @Test("Every mixed metadata and write offer remains non-alerting")
    func metadataWithoutExecutionDoesNotAlert() async {
        let correlator = CrossProcessCorrelator()
        let now = Date()
        for (index, action) in ["create", "write", "close_modified", "setmode", "setowner"].enumerated() {
            let chain = await correlator.recordFileEvent(
                path: "/Users/test/correlation/generated-config",
                action: action,
                pid: Int32(300 + index),
                processName: "stage-\(index)",
                processPath: "/opt/stage-\(index)/bin/tool",
                timestamp: now.addingTimeInterval(Double(index))
            )
            #expect(chain == nil)
        }
        let snapshot = await correlator.telemetrySnapshot()
        #expect(snapshot.file.acceptedEvents == 5)
        #expect(snapshot.file.retainedEvents == 5)
        #expect(snapshot.conservationMaintained)
    }

    @Test("Execution with a read retains the existing medium-severity signal")
    func executedArtifactWithoutWriteRemainsMedium() async throws {
        let correlator = CrossProcessCorrelator()
        let now = Date()
        let first = await correlator.recordFileEvent(
            path: "/Users/test/correlation/program",
            action: "read",
            pid: 400,
            processName: "reader",
            processPath: "/opt/reader/bin/tool",
            timestamp: now
        )
        #expect(first == nil)
        let result = await correlator.recordFileEvent(
            path: "/Users/test/correlation/program",
            action: "execute",
            pid: 401,
            processName: "executor",
            processPath: "/opt/executor/bin/tool",
            timestamp: now.addingTimeInterval(1)
        )
        let chain = try #require(result)
        #expect(chain.severity == .medium)
        #expect(chain.distinctPIDCount == 2)
        #expect(chain.events.map(\.action) == ["read", "execute"])
        #expect(await correlator.telemetrySnapshot().conservationMaintained)
    }
}
