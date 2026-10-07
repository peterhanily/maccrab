// ESIngressStormBenchmarkTests.swift
// MacCrabCoreTests
//
// v1.22.7 ES ingress throughput. Deterministic, in-process, no sleeps. Feeds a
// synthetic build-storm mix (50k OPEN + 20k CLOSE + 4k SIGNAL + lineage) through
// the three ingress stages this release changed, and pins the properties that
// the installed-host captures showed were missing:
//
//   1. the callback-boundary admission policy cost (the work that ran inline on
//      the ES handler thread before v1.22.7, where ESClient.h:632 says the next
//      kernel message is dequeued only when the handler returns);
//   2. the merged-lane routing of a dynamic-AI OPEN flood (attempt4: 47,931
//      admitted OPENs in 30 s rode the priority lane and backlogged it to
//      76,684, evicting exec/fork/exit);
//   3. the per-client ESMessageWorker reserve (an OPEN flood must not consume
//      the write-family budget on the file client).
//
// Every assertion is a GOAL property; the "before" run on the base commit is
// expected to fail the routing and reserve assertions — that failure is the
// measurement. Numbers are printed with a BENCH prefix so a before/after diff
// can be read off the test log.

import Darwin
import EndpointSecurity
import Foundation
import Testing
@testable import MacCrabCore

@Suite("ES ingress storm benchmark")
struct ESIngressStormBenchmarkTests {
    private static let openType = ES_EVENT_TYPE_NOTIFY_OPEN.rawValue
    private static let closeType = ES_EVENT_TYPE_NOTIFY_CLOSE.rawValue
    private static let writeType = ES_EVENT_TYPE_NOTIFY_WRITE.rawValue
    private static let signalType = ES_EVENT_TYPE_NOTIFY_SIGNAL.rawValue
    private static let execType = ES_EVENT_TYPE_NOTIFY_EXEC.rawValue
    private static let forkType = ES_EVENT_TYPE_NOTIFY_FORK.rawValue
    private static let exitType = ES_EVENT_TYPE_NOTIFY_EXIT.rawValue

    /// An attributed AI session (root 42, child 43, project /Users/x/project) so
    /// ordinary text OPENs by pid 43 are admitted — the storm shape measured on
    /// the maintainer's host with agents running npm/esbuild.
    private func attributedRegistry() -> FileEventInterestPolicyRegistry {
        let registry = FileEventInterestPolicyRegistry()
        _ = registry.install(FileEventInterestDescriptorSnapshot(
            singleEventRules: [],
            sequenceRules: [],
            graphRules: [],
            builtinRequirements: [BuiltinFileEventRequirement(
                id: "bench.dynamic-ai-open",
                sources: [.endpointSecurityFile],
                kind: .dynamicAIConsumers
            )]
        ))
        #expect(registry.publishDynamicAI(.currentCanonical(
            validUntilUptimeNanoseconds: UInt64.max,
            sessions: [DynamicAIFileEventSession(
                rootProcessID: 42,
                childProcessIDs: [43],
                projectRoots: ["/Users/x/project"]
            )]
        )))
        return registry
    }

    private func process(pid: Int32, name: String) -> MacCrabCore.ProcessInfo {
        MacCrabCore.ProcessInfo(
            pid: pid, ppid: 42, rpid: 42,
            name: name, executable: "/usr/local/bin/\(name)",
            commandLine: name, args: [name], workingDirectory: "/Users/x/project",
            userId: 501, userName: "x", groupId: 20,
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            isPlatformBinary: false
        )
    }

    private func fileEvent(action: String, fileAction: FileAction, path: String) -> Event {
        Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            eventCategory: .file, eventType: .change, eventAction: action,
            process: process(pid: 43, name: "node"),
            file: FileInfo(path: path, action: fileAction)
        )
    }

    private func processEvent(action: String, type: EventType = .start) -> Event {
        Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            eventCategory: .process, eventType: type, eventAction: action,
            process: process(pid: 43, name: "node")
        )
    }

    // MARK: 1. Callback-boundary policy cost

    @Test("OPEN admission policy: cost per decision for the admitted dynamic-AI storm shape")
    func openPolicyDecisionCost() {
        let registry = attributedRegistry()
        let paths = (0..<512).map {
            "/Users/x/project/packages/app/src/components/Widget\($0).ts"
        }
        let n = 50_000
        var admitted = 0
        let start = DispatchTime.now().uptimeNanoseconds
        for i in 0..<n {
            if !ESCollector.shouldDropBeforeWorker(
                eventType: Self.openType,
                path: paths[i & 511],
                processID: 43,
                dynamicAIRegistry: registry
            ) {
                admitted += 1
            }
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds &- start
        let perDecision = elapsed / UInt64(n)
        print("BENCH open_policy_admitted ns/decision=\(perDecision) admitted=\(admitted)/\(n)")
        #expect(admitted == n, "attributed text OPENs must be admitted")
        // Bounded-runtime guard only; the number itself is the measurement.
        #expect(perDecision < 5_000_000)
    }

    /// In-process A/B on one storm mix: the policy the base handler ran inline
    /// per message versus the v1.22.7 field-only callback. Measuring both in the
    /// same run makes the ratio independent of host load (sibling test runs
    /// skew absolute numbers by 5x on the maintainer's machine).
    @Test("mixed storm: field-only callback vs the inline policy it replaced (100k: 50k OPEN + 20k CLOSE + 4k SIGNAL + 26k lineage)")
    func mixedStormCallbackAB() {
        let registry = attributedRegistry()
        let textPaths = (0..<256).map { "/Users/x/project/src/module\($0).ts" }
        let binaryPaths = (0..<256).map { "/private/var/folders/hf/T/cache\($0).bin" }

        struct Message {
            let type: UInt32
            let path: String?
            let closeModified: Bool
            let signal: Int32
            let targetPID: Int32
        }
        var storm: [Message] = []
        storm.reserveCapacity(100_000)
        for i in 0..<50_000 {
            // Half admitted text reads, half temp/binary churn — the measured
            // attempt4 split was 41% admitted during the esbuild burst.
            storm.append(Message(
                type: Self.openType,
                path: (i & 1 == 0) ? textPaths[i & 255] : binaryPaths[i & 255],
                closeModified: true, signal: 0, targetPID: 0))
        }
        for _ in 0..<20_000 {
            storm.append(Message(type: Self.closeType, path: "/Users/x/project/src/a.ts",
                                 closeModified: false, signal: 0, targetPID: 0))
        }
        for i in 0..<4_000 {
            // kill(pid, 0) liveness probes and SIGTERM job control at build
            // processes — the measured ~4.1k/s flood shape.
            storm.append(Message(type: Self.signalType, path: nil, closeModified: true,
                                 signal: (i & 3 == 0) ? SIGTERM : 0, targetPID: 4_000 + Int32(i)))
        }
        for i in 0..<26_000 {
            storm.append(Message(type: [Self.execType, Self.forkType, Self.exitType][i % 3],
                                 path: nil, closeModified: true, signal: 0, targetPID: 0))
        }

        // A: what the base callback did inline per message (path policy).
        var keptBefore: [UInt32: Int] = [:]
        let startBefore = DispatchTime.now().uptimeNanoseconds
        for m in storm {
            if !ESCollector.shouldDropBeforeWorker(
                eventType: m.type, path: m.path, closeModified: m.closeModified,
                processID: 43, dynamicAIRegistry: registry
            ) {
                keptBefore[m.type, default: 0] += 1
            }
        }
        let nanosBefore = DispatchTime.now().uptimeNanoseconds &- startBefore

        // B: the v1.22.7 field-only callback.
        var keptAfter: [UInt32: Int] = [:]
        let startAfter = DispatchTime.now().uptimeNanoseconds
        for m in storm {
            if !ESCollector.shouldDropAtCallback(
                eventType: m.type, closeModified: m.closeModified,
                signal: m.signal, signalTargetPID: m.targetPID,
                signalTargetExecutable: "/usr/local/bin/node"
            ) {
                keptAfter[m.type, default: 0] += 1
            }
        }
        let nanosAfter = DispatchTime.now().uptimeNanoseconds &- startAfter

        let n = UInt64(storm.count)
        let perSecondBefore = nanosBefore == 0 ? UInt64.max : n * 1_000_000_000 / nanosBefore
        let perSecondAfter = nanosAfter == 0 ? UInt64.max : n * 1_000_000_000 / nanosAfter
        func render(_ m: [UInt32: Int]) -> [String] {
            m.map { "\(ESCollector.eventTypeName($0.key))=\($0.value)" }.sorted()
        }
        print("BENCH callback_ab messages=\(n) inline_policy_per_s=\(perSecondBefore) field_only_per_s=\(perSecondAfter) speedup=\(nanosAfter == 0 ? 0 : nanosBefore / nanosAfter)x kept_inline=\(render(keptBefore)) kept_field_only=\(render(keptAfter))")

        #expect(storm.count == 100_000)
        // The field-only callback retains every path-dependent type for the
        // worker, still rejects unmodified CLOSE, and drops the signal flood.
        #expect(keptAfter[Self.openType] == 50_000)
        #expect(keptAfter[Self.closeType] == nil)
        #expect(keptAfter[Self.signalType] == nil, "non-security-tool signals never reach the worker")
        #expect(keptAfter[Self.execType] == 8_667)
        #expect(keptAfter[Self.forkType] == 8_667)
        #expect(keptAfter[Self.exitType] == 8_666)
        // The inline policy kept the whole signal flood for the priority lane.
        #expect(keptBefore[Self.signalType] == 4_000)
        // Floor: the kernel offered 9.1k file messages/s in the attempt4 storm
        // window; the callback must clear that by two orders of magnitude so
        // it can never be the dequeue bottleneck, even on a loaded host.
        #expect(perSecondAfter >= 200_000, "field-only callback floor (decisions/s): \(perSecondAfter)")
        #expect(nanosAfter * 10 < nanosBefore, "the field-only callback must be at least 10x cheaper than the inline policy")
    }

    // MARK: 2. Merged-lane routing

    @Test("a dynamic-AI OPEN flood never shares a lane with exec/fork/exit")
    func openFloodDoesNotRideTheLineageLane() {
        var priority = 0
        var file = 0
        var lineageOnPriority = 0
        for i in 0..<50_000 {
            let event = fileEvent(
                action: "open", fileAction: .open,
                path: "/Users/x/project/src/module\(i & 255).ts"
            )
            if EventPipelineLane.finalLane(for: event) == .priority { priority += 1 } else { file += 1 }
        }
        for i in 0..<26_000 {
            let action = ["exec", "fork", "exit"][i % 3]
            let event = processEvent(action: action, type: action == "exit" ? .end : .start)
            if EventPipelineLane.finalLane(for: event) == .priority { lineageOnPriority += 1 }
        }
        print("BENCH lane_routing open_on_priority=\(priority) open_on_file=\(file) lineage_on_priority=\(lineageOnPriority)")
        #expect(lineageOnPriority == 26_000, "lineage always rides the priority lane")
        #expect(priority == 0, "OPEN volume must not be able to evict lineage from the priority lane")
        #expect(file == 50_000)
    }

    // MARK: 3. Worker reserve on the file client

    /// Configure a worker exactly the way the file client does, hold its queue
    /// so nothing drains, fill it with an OPEN flood, then offer write-family
    /// messages. The property: the OPEN flood cannot consume the slots the
    /// write family needs. Deterministic — the gate is a semaphore, not a sleep.
    private func writeFamilySurvivesOpenFlood(
        reservesLineageSlots: Bool,
        openIsCritical: Bool
    ) -> (openAccepted: Int, writeAccepted: Int, writeRefused: Int) {
        let cap = 4096
        let gate = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: cap,
            label: "bench.file-client",
            reservesLineageSlots: reservesLineageSlots,
            process: { _ in gate.wait() },
            free: { _ in }
        )
        var openAccepted = 0
        var writeAccepted = 0
        var writeRefused = 0
        var token = 1
        func handle() -> UnsafeRawPointer {
            token += 1
            return UnsafeRawPointer(bitPattern: token)!
        }
        for _ in 0..<cap {
            if worker.submit(handle(), lineageCritical: openIsCritical, eventType: Self.openType) {
                openAccepted += 1
            }
        }
        for _ in 0..<(cap / 4) {
            if worker.submit(handle(), lineageCritical: true, eventType: Self.writeType) {
                writeAccepted += 1
            } else {
                writeRefused += 1
            }
        }
        // Release every held block so the drain barrier can complete.
        for _ in 0..<cap { gate.signal() }
        worker.shutdownAndDrain()
        return (openAccepted, writeAccepted, writeRefused)
    }

    @Test("file-client worker: an OPEN flood cannot consume the write-family reserve")
    func fileClientWorkerReserveProtectsWriteFamily() {
        // Pre-v1.22.7 file-client configuration: no reserve, every type equal.
        let before = writeFamilySurvivesOpenFlood(reservesLineageSlots: false, openIsCritical: true)
        // v1.22.7 file-client configuration: reserve held; OPEN is never critical.
        let after = writeFamilySurvivesOpenFlood(reservesLineageSlots: true, openIsCritical: false)
        print("BENCH worker_reserve before(open=\(before.openAccepted) write_accepted=\(before.writeAccepted) write_refused=\(before.writeRefused)) after(open=\(after.openAccepted) write_accepted=\(after.writeAccepted) write_refused=\(after.writeRefused))")
        #expect(after.writeRefused == 0, "write-family must never be refused because OPENs filled the budget")
        #expect(after.writeAccepted == 1024)
        #expect(after.openAccepted == 3072)
        // The base configuration is the regression this test exists to catch.
        #expect(before.writeRefused == 1024)
    }

    @Test("paced storm through the worker: zero lineage-critical loss and a submit throughput floor")
    func pacedStormLosesNoLineage() {
        let worker = ESMessageWorker(
            maxInFlight: 4096,
            label: "bench.exec-client",
            reservesLineageSlots: true,
            process: { _ in },
            free: { _ in }
        )
        var token = 1
        var lineageRefused = 0
        var submitted = 0
        var paceSpins = 0
        let start = DispatchTime.now().uptimeNanoseconds
        for i in 0..<100_000 {
            // The kernel delivers at most tens of thousands of messages a
            // second; a bare submit loop runs at >1M/s and would measure GCD
            // block scheduling, not admission. Pace to the drain: whenever the
            // worker holds three quarters of its budget, yield this thread
            // until it has drained below half. Bounded, no sleep.
            if worker.inFlightCount() >= 3072 {
                while worker.inFlightCount() > 2048 {
                    paceSpins += 1
                    if paceSpins > 50_000_000 { break }
                    sched_yield()
                }
            }
            token += 1
            let handle = UnsafeRawPointer(bitPattern: token)!
            let isLineage = i % 4 != 0   // 75k lineage, 25k other
            submitted += 1
            let accepted = worker.submit(
                handle,
                lineageCritical: isLineage,
                eventType: isLineage ? Self.execType : Self.signalType
            )
            if isLineage && !accepted { lineageRefused += 1 }
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds &- start
        worker.shutdownAndDrain()
        let perSecond = elapsed == 0 ? UInt64.max : UInt64(submitted) * 1_000_000_000 / elapsed
        let dropped = worker.backpressureDroppedByEventType()
        print("BENCH worker_storm submitted=\(submitted) submits_per_s=\(perSecond) lineage_refused=\(lineageRefused) dropped_by_type=\(dropped)")
        #expect(lineageRefused == 0)
        #expect(perSecond >= 100_000, "worker submit floor (submits/s): \(perSecond)")
    }
}
