// ESIngressStormBenchmarkTests.swift
// MacCrabCoreTests
//
// v1.22.7 ES ingress throughput. Deterministic, in-process, no sleeps. Feeds a
// synthetic build-storm mix (50k OPEN + 20k CLOSE + 4k SIGNAL + lineage) through
// the ingress stages this release changed, and pins the properties that the
// installed-host captures showed were missing:
//
//   1. the callback-boundary cost — the DROP policy that ran inline on the ES
//      handler thread before v1.22.7 (ESClient.h:632 says the next kernel
//      message is dequeued only when the handler returns) versus the
//      field-only callback plus the byte-level protected-OPEN classification
//      it now runs, and the full hand-off (tracker + retain + box + submit);
//   2. the merged-lane routing: a dynamic-AI OPEN flood rides the file lane,
//      credential / agent-content OPENs and lineage stay on priority (attempt4:
//      47,931 admitted OPENs in 30 s rode the priority lane and backlogged it
//      to 76,684, evicting exec/fork/exit);
//   3. the per-client ESMessageWorker reserve: an OPEN flood can consume
//      neither the write-family budget nor a protected OPEN's slot;
//   4. the worker-side cost of a coalesced WRITE repeat (decided before the
//      ProcessInfo/Event build).
//
// The registry used here has the production shape: `ESCollector.
// dynamicAIFileInterestRegistry` holds ONLY the dynamic-AI built-in
// requirement (ESCollector.swift, "Dynamic AI consumers are an additional
// exception"), not the compiled rule corpus.
//
// Every assertion is a GOAL property; the "before" run on the base commit is
// expected to fail the routing and reserve assertions — that failure is the
// measurement. Numbers are printed with a BENCH prefix so a before/after diff
// can be read off the test log. Absolute numbers are debug-build and
// load-dependent; the in-run ratios are not.

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

    private func fileEvent(
        action: String, fileAction: FileAction, path: String, enrichments: [String: String] = [:]
    ) -> Event {
        Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            eventCategory: .file, eventType: .change, eventAction: action,
            process: process(pid: 43, name: "node"),
            file: FileInfo(path: path, action: fileAction),
            enrichments: enrichments
        )
    }

    private func processEvent(action: String, type: EventType = .start) -> Event {
        Event(
            timestamp: Date(timeIntervalSince1970: 1_700_000_000),
            eventCategory: .process, eventType: type, eventAction: action,
            process: process(pid: 43, name: "node")
        )
    }

    /// The system-wide OPEN mix the callback sees: project sources, build
    /// caches, .git objects, framework/Library reads, and a 1% credential /
    /// agent-content slice.
    private func systemOpenPaths() -> [String] {
        var paths: [String] = []
        for i in 0..<100 { paths.append("/Users/x/project/packages/app/src/components/Widget\(i).ts") }
        for i in 0..<60 { paths.append("/Users/x/project/node_modules/.cache/esbuild/chunk-\(i).js") }
        for i in 0..<40 { paths.append("/Users/x/project/.git/objects/ab/\(i)cdef0123456789") }
        for i in 0..<40 { paths.append("/private/var/folders/hf/T/com.apple.dt/cache\(i).bin") }
        for i in 0..<40 { paths.append("/System/Library/Frameworks/Foundation.framework/Versions/C/Resources/\(i).strings") }
        for i in 0..<16 { paths.append("/Users/x/Library/Caches/com.apple.dt.Xcode/DerivedData/\(i).o") }
        paths.append("/Users/x/.ssh/id_ed25519")
        paths.append("/Users/x/.aws/credentials")
        paths.append("/Users/x/.claude/settings.json")
        paths.append("/Users/x/Library/Application Support/Google/Chrome/Default/Login Data")
        return paths
    }

    // MARK: 1. Callback-boundary cost

    @Test("OPEN admission policy: cost per decision for the admitted dynamic-AI storm shape (now on the worker)")
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
                protectedPath: false,
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

    @Test("protected-OPEN classification on raw bytes: cost per OPEN over the system-wide mix, and parity")
    func protectedOpenClassificationCost() {
        let paths = systemOpenPaths()
        let n = 100_000
        var protected = 0
        let start = DispatchTime.now().uptimeNanoseconds
        for i in 0..<n where ESCollector.isProtectedOpenPath(paths[i % paths.count]) {
            protected += 1
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds &- start
        let perDecision = elapsed / UInt64(n)
        print("BENCH protected_open_bytes ns/decision=\(perDecision) protected=\(protected)/\(n) distinct_paths=\(paths.count)")
        let expected = paths.map { ESCollector.isCredentialReadPath($0) || ESCollector.isAgentContentReadPath($0) }
            .filter { $0 }.count
        #expect(protected == expected * (n / paths.count) + (0..<(n % paths.count)).filter {
            ESCollector.isCredentialReadPath(paths[$0]) || ESCollector.isAgentContentReadPath(paths[$0])
        }.count)
        // Budget: the callback thread is the kernel dequeue rate. attempt4
        // offered 3.4-3.9k OPENs/s system-wide and 9.1k file messages/s in the
        // storm window; at this bound the classification costs under 4% of a
        // core there. Debug build, loaded host: the number is the measurement.
        #expect(perDecision <= 10_000, "protected-OPEN byte classification budget (ns/OPEN): \(perDecision)")
    }

    /// In-process A/B on one storm mix: the DROP policy the base handler ran
    /// inline per message versus what the v1.22.7 callback runs — the
    /// field-only policy plus, for every OPEN, the byte-level protected-path
    /// classification. Measuring both in the same run makes the ratio
    /// independent of host load.
    @Test("mixed storm: v1.22.7 callback work vs the inline policy it replaced (100k: 50k OPEN + 20k CLOSE + 4k SIGNAL + 26k lineage)")
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
            // attempt4 split was 41% admitted during the esbuild burst. Every
            // 500th OPEN is a credential read riding inside the flood.
            let path: String
            if i % 500 == 0 {
                path = "/Users/x/.ssh/id_ed25519"
            } else {
                path = (i & 1 == 0) ? textPaths[i & 255] : binaryPaths[i & 255]
            }
            storm.append(Message(type: Self.openType, path: path, closeModified: true, signal: 0, targetPID: 0))
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

        // B: the v1.22.7 callback — field-only drop policy, then for a
        // retained OPEN the byte-level protected classification.
        var keptAfter: [UInt32: Int] = [:]
        var protectedOpens = 0
        let startAfter = DispatchTime.now().uptimeNanoseconds
        for m in storm {
            if ESCollector.shouldDropAtCallback(
                eventType: m.type, closeModified: m.closeModified,
                signal: m.signal, signalTargetPID: m.targetPID,
                signalTargetExecutable: "/usr/local/bin/node"
            ) { continue }
            keptAfter[m.type, default: 0] += 1
            if m.type == Self.openType, let path = m.path, ESCollector.isProtectedOpenPath(path) {
                protectedOpens += 1
            }
        }
        let nanosAfter = DispatchTime.now().uptimeNanoseconds &- startAfter

        let n = UInt64(storm.count)
        let perSecondBefore = nanosBefore == 0 ? UInt64.max : n * 1_000_000_000 / nanosBefore
        let perSecondAfter = nanosAfter == 0 ? UInt64.max : n * 1_000_000_000 / nanosAfter
        func render(_ m: [UInt32: Int]) -> [String] {
            m.map { "\(ESCollector.eventTypeName($0.key))=\($0.value)" }.sorted()
        }
        print("BENCH callback_ab messages=\(n) inline_policy_per_s=\(perSecondBefore) callback_v1227_per_s=\(perSecondAfter) speedup=\(nanosAfter == 0 ? 0 : nanosBefore / nanosAfter)x protected_opens=\(protectedOpens) kept_inline=\(render(keptBefore)) kept_v1227=\(render(keptAfter))")

        #expect(storm.count == 100_000)
        // The v1.22.7 callback retains every OPEN for the worker, flags the
        // credential reads riding inside the flood, still rejects unmodified
        // CLOSE, and drops the signal flood.
        #expect(keptAfter[Self.openType] == 50_000)
        #expect(protectedOpens == 100)
        #expect(keptAfter[Self.closeType] == nil)
        #expect(keptAfter[Self.signalType] == nil, "non-security-tool signals never reach the worker")
        #expect(keptAfter[Self.execType] == 8_667)
        #expect(keptAfter[Self.forkType] == 8_667)
        #expect(keptAfter[Self.exitType] == 8_666)
        // The inline policy kept the whole signal flood for the priority lane.
        #expect(keptBefore[Self.signalType] == 4_000)
        // Floor: the kernel offered 9.1k file messages/s in the attempt4 storm
        // window; the callback must clear that by more than an order of
        // magnitude so it can never be the dequeue bottleneck on a loaded host.
        #expect(perSecondAfter >= 200_000, "v1.22.7 callback floor (messages/s): \(perSecondAfter)")
        #expect(nanosAfter * 10 < nanosBefore, "the v1.22.7 callback must be at least 10x cheaper than the inline policy")
    }

    /// The full hand-off a retained message pays on the callback thread:
    /// tracker.record (D1 seq accounting), the box allocation, the retain and
    /// ESMessageWorker.submit — everything but es_retain_message itself. This
    /// is the number the "callback cost" claim must be read against.
    @Test("hand-off cost per retained message through a draining worker")
    func handoffCostPerMessage() {
        final class Box {
            let startNanos: UInt64
            let eventType: UInt32
            let protectedOpen: Bool
            init(startNanos: UInt64, eventType: UInt32, protectedOpen: Bool) {
                self.startNanos = startNanos
                self.eventType = eventType
                self.protectedOpen = protectedOpen
            }
        }
        let tracker = ESSeqTracker()
        let worker = ESMessageWorker(
            maxInFlight: 4096, label: "bench.handoff", reservesLineageSlots: true,
            process: { _ in },
            free: { handle in Unmanaged<Box>.fromOpaque(handle).release() }
        )
        let n = 100_000
        var accepted = 0
        var paceSpins = 0
        let start = DispatchTime.now().uptimeNanoseconds
        for i in 0..<n {
            if worker.inFlightCount() >= 3072 {
                while worker.inFlightCount() > 2048 {
                    paceSpins += 1
                    if paceSpins > 50_000_000 { break }
                    sched_yield()
                }
            }
            let now = DispatchTime.now().uptimeNanoseconds
            tracker.record(eventType: Self.openType, seqNum: UInt64(i), globalSeq: UInt64(i),
                           callbackUptimeNanoseconds: now)
            let box = Box(startNanos: now, eventType: Self.openType, protectedOpen: false)
            if worker.submit(
                UnsafeRawPointer(Unmanaged.passRetained(box).toOpaque()),
                lineageCritical: ESCollector.usesWorkerReserve(eventType: Self.openType, protectedOpen: false),
                eventType: Self.openType
            ) {
                accepted += 1
            }
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds &- start
        worker.shutdownAndDrain()
        let perMessage = elapsed / UInt64(n)
        let perSecond = elapsed == 0 ? UInt64.max : UInt64(n) * 1_000_000_000 / elapsed
        print("BENCH handoff ns/msg=\(perMessage) msgs_per_s=\(perSecond) accepted=\(accepted)/\(n)")
        #expect(perSecond >= 100_000, "hand-off floor (messages/s): \(perSecond)")
    }

    // MARK: 2. Merged-lane routing

    @Test("a dynamic-AI OPEN flood rides the file lane; credential/agent-content OPENs and lineage stay on priority")
    func openFloodDoesNotRideTheLineageLane() {
        let stamp = [EventPipelineLane.openAdmissionEnrichmentKey: EventPipelineLane.dynamicAIOpenAdmission]
        var dynamicOnPriority = 0
        var dynamicOnFile = 0
        for i in 0..<50_000 {
            let event = fileEvent(
                action: "open", fileAction: .open,
                path: "/Users/x/project/src/module\(i & 255).ts",
                enrichments: stamp
            )
            if EventPipelineLane.finalLane(for: event) == .priority { dynamicOnPriority += 1 } else { dynamicOnFile += 1 }
        }
        var protectedOnPriority = 0
        let protectedPaths = ["/Users/x/.ssh/id_ed25519", "/Users/x/.aws/credentials",
                              "/Users/x/.claude/settings.json", "/Users/x/.claude/skills/x/SKILL.md"]
        for i in 0..<1_000 {
            let event = fileEvent(action: "open", fileAction: .open, path: protectedPaths[i & 3])
            if EventPipelineLane.finalLane(for: event) == .priority { protectedOnPriority += 1 }
        }
        var lineageOnPriority = 0
        for i in 0..<26_000 {
            let action = ["exec", "fork", "exit"][i % 3]
            let event = processEvent(action: action, type: action == "exit" ? .end : .start)
            if EventPipelineLane.finalLane(for: event) == .priority { lineageOnPriority += 1 }
        }
        print("BENCH lane_routing dynamic_open_on_priority=\(dynamicOnPriority) dynamic_open_on_file=\(dynamicOnFile) protected_open_on_priority=\(protectedOnPriority)/1000 lineage_on_priority=\(lineageOnPriority)")
        #expect(lineageOnPriority == 26_000, "lineage always rides the priority lane")
        #expect(dynamicOnPriority == 0, "OPEN volume must not be able to evict lineage from the priority lane")
        #expect(dynamicOnFile == 50_000)
        #expect(protectedOnPriority == 1_000, "credential / agent-content OPENs ride priority, in order with their exec")
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
        // v1.22.7 file-client configuration: reserve held; an ordinary OPEN is never critical.
        let after = writeFamilySurvivesOpenFlood(reservesLineageSlots: true, openIsCritical: false)
        print("BENCH worker_reserve before(open=\(before.openAccepted) write_accepted=\(before.writeAccepted) write_refused=\(before.writeRefused)) after(open=\(after.openAccepted) write_accepted=\(after.writeAccepted) write_refused=\(after.writeRefused))")
        #expect(after.writeRefused == 0, "write-family must never be refused because OPENs filled the budget")
        #expect(after.writeAccepted == 1024)
        #expect(after.openAccepted == 3072)
        // The base configuration is the regression this test exists to catch.
        #expect(before.writeRefused == 1024)
    }

    @Test("file-client worker: a credential or agent-content OPEN is accepted with the ordinary-OPEN slots full")
    func protectedOpenSurvivesOpenFlood() {
        let cap = 4096
        let gate = DispatchSemaphore(value: 0)
        let worker = ESMessageWorker(
            maxInFlight: cap, label: "bench.file-client.protected", reservesLineageSlots: true,
            process: { _ in gate.wait() }, free: { _ in }
        )
        var token = 1
        func handle() -> UnsafeRawPointer {
            token += 1
            return UnsafeRawPointer(bitPattern: token)!
        }
        func submitOpen(_ path: String) -> Bool {
            // Exactly the handler's decision: reserve-eligible iff the raw path
            // is on the static credential / agent-content allowlists.
            worker.submit(
                handle(),
                lineageCritical: ESCollector.usesWorkerReserve(
                    eventType: Self.openType, protectedOpen: ESCollector.isProtectedOpenPath(path)
                ),
                eventType: Self.openType
            )
        }
        var ordinaryAccepted = 0
        for i in 0..<cap where submitOpen("/Users/x/project/src/module\(i & 255).ts") {
            ordinaryAccepted += 1
        }
        let sshAccepted = submitOpen("/Users/x/.ssh/id_ed25519")
        let agentConfigAccepted = submitOpen("/Users/x/.claude/settings.json")
        let decoyAccepted = submitOpen("/Users/x/Library/Application Support/MacCrab/decoys/passwords.txt")
        let ordinaryRefused = !submitOpen("/Users/x/project/README.md")
        let refusedByType = worker.backpressureDroppedByEventType()
        print("BENCH worker_protected_open ordinary_accepted=\(ordinaryAccepted)/\(cap) ssh=\(sshAccepted) agent_config=\(agentConfigAccepted) decoy=\(decoyAccepted) ordinary_refused_after=\(ordinaryRefused) dropped_by_type=\(refusedByType)")
        for _ in 0..<cap { gate.signal() }
        worker.shutdownAndDrain()
        #expect(ordinaryAccepted == 3072, "ordinary OPENs stop at the non-reserved budget")
        #expect(sshAccepted, "a credential OPEN must never be shed behind the OPEN flood")
        #expect(agentConfigAccepted, "an agent-content OPEN must never be shed behind the OPEN flood")
        #expect(decoyAccepted, "a honeyfile OPEN must never be shed behind the OPEN flood")
        #expect(ordinaryRefused, "the flood itself is what gets refused, and it is counted")
        #expect(refusedByType[Self.openType] == 1025)
    }

    // MARK: 4. Coalesced repeat cost on the worker

    @Test("a coalesced WRITE repeat costs the worker the exemption scan and a table probe, before any build")
    func coalescedRepeatCostOnWorker() {
        let coalescer = ESRepeatCoalescer()
        let paths = (0..<256).map { "/Users/x/project/dist/chunk-\($0).js" }
        let n = 100_000
        var coalesced = 0
        var exempt = 0
        let start = DispatchTime.now().uptimeNanoseconds
        for i in 0..<n {
            let path = paths[i & 255]
            // The worker's decision path for an admitted WRITE, in order.
            if ESCollector.isRepeatCoalescingExempt(path: path) {
                exempt += 1
                continue
            }
            if coalescer.shouldCoalesce(path: path, pid: 43, pidversion: 7, kind: .write,
                                        nowNanos: UInt64(i) * 1_000) {
                coalesced += 1
            }
        }
        let elapsed = DispatchTime.now().uptimeNanoseconds &- start
        let perDecision = elapsed / UInt64(n)
        print("BENCH coalesce_decision ns/decision=\(perDecision) coalesced=\(coalesced)/\(n) exempt=\(exempt) entries=\(coalescer.count)")
        #expect(exempt == 0)
        #expect(coalesced == n - 256, "every repeat inside the window folds into the first write")
        #expect(coalescer.count == 256)
        #expect(perDecision <= 5_000, "coalesce decision budget (ns): \(perDecision)")
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
