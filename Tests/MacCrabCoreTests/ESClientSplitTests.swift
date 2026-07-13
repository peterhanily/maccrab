// ESClientSplitTests.swift
// v1.21.4 Phase-4 (Mitigation C) — file/exec ES client split.
//
// The live dual-client path (es_new_client × 2, per-queue kernel backpressure)
// is ES-only: it needs a root, entitled es_client_t that only a live system can
// produce (the same limitation ESCollectorDispatchTests notes). So this suite
// exercises the PURE, synthesizable seams the split is built from:
//
//   1. The subscription PARTITION — `fileClientTypes` / `execClientTypes` split
//      the full pre-split subscription set so every type lands on exactly ONE
//      client (union == full, intersection == ∅, no doubling). This is the
//      load-bearing invariant: a lost type = a blind spot; a doubled type = a
//      double-count in the merged accessors.
//   2. The graceful-fallback DECISION — `shouldDegradeToSingleClient` (second
//      client fails ⇒ single all-types client + degraded flag).
//   3. The read-path MERGE — `mergeCountMaps` (union of the two disjoint
//      per-queue trackers), including the "money test" measurement shape (a file
//      queue with drops + an exec queue with none, merged losslessly).

import Testing
import Foundation
import EndpointSecurity
@testable import MacCrabCore

@Suite("Phase-4 Mitigation C: file/exec ES client split")
struct ESClientSplitTests {

    private static func rawSet(_ t: [es_event_type_t]) -> Set<UInt32> { Set(t.map { $0.rawValue }) }

    // MARK: - Partition completeness + disjointness

    @Test("partition is complete and disjoint for every flag combination")
    func partitionCompleteDisjoint() {
        for open in [false, true] {
            for intro in [false, true] {
                let file = ESCollector.fileClientTypes(subscribeFileOpen: open, subscribeIntrospection: intro)
                let exec = ESCollector.execClientTypes(subscribeFileOpen: open, subscribeIntrospection: intro)
                let full = ESCollector.fullSubscription(subscribeFileOpen: open, subscribeIntrospection: intro)

                let fileSet = Self.rawSet(file)
                let execSet = Self.rawSet(exec)
                let fullSet = Self.rawSet(full)

                // Disjoint: no type on both clients (no double-count).
                #expect(fileSet.isDisjoint(with: execSet), "open=\(open) intro=\(intro): file/exec overlap")
                // Union == full: no type lost.
                #expect(fileSet.union(execSet) == fullSet, "open=\(open) intro=\(intro): union != full")
                // Counts add up ⇒ neither client has an internal duplicate either.
                #expect(file.count + exec.count == full.count)
                #expect(fileSet.count == file.count)   // no dupes within the file client
                #expect(execSet.count == exec.count)   // no dupes within the exec client
            }
        }
    }

    // MARK: - Membership (which types on which client)

    @Test("file client is exactly the write-family (+ OPEN when enabled)")
    func fileClientMembership() {
        let writeFamily = Self.rawSet([
            ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_WRITE,
            ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_RENAME,
            ES_EVENT_TYPE_NOTIFY_UNLINK,
        ])
        // Introspection flag must not affect the file client's membership.
        let noOpen = Self.rawSet(ESCollector.fileClientTypes(subscribeFileOpen: false, subscribeIntrospection: true))
        #expect(noOpen == writeFamily)
        let withOpen = Self.rawSet(ESCollector.fileClientTypes(subscribeFileOpen: true, subscribeIntrospection: false))
        #expect(withOpen == writeFamily.union([ES_EVENT_TYPE_NOTIFY_OPEN.rawValue]))
    }

    @Test("exec client carries process lineage + low-volume family (+ introspection when enabled)")
    func execClientMembership() {
        let base = Self.rawSet([
            ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_SIGNAL, ES_EVENT_TYPE_NOTIFY_KEXTLOAD,
            ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD, ES_EVENT_TYPE_NOTIFY_MMAP,
            ES_EVENT_TYPE_NOTIFY_MPROTECT, ES_EVENT_TYPE_NOTIFY_SETOWNER, ES_EVENT_TYPE_NOTIFY_SETMODE,
        ])
        let introspection = Self.rawSet([
            ES_EVENT_TYPE_NOTIFY_GET_TASK_READ, ES_EVENT_TYPE_NOTIFY_TRACE,
            ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ])
        // OPEN flag must not affect the exec client's membership.
        let noIntro = Self.rawSet(ESCollector.execClientTypes(subscribeFileOpen: true, subscribeIntrospection: false))
        #expect(noIntro == base)
        let withIntro = Self.rawSet(ESCollector.execClientTypes(subscribeFileOpen: false, subscribeIntrospection: true))
        #expect(withIntro == base.union(introspection))
    }

    @Test("OPEN rides the file client only, and only when subscribeFileOpen is set")
    func openGatingAndRouting() {
        // Never on the exec client, even with both flags on.
        let execBoth = Self.rawSet(ESCollector.execClientTypes(subscribeFileOpen: true, subscribeIntrospection: true))
        #expect(!execBoth.contains(ES_EVENT_TYPE_NOTIFY_OPEN.rawValue))
        // Present on the file client iff the flag is set.
        #expect(!Self.rawSet(ESCollector.fileClientTypes(subscribeFileOpen: false, subscribeIntrospection: true)).contains(ES_EVENT_TYPE_NOTIFY_OPEN.rawValue))
        #expect(Self.rawSet(ESCollector.fileClientTypes(subscribeFileOpen: true, subscribeIntrospection: true)).contains(ES_EVENT_TYPE_NOTIFY_OPEN.rawValue))
    }

    @Test("full subscription (degraded fallback set) equals the whole pre-split set")
    func fullSubscriptionMatchesPreSplit() {
        let full = Self.rawSet(ESCollector.fullSubscription(subscribeFileOpen: true, subscribeIntrospection: true))
        let expected = Self.rawSet([
            ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
            ES_EVENT_TYPE_NOTIFY_CREATE, ES_EVENT_TYPE_NOTIFY_WRITE, ES_EVENT_TYPE_NOTIFY_CLOSE,
            ES_EVENT_TYPE_NOTIFY_RENAME, ES_EVENT_TYPE_NOTIFY_UNLINK, ES_EVENT_TYPE_NOTIFY_SIGNAL,
            ES_EVENT_TYPE_NOTIFY_KEXTLOAD, ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
            ES_EVENT_TYPE_NOTIFY_MMAP, ES_EVENT_TYPE_NOTIFY_MPROTECT,
            ES_EVENT_TYPE_NOTIFY_SETOWNER, ES_EVENT_TYPE_NOTIFY_SETMODE, ES_EVENT_TYPE_NOTIFY_OPEN,
            ES_EVENT_TYPE_NOTIFY_GET_TASK_READ, ES_EVENT_TYPE_NOTIFY_TRACE,
            ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE, ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
        ])
        #expect(full == expected)
    }

    // MARK: - Graceful-fallback decision

    @Test("degrade decision: SUCCESS keeps the split; any error degrades to one client")
    func degradeDecision() {
        #expect(ESCollector.shouldDegradeToSingleClient(secondClientResult: ES_NEW_CLIENT_RESULT_SUCCESS) == false)
        #expect(ESCollector.shouldDegradeToSingleClient(secondClientResult: ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS) == true)
        #expect(ESCollector.shouldDegradeToSingleClient(secondClientResult: ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED) == true)
        #expect(ESCollector.shouldDegradeToSingleClient(secondClientResult: ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED) == true)
    }

    // MARK: - Read-path merge (union of two disjoint per-queue trackers)

    @Test("count-map merge is a union for disjoint keys and a sum for shared keys")
    func mergeCountMaps() {
        let a: [UInt32: UInt64] = [1: 10, 2: 20]
        let b: [UInt32: UInt64] = [3: 30, 4: 40]
        #expect(ESCollector.mergeCountMaps([a, b]) == [1: 10, 2: 20, 3: 30, 4: 40])

        // Shared key (degraded single client, or defensive) sums.
        #expect(ESCollector.mergeCountMaps([[1: 5, 2: 7], [2: 3, 5: 9]]) == [1: 5, 2: 10, 5: 9])

        #expect(ESCollector.mergeCountMaps([]).isEmpty)
        #expect(ESCollector.mergeCountMaps([[:], [:]]).isEmpty)
    }

    @Test("two per-queue trackers over disjoint types merge losslessly (the money-test shape)")
    func perQueueTrackerMergeIsLossless() {
        let write = ES_EVENT_TYPE_NOTIFY_WRITE.rawValue
        let exec = ES_EVENT_TYPE_NOTIFY_EXEC.rawValue

        // FILE queue tracker: a WRITE gap (seq 2 and 3 dropped ⇒ 2).
        let fileTracker = ESSeqTracker()
        fileTracker.record(eventType: write, seqNum: 1, globalSeq: 1)
        fileTracker.record(eventType: write, seqNum: 4, globalSeq: 4)

        // EXEC queue tracker: contiguous exec seqs ⇒ ZERO drops. This is the whole
        // point of the split — the file flood cannot starve exec's own queue.
        let execTracker = ESSeqTracker()
        execTracker.record(eventType: exec, seqNum: 1, globalSeq: 1)
        execTracker.record(eventType: exec, seqNum: 2, globalSeq: 2)

        let merged = ESCollector.mergeCountMaps([fileTracker.droppedByType(), execTracker.droppedByType()])
        #expect(merged[write] == 2)                        // file drops preserved
        #expect((merged[exec] ?? 0) == 0)                  // exec unharmed by the file flood
    }

    // MARK: - Event-type name coverage (heartbeat keying of the merged maps)

    @Test("every partitioned type has a stable heartbeat name (no TYPE_<raw> leaks)")
    func everyPartitionedTypeIsNamed() {
        let full = ESCollector.fullSubscription(subscribeFileOpen: true, subscribeIntrospection: true)
        for t in full {
            let name = ESCollector.eventTypeName(t.rawValue)
            #expect(!name.hasPrefix("TYPE_"), "unnamed subscribed type raw=\(t.rawValue)")
        }
    }
}
