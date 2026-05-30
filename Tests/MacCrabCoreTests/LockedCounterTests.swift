// LockedCounterTests.swift
// MacCrabCoreTests
//
// Regression: v1.17 DEPS-01. The shared event/alert counters in
// DaemonBootstrap were `nonisolated(unsafe) var UInt64` written from the
// event-loop thread while heartbeat timers read them from another thread.
// They are now LockedCounter instances. This verifies LockedCounter is
// safe under concurrent increment: no lost updates and a consistent read.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("LockedCounter")
struct LockedCounterTests {

    @Test("increment returns the post-increment value sequentially")
    func sequentialIncrement() {
        let counter = LockedCounter()
        #expect(counter.get() == 0)
        #expect(counter.increment() == 1)
        #expect(counter.increment() == 2)
        #expect(counter.get() == 2)
    }

    @Test("no lost updates under concurrent increment")
    func concurrentIncrementHasNoLostUpdates() async {
        let counter = LockedCounter()
        let workers = 16
        let perWorker = 5_000

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<workers {
                group.addTask {
                    for _ in 0..<perWorker {
                        counter.increment()
                    }
                }
            }
        }

        // A racy `+= 1` would drop updates; the lock must preserve every one.
        #expect(counter.get() == workers * perWorker)
    }

    @Test("concurrent reads and writes stay coherent")
    func concurrentReadWrite() async {
        let counter = LockedCounter()
        let total = 10_000

        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                for _ in 0..<total { counter.increment() }
            }
            // Reader thread mirrors the heartbeat-timer access pattern.
            group.addTask {
                for _ in 0..<total {
                    let v = counter.get()
                    #expect(v >= 0 && v <= total)
                }
            }
        }

        #expect(counter.get() == total)
    }
}
