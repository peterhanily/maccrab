import Dispatch
import Foundation
import Testing
@testable import MacCrabCore

private final class UserNameResolverRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var calls: [UInt32: Int] = [:]
    private var active = 0
    private var maximumActive = 0
    private var results: [UInt32: [String]] = [:]

    func begin(_ uid: UInt32) -> Int {
        lock.lock()
        defer { lock.unlock() }
        calls[uid, default: 0] += 1
        active += 1
        maximumActive = max(maximumActive, active)
        return calls[uid]!
    }

    func end() { lock.lock(); active -= 1; lock.unlock() }

    func record(_ uid: UInt32, _ value: String) {
        lock.lock(); results[uid, default: []].append(value); lock.unlock()
    }

    func callCount(_ uid: UInt32) -> Int {
        lock.lock(); defer { lock.unlock() }; return calls[uid] ?? 0
    }

    var peakResolvers: Int {
        lock.lock(); defer { lock.unlock() }; return maximumActive
    }

    func values(_ uid: UInt32) -> [String] {
        lock.lock(); defer { lock.unlock() }; return results[uid] ?? []
    }
}

/// Every instance receives an inert resolver. No account, filesystem, native
/// collector, store, or shared production-cache access occurs in this suite.
@Suite("Bounded UID name memoization")
struct UserNameCacheTests {
    @Test("Default and oversized requests retain at most 256 entries through ring wraparound",
          arguments: [256, Int.max])
    func boundedCapacity(capacity: Int) {
        let cache = UserNameCache(capacity: capacity, resolver: { "fixture-\($0)" })
        for uid in UInt32(0)..<UInt32(1_024) {
            #expect(cache.name(for: uid) == "fixture-\(uid)")
        }
        let retained = (UInt32(0)..<UInt32(1_024)).filter { cache.lookup($0) != nil }
        #expect(retained == Array(UInt32(768)..<UInt32(1_024)))
        #expect(retained.count == UserNameCache.maximumEntries)
    }

    @Test("FIFO hits do not change eviction order; evicted names are resolved again")
    func fifoAndReresolution() {
        let recorder = UserNameResolverRecorder()
        let cache = UserNameCache(capacity: 3) { uid in
            let call = recorder.begin(uid)
            defer { recorder.end() }
            return "fixture-\(uid)-\(call)"
        }
        for uid in UInt32(1)...UInt32(3) { #expect(cache.name(for: uid) == "fixture-\(uid)-1") }
        #expect(cache.lookup(1) == "fixture-1-1")
        #expect(cache.name(for: 1) == "fixture-1-1")
        #expect(recorder.callCount(1) == 1)
        #expect(cache.name(for: 4) == "fixture-4-1")
        #expect(cache.lookup(1) == nil)
        #expect(cache.lookup(2) == "fixture-2-1")
        #expect(cache.name(for: 1) == "fixture-1-2")
        #expect(cache.lookup(2) == nil)
        #expect(cache.lookup(3) == "fixture-3-1")
        #expect(recorder.callCount(1) == 2)
    }

    @Test("Empty resolved names are cached misses, including after eviction and re-resolution")
    func cachedMisses() {
        let recorder = UserNameResolverRecorder()
        let cache = UserNameCache(capacity: 1) { uid in
            _ = recorder.begin(uid); defer { recorder.end() }; return ""
        }
        #expect(cache.lookup(7) == nil)
        #expect(recorder.callCount(7) == 0)
        #expect(cache.name(for: 7) == "")
        #expect(cache.lookup(7) == "")
        #expect(cache.name(for: 7) == "")
        #expect(recorder.callCount(7) == 1)
        #expect(cache.name(for: 8) == "")
        #expect(cache.lookup(7) == nil)
        #expect(cache.name(for: 7) == "")
        #expect(recorder.callCount(7) == 2)
    }

    @Test("UID extremes and exact Unicode name values are preserved")
    func exactValues() {
        let cache = UserNameCache(capacity: 2) { uid in uid == 0 ? "e\u{301} 用户" : "fixture-max" }
        #expect(cache.name(for: 0).utf8.elementsEqual("e\u{301} 用户".utf8))
        #expect(cache.name(for: UInt32.max) == "fixture-max")
        #expect(cache.lookup(0) == "e\u{301} 用户")
        #expect(cache.lookup(UInt32.max) == "fixture-max")
    }

    @Test("Nonpositive fixture capacities still retain one bounded entry", arguments: [0, Int.min])
    func minimumCapacity(capacity: Int) {
        let cache = UserNameCache(capacity: capacity, resolver: { "fixture-\($0)" })
        #expect(cache.name(for: 1) == "fixture-1")
        #expect(cache.name(for: 2) == "fixture-2")
        #expect(cache.lookup(1) == nil)
        #expect(cache.lookup(2) == "fixture-2")
    }

    @Test("Concurrent calls resolve each resident UID once and keep exact result ownership")
    func concurrentCalls() throws {
        let recorder = UserNameResolverRecorder()
        let cache = UserNameCache(capacity: 32) { uid in
            _ = recorder.begin(uid)
            defer { recorder.end() }
            return "fixture-\(uid)"
        }
        let group = DispatchGroup()
        for index in 0..<128 {
            let uid = UInt32(index % 16)
            group.enter()
            DispatchQueue.global().async {
                recorder.record(uid, cache.name(for: uid))
                group.leave()
            }
        }
        try #require(group.wait(timeout: .now() + 5) == .success)
        for uid in UInt32(0)..<UInt32(16) {
            #expect(recorder.callCount(uid) == 1)
            #expect(recorder.values(uid) == Array(repeating: "fixture-\(uid)", count: 8))
        }
        #expect(recorder.peakResolvers == 1)
    }

    @Test("Different UID misses cannot enter the resolver concurrently")
    func serializedResolution() throws {
        let recorder = UserNameResolverRecorder()
        let firstEntered = DispatchSemaphore(value: 0)
        let releaseFirst = DispatchSemaphore(value: 0)
        let secondStarted = DispatchSemaphore(value: 0)
        let secondEntered = DispatchSemaphore(value: 0)
        let group = DispatchGroup()
        let cache = UserNameCache(capacity: 2) { uid in
            _ = recorder.begin(uid)
            defer { recorder.end() }
            if uid == 1 {
                firstEntered.signal()
                _ = releaseFirst.wait(timeout: .now() + 5)
            } else {
                secondEntered.signal()
            }
            return "fixture-\(uid)"
        }
        defer { releaseFirst.signal(); _ = group.wait(timeout: .now() + 5) }
        group.enter()
        DispatchQueue.global().async { recorder.record(1, cache.name(for: 1)); group.leave() }
        try #require(firstEntered.wait(timeout: .now() + 5) == .success)
        group.enter()
        DispatchQueue.global().async {
            secondStarted.signal()
            recorder.record(2, cache.name(for: 2))
            group.leave()
        }
        try #require(secondStarted.wait(timeout: .now() + 5) == .success)
        // This is a bounded exclusion assertion, not a performance threshold.
        #expect(secondEntered.wait(timeout: .now() + .milliseconds(50)) == .timedOut)
        #expect(recorder.callCount(2) == 0)
        releaseFirst.signal()
        try #require(group.wait(timeout: .now() + 5) == .success)
        #expect(recorder.values(1) == ["fixture-1"])
        #expect(recorder.values(2) == ["fixture-2"])
        #expect(recorder.peakResolvers == 1)
    }

    @Test("Inline lookup returns a cache miss before a blocked resolver is released")
    func busyLookupNeverWaitsForResolver() throws {
        let recorder = UserNameResolverRecorder()
        let entered = DispatchSemaphore(value: 0)
        let release = DispatchSemaphore(value: 0)
        let lookupReturned = DispatchSemaphore(value: 0)
        let group = DispatchGroup()
        let cache = UserNameCache(capacity: 2) { uid in
            if uid == 9 {
                entered.signal()
                _ = release.wait(timeout: .now() + 5)
            }
            return "fixture-\(uid)"
        }
        #expect(cache.name(for: 1) == "fixture-1")
        defer { release.signal(); _ = group.wait(timeout: .now() + 5) }
        group.enter()
        DispatchQueue.global().async { _ = cache.name(for: 9); group.leave() }
        try #require(entered.wait(timeout: .now() + 5) == .success)
        group.enter()
        DispatchQueue.global().async {
            recorder.record(1, cache.lookup(1) ?? "<miss>")
            recorder.record(2, cache.lookup(2) ?? "<miss>")
            lookupReturned.signal()
            group.leave()
        }
        // A blocking lookup cannot satisfy this ordering while the resolver
        // gate remains closed. The deadline bounds fixture failure only.
        try #require(lookupReturned.wait(timeout: .now() + 1) == .success)
        #expect(recorder.values(1) == ["<miss>"])
        #expect(recorder.values(2) == ["<miss>"])
        release.signal()
        try #require(group.wait(timeout: .now() + 5) == .success)
        #expect(cache.lookup(1) == "fixture-1")
        #expect(cache.lookup(9) == "fixture-9")
    }
}
