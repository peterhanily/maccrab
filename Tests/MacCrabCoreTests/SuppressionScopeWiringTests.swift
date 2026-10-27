import Foundation
import Testing
@testable import MacCrabAgentKit
@testable import MacCrabCore

/// `maccrabctl allow` writes rule+hash and host entries; the engine's
/// match-aware check must be able to apply them.
@Suite("Hash and host suppression scopes reach the match check")
struct SuppressionScopeWiringTests {
    private func manager() throws -> (SuppressionManager, String) {
        let dir = NSTemporaryDirectory() + "maccrab_supp_scope_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return (SuppressionManager(dataDir: dir), dir)
    }

    private let match = RuleMatch(ruleId: "rule.x", ruleName: "X", severity: .high,
                                  description: "", mitreTechniques: [], tags: [])

    @Test("a rule+hash entry applies to the digest")
    func hashScope() async throws {
        let (mgr, dir) = try manager()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let digest = String(repeating: "ab", count: 32)
        _ = await mgr.add(Suppression(scope: .ruleHash(ruleId: "rule.x", sha256: digest),
                                      source: .cli, reason: "test"))
        #expect(await mgr.isSuppressed(match: match, processPath: "/any", processSHA256: digest))
        #expect(!(await mgr.isSuppressed(match: match, processPath: "/any", processSHA256: nil)))
    }

    @Test("a host entry matches this host's full name or its first label")
    func hostScope() async throws {
        let (mgr, dir) = try manager()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        #expect(!SuppressionManager.localHostName.isEmpty)
        _ = await mgr.add(Suppression(scope: .host("build-mac"), source: .cli, reason: "test"))
        #expect(await mgr.isSuppressed(match: match, processPath: "/p", hostname: "build-mac.local"))
        #expect(await mgr.isSuppressed(match: match, processPath: "/p", hostname: "build-mac"))
        #expect(!(await mgr.isSuppressed(match: match, processPath: "/p", hostname: "other.local")))
        #expect(!(await mgr.isSuppressed(match: match, processPath: "/p", hostname: "")))
    }

    @Test("a same-size rewrite with a restored mtime is hashed again, not served from the cache")
    func hasherCacheIdentity() async throws {
        let path = NSTemporaryDirectory() + "maccrab_hash_\(UUID().uuidString)"
        defer { try? FileManager.default.removeItem(atPath: path) }
        try Data(repeating: 0x41, count: 4096).write(to: URL(fileURLWithPath: path))
        let hasher = FileHasher()
        let original = try #require(await hasher.hash(path: path))

        let mtime = try FileManager.default.attributesOfItem(atPath: path)[.modificationDate] as? Date
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: path))
        try handle.write(contentsOf: Data(repeating: 0x42, count: 4096))
        try handle.close()
        try FileManager.default.setAttributes([.modificationDate: try #require(mtime)], ofItemAtPath: path)
        let rewritten = try #require(await hasher.hash(path: path))
        #expect(rewritten != original)
    }

    @Test("concurrent misses for one file hash it once and leave one LRU entry")
    func concurrentMissesHashOnce() async throws {
        let dir = NSTemporaryDirectory() + "maccrab_hash_join_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let a = dir + "/a", b = dir + "/b"
        try Data(repeating: 0x41, count: 4 << 20).write(to: URL(fileURLWithPath: a))
        try Data(repeating: 0x42, count: 4096).write(to: URL(fileURLWithPath: b))
        let hasher = FileHasher(capacity: 2)
        let digests = await withTaskGroup(of: String?.self) { group in
            for _ in 0..<8 { group.addTask { await hasher.hash(path: a) } }
            var all: [String?] = []
            for await digest in group { all.append(digest) }
            return all
        }
        #expect(Set(digests).count == 1 && digests.allSatisfy { $0 != nil })
        #expect(await hasher.stats().misses == 1)
        _ = await hasher.hash(path: b)
        _ = await hasher.hash(path: a)
        #expect(await hasher.stats().misses == 2, "a is still cached after b joins a two-entry cache")
        #expect(await hasher.cacheCount() == 2)
    }

    // MARK: Image binding

    /// An exec event for `path` carrying the kernel's view of the image when
    /// `image` is given, hashed by the real hasher on the heavy plane.
    private func hashedExec(path: String, image: HeavyEnrichmentFileIdentity?) async throws -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: 7_777, ppid: 1, rpid: 7_777, name: (path as NSString).lastPathComponent,
            executable: path, commandLine: path, args: [path], workingDirectory: "/",
            userId: 501, userName: "u", groupId: 20, startTime: Date())
        var enrichments: [String: String] = [:]
        if let image {
            enrichments[HeavyEnrichmentFileIdentity.execImageEnrichmentKey] = image.serialized
        }
        let event = Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                          eventAction: "exec", process: process, enrichments: enrichments)
        let enricher = EventEnricher(
            processHasher: ProcessHasher(),
            heavyEnrichmentPlane: HeavyEnrichmentPlane(
                configuration: .init(operationTimeoutSeconds: 30),
                liveMemoryBudget: .isolatedProductionEquivalentForTesting()))
        var enriched = await enricher.enrich(event)
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(30))
        while enriched.process.hashes == nil, clock.now < deadline {
            if let patch = await enricher.drainDeferredEnrichments(limit: 16)
                .first(where: { $0.component == .processHashes }) {
                enriched = try #require(patch.applying(to: enriched))
                break
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        _ = await enricher.shutdownHeavyEnrichment()
        return enriched
    }

    private func imageFixture() throws -> (directory: String, path: String, image: HeavyEnrichmentFileIdentity) {
        let directory = NSTemporaryDirectory() + "maccrab_image_bind_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        let path = directory + "/tool"
        try Data(repeating: 0x41, count: 4096).write(to: URL(fileURLWithPath: path))
        return (directory, path, try #require(HeavyEnrichmentFileIdentity.capture(path: path)))
    }

    @Test("a digest hashed from a file renamed onto the exec path never reaches the hash scope")
    func replacedImageDigestIsUnbound() async throws {
        let (directory, path, image) = try imageFixture()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        // The allow-listed binary, renamed onto the path once the process is running.
        let replacement = directory + "/allowlisted"
        try Data(repeating: 0x42, count: 8192).write(to: URL(fileURLWithPath: replacement))
        let allowlisted = try #require(await FileHasher().hash(path: replacement))
        #expect(rename(replacement, path) == 0)
        let (mgr, store) = try manager()
        defer { try? FileManager.default.removeItem(atPath: store) }
        _ = await mgr.add(Suppression(scope: .ruleHash(ruleId: "rule.x", sha256: allowlisted),
                                      source: .cli, reason: "test"))

        let enriched = try await hashedExec(path: path, image: image)
        let hashes = try #require(enriched.process.hashes)
        #expect(hashes.sha256 == allowlisted, "the path now holds the allow-listed bytes")
        #expect(hashes.imageBound == false)
        #expect(SuppressionManager.imageBoundSHA256(hashes) == nil)
        #expect(!(await mgr.isSuppressed(match: match, processPath: path,
                                         processSHA256: SuppressionManager.imageBoundSHA256(hashes))))
        // The raw digest alone would have matched; only the binding keeps the entry away.
        #expect(await mgr.isSuppressed(match: match, processPath: path, processSHA256: hashes.sha256))
    }

    @Test("the digest of an unchanged image is bound and reaches the hash scope")
    func unchangedImageDigestIsBound() async throws {
        let (directory, path, image) = try imageFixture()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let digest = try #require(await FileHasher().hash(path: path))
        let (mgr, store) = try manager()
        defer { try? FileManager.default.removeItem(atPath: store) }
        _ = await mgr.add(Suppression(scope: .ruleHash(ruleId: "rule.x", sha256: digest),
                                      source: .cli, reason: "test"))

        let enriched = try await hashedExec(path: path, image: image)
        let hashes = try #require(enriched.process.hashes)
        #expect(hashes.sha256 == digest)
        #expect(hashes.imageBound == true)
        #expect(SuppressionManager.imageBoundSHA256(hashes) == digest)
        #expect(await mgr.isSuppressed(match: match, processPath: path,
                                       processSHA256: SuppressionManager.imageBoundSHA256(hashes)))
    }

    @Test("without the kernel's image identity no digest is bound")
    func collectorDigestIsUnbound() async throws {
        let (directory, path, _) = try imageFixture()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let enriched = try await hashedExec(path: path, image: nil)
        let hashes = try #require(enriched.process.hashes)
        #expect(hashes.sha256 != nil)
        #expect(hashes.imageBound == false)
        let digest = String(repeating: "ab", count: 32)
        #expect(SuppressionManager.imageBoundSHA256(ProcessHashes(sha256: digest)) == nil)
        #expect(SuppressionManager.imageBoundSHA256(ProcessHashes(sha256: digest, imageBound: false)) == nil)
        #expect(SuppressionManager.imageBoundSHA256(ProcessHashes(sha256: digest, imageBound: true)) == digest)
        #expect(SuppressionManager.imageBoundSHA256(nil) == nil)
    }

    @Test("the engine's suppression decision never offers a laundered digest")
    func engineDecisionUsesBoundDigestOnly() async throws {
        let (directory, path, image) = try imageFixture()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let original = try #require(await FileHasher().hash(path: path))
        let replacement = directory + "/allowlisted"
        try Data(repeating: 0x42, count: 8192).write(to: URL(fileURLWithPath: replacement))
        let allowlisted = try #require(await FileHasher().hash(path: replacement))
        let (mgr, store) = try manager()
        defer { try? FileManager.default.removeItem(atPath: store) }
        for digest in [original, allowlisted] {
            _ = await mgr.add(Suppression(scope: .ruleHash(ruleId: "rule.x", sha256: digest),
                                          source: .cli, reason: "test"))
        }
        // The exec'd image is still in place: its own entry applies.
        let honest = try await hashedExec(path: path, image: image)
        #expect(honest.process.hashes?.sha256 == original)
        #expect(await DaemonState.isSuppressed(match, event: honest, manager: mgr))
        // The allow-listed binary renamed onto the path after exec: the
        // engine is asked exactly as EventLoop and MonitorTasks ask it.
        #expect(rename(replacement, path) == 0)
        let laundered = try await hashedExec(path: path, image: image)
        #expect(laundered.process.hashes?.sha256 == allowlisted)
        #expect(!(await DaemonState.isSuppressed(match, event: laundered, manager: mgr)))
    }

    @Test("a digest is bound only when the hasher read the kernel's image")
    func bindingComparesTheHashedFile() throws {
        let image = HeavyEnrichmentFileIdentity(
            deviceID: 1, inodeNumber: 10, sizeBytes: 4096,
            modificationSeconds: 1_700_000_000, modificationNanoseconds: 0,
            statusChangeSeconds: 1_700_000_000, statusChangeNanoseconds: 0)
        let other = HeavyEnrichmentFileIdentity(
            deviceID: 1, inodeNumber: 11, sizeBytes: 4096,
            modificationSeconds: 1_700_000_000, modificationNanoseconds: 0,
            statusChangeSeconds: 1_700_000_000, statusChangeNanoseconds: 0)
        #expect(EventEnricher.digestIsImageBound(hashed: image, image: image))
        // The path read as the image before and after the hash, but the
        // hasher's own probe found another file: unbound.
        #expect(!EventEnricher.digestIsImageBound(hashed: other, image: image))
        #expect(!EventEnricher.digestIsImageBound(hashed: nil, image: image))
        #expect(!EventEnricher.digestIsImageBound(hashed: image, image: nil))
        #expect(!EventEnricher.digestIsImageBound(hashed: nil, image: nil))
    }

    @Test("the binding is wired to the hasher's identity and the engine to the bound digest")
    func bindingWiring() throws {
        let root = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let enricher = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Enrichment/EventEnricher.swift"), encoding: .utf8)
        #expect(enricher.contains("imageBound: Self.digestIsImageBound(hashed: computed.fileIdentity, image: image)"))
        #expect(!enricher.contains("image == stable"))
        // The image the digest is checked against is the one the hash work is
        // keyed on, so no subscriber can receive another image's binding.
        #expect(enricher.contains("let image = binding.execImageIdentity"))
        let plane = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabCore/Enrichment/HeavyEnrichmentPlane.swift"), encoding: .utf8)
        let hashKey = try #require(plane.range(of: "case .processHashes:\n                // Every subscriber"))
        #expect(plane[hashKey.upperBound...].prefix(700).contains("image: binding.execImageIdentity"))
        let state = try String(contentsOf: root.appendingPathComponent("Sources/MacCrabAgentKit/DaemonState.swift"), encoding: .utf8)
        let instance = try #require(state.range(of: "func isSuppressed(_ match: RuleMatch, event: Event) async -> Bool {"))
        #expect(state[instance.upperBound...].prefix(120).contains("Self.isSuppressed(match, event: event, manager: suppressionManager)"))
    }

    @Test("the kernel's image identity does not travel to the store")
    func imageIdentityIsNotPersisted() async throws {
        let (directory, path, image) = try imageFixture()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let key = HeavyEnrichmentFileIdentity.execImageEnrichmentKey
        let enriched = try await hashedExec(path: path, image: image)
        #expect(enriched.enrichments[key] == nil)
        #expect(enriched.enrichments["enriched"] == "true")
        let store = try EventStore(path: directory + "/events.db")
        try await store.insert(event: enriched)
        let snapshot = try await store.exactEventsSnapshot(since: .distantPast, limit: 10)
        #expect(snapshot.isComplete)
        let row = try #require(snapshot.events.first { $0.id == enriched.id })
        #expect(row.enrichments[key] == nil)
        #expect(row.enrichments["enriched"] == "true", "enrichments do reach the store; the key was removed before")
    }

    // MARK: Per-image hash work

    /// An exec event carrying the kernel's view of the image, with a collector
    /// signature and a user name, so enrichment offers only hash work.
    private func execEvent(path: String, pid: Int32, started: Date,
                           image: HeavyEnrichmentFileIdentity?) -> Event {
        let process = MacCrabCore.ProcessInfo(
            pid: pid, ppid: 1, rpid: pid, name: (path as NSString).lastPathComponent,
            executable: path, commandLine: path, args: [path], workingDirectory: "/",
            userId: 501, userName: "u", groupId: 20, startTime: started,
            codeSignature: CodeSignatureInfo(signerType: .unsigned))
        var enrichments: [String: String] = [:]
        if let image {
            enrichments[HeavyEnrichmentFileIdentity.execImageEnrichmentKey] = image.serialized
        }
        return Event(timestamp: Date(), eventCategory: .process, eventType: .start,
                     eventAction: "exec", process: process, enrichments: enrichments)
    }

    @Test("two execs of one path by one process are hashed and bound per image")
    func reexecIsBoundPerImage() async throws {
        let (directory, path, image) = try imageFixture()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let digest = try #require(await FileHasher().hash(path: path))
        let (mgr, store) = try manager()
        defer { try? FileManager.default.removeItem(atPath: store) }
        _ = await mgr.add(Suppression(scope: .ruleHash(ruleId: "rule.x", sha256: digest),
                                      source: .cli, reason: "test"))
        // The image a later exec of the same path ran: another file than the
        // one the path holds when the hash is taken. Exec keeps the pid and
        // the birth time, so both execs have one process identity.
        let replaced = HeavyEnrichmentFileIdentity(
            deviceID: image.deviceID, inodeNumber: image.inodeNumber &+ 1,
            sizeBytes: image.sizeBytes,
            modificationSeconds: image.modificationSeconds,
            modificationNanoseconds: image.modificationNanoseconds,
            statusChangeSeconds: image.statusChangeSeconds,
            statusChangeNanoseconds: image.statusChangeNanoseconds)

        let plane = HeavyEnrichmentPlane(
            configuration: .init(maximumConcurrentWorkers: 1, operationTimeoutSeconds: 30),
            liveMemoryBudget: .isolatedProductionEquivalentForTesting())
        let enricher = EventEnricher(processHasher: ProcessHasher(), heavyEnrichmentPlane: plane)
        // Hold the plane's only worker, so every hash offer below is queued
        // and a later offer with the same work key joins the earlier one.
        let gate = AsyncStream<Void>.makeStream()
        let holder = execEvent(path: "/usr/bin/true", pid: 999_990, started: Date(), image: nil)
        let held = await plane.offer(component: .environment,
                                     binding: HeavyEnrichmentBinding(event: holder),
                                     cacheResult: false) {
            for await _ in gate.stream { break }
            return .environment(nil)
        }
        guard case .pending = held else {
            Issue.record("the gate did not take the only worker: \(held)")
            return
        }

        let started = Date(timeIntervalSince1970: 1_750_000_000)
        let first = await enricher.enrich(execEvent(path: path, pid: 999_991, started: started, image: image))
        let beforeReexec = await plane.snapshot().coalescedRequestsTotal
        let second = await enricher.enrich(execEvent(path: path, pid: 999_991, started: started, image: replaced))
        #expect(await plane.snapshot().coalescedRequestsTotal == beforeReexec,
                "a different image must not join the earlier exec's hash work")
        let third = await enricher.enrich(execEvent(path: path, pid: 999_992, started: started, image: image))
        let beforeRepeat = await plane.snapshot().coalescedRequestsTotal
        let fourth = await enricher.enrich(execEvent(path: path, pid: 999_992, started: started, image: image))
        #expect(await plane.snapshot().coalescedRequestsTotal == beforeRepeat + 1,
                "the same image still shares one hash")

        gate.continuation.yield()
        gate.continuation.finish()
        let events = [first, second, third, fourth]
        var hashed: [UUID: Event] = [:]
        let clock = ContinuousClock()
        let deadline = clock.now.advanced(by: .seconds(30))
        while hashed.count < events.count, clock.now < deadline {
            for patch in await enricher.drainDeferredEnrichments(limit: 16)
            where patch.component == .processHashes {
                guard let event = events.first(where: { $0.id == patch.binding.eventID }) else { continue }
                hashed[event.id] = try #require(patch.applying(to: event))
            }
            try await Task.sleep(for: .milliseconds(5))
        }
        _ = await enricher.shutdownHeavyEnrichment()

        let original = try #require(hashed[first.id])
        let reexec = try #require(hashed[second.id])
        #expect(original.process.hashes?.imageBound == true)
        #expect(reexec.process.hashes?.sha256 == digest, "the path still holds the first image's bytes")
        #expect(reexec.process.hashes?.imageBound != true)
        #expect(await DaemonState.isSuppressed(match, event: original, manager: mgr))
        #expect(!(await DaemonState.isSuppressed(match, event: reexec, manager: mgr)))
        for event in [third, fourth] {
            let repeated = try #require(hashed[event.id])
            #expect(repeated.process.hashes?.imageBound == true)
            #expect(await DaemonState.isSuppressed(match, event: repeated, manager: mgr))
        }
    }

    @Test("a binding rebuilt from the returned event equals the one its patch carries")
    func bindingEqualityIgnoresImage() throws {
        let (directory, path, image) = try imageFixture()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let started = Date(timeIntervalSince1970: 1_750_000_000)
        let raw = execEvent(path: path, pid: 999_993, started: started, image: image)
        var returned = raw
        returned.enrichments.removeValue(forKey: HeavyEnrichmentFileIdentity.execImageEnrichmentKey)
        let carried = HeavyEnrichmentBinding(event: raw)
        let rebuilt = HeavyEnrichmentBinding(event: returned)
        #expect(carried.execImageIdentity == image)
        #expect(rebuilt.execImageIdentity == nil)
        // The deferred buffer compares these two for an event it retained only
        // as a rejected identity; the image routes work and is not identity.
        #expect(carried == rebuilt)
        #expect(carried.hashValue == rebuilt.hashValue)
        #expect(carried.matches(returned))
        // Every field that names the event still counts.
        #expect(carried != HeavyEnrichmentBinding(event: execEvent(path: path, pid: 999_994, started: started, image: image)))
        #expect(carried != HeavyEnrichmentBinding(event: execEvent(path: path, pid: 999_993, started: started, image: image)),
                "another event of the same process")
        // A new stored field must join the hand-written equality as well.
        #expect(Mirror(reflecting: carried).children.compactMap(\.label) == [
            "eventID", "processID", "processStartTime", "executablePath", "userID",
            "filePath", "eventFileSize", "execImageIdentity",
        ])
    }

    @Test("an image identity survives its enrichment round trip and rejects damage")
    func identitySerialization() throws {
        let identity = HeavyEnrichmentFileIdentity(
            deviceID: 16_777_231, inodeNumber: 42, sizeBytes: 4096,
            modificationSeconds: 1_700_000_000, modificationNanoseconds: 123,
            statusChangeSeconds: 1_700_000_001, statusChangeNanoseconds: 456)
        #expect(HeavyEnrichmentFileIdentity(serialized: identity.serialized) == identity)
        let damaged = ["", "1:2:3", identity.serialized + ":9", "x" + identity.serialized,
                       identity.serialized.replacingOccurrences(of: ".", with: ","),
                       identity.serialized.replacingOccurrences(of: "42", with: "-42")]
        for value in damaged {
            #expect(HeavyEnrichmentFileIdentity(serialized: value) == nil, "\(value)")
        }
    }
}
