import Foundation
import Testing
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
