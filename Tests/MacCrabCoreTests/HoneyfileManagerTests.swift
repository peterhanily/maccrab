// HoneyfileManagerTests.swift
// Deploy/remove, tamper detection, and isHoneyfile() lookup for the
// deception tier.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("HoneyfileManager")
struct HoneyfileManagerTests {

    /// Create an isolated home directory under a temp path so tests don't
    /// touch the real user's ~/.aws, ~/.ssh, etc.
    private func makeSandboxHome() throws -> (home: String, cleanup: () -> Void) {
        let home = NSTemporaryDirectory() + "maccrab_honey_home_\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
        let cleanup: () -> Void = {
            try? FileManager.default.removeItem(atPath: home)
        }
        return (home, cleanup)
    }

    private func makeManifestPath(_ home: String) -> String {
        home + "/honey_manifest.json"
    }

    // MARK: - Deploy

    @Test("Deploy writes every default honeyfile into a clean sandbox")
    func deployClean() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))
        let written = try await mgr.deploy()

        #expect(written.count == HoneyfileManager.HoneyfileType.allCases.count)
        for entry in written {
            #expect(FileManager.default.fileExists(atPath: entry.path),
                    "Expected file at \(entry.path)")
        }
    }

    @Test("Deploy refuses to overwrite a pre-existing real file")
    func deployRefusesOverwrite() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        // Plant a real file at the AWS credentials honeyfile path BEFORE deploy.
        let awsDir = home + "/.aws"
        try FileManager.default.createDirectory(atPath: awsDir, withIntermediateDirectories: true)
        try "real-secret-content".data(using: .utf8)!.write(
            to: URL(fileURLWithPath: awsDir + "/credentials.bak")
        )

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))

        await #expect(throws: HoneyfileManager.HoneyfileError.self) {
            try await mgr.deploy()
        }

        // Real content should still be on disk — we refused, we didn't clobber.
        let content = try String(contentsOfFile: awsDir + "/credentials.bak", encoding: .utf8)
        #expect(content == "real-secret-content")
    }

    @Test("Deployed files are mode 0o400 (owner-read only)")
    func deployFilePermissions() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))
        let written = try await mgr.deploy()

        for entry in written {
            let attrs = try FileManager.default.attributesOfItem(atPath: entry.path)
            let perms = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0
            #expect(perms == 0o400, "Expected 0o400 at \(entry.path), got \(String(perms, radix: 8))")
        }
    }

    @Test("Deployed files carry a believable past mtime (≥ 30 days ago)")
    func deployAgesMtime() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))
        let written = try await mgr.deploy()

        let cutoff = Date(timeIntervalSinceNow: -30 * 86400)
        for entry in written {
            let attrs = try FileManager.default.attributesOfItem(atPath: entry.path)
            let mtime = attrs[.modificationDate] as? Date
            #expect(mtime != nil && mtime! < cutoff,
                    "Expected mtime before \(cutoff) for \(entry.path), got \(String(describing: mtime))")
        }
    }

    // MARK: - isHoneyfile lookup

    @Test("isHoneyfile returns true for deployed paths, false otherwise")
    func isHoneyfileLookup() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))
        let written = try await mgr.deploy()

        for entry in written {
            let isHoney = await mgr.isHoneyfile(entry.path)
            #expect(isHoney, "Expected isHoneyfile to return true for \(entry.path)")
        }

        let notHoney = await mgr.isHoneyfile(home + "/some/random/file.txt")
        #expect(!notHoney)
    }

    // MARK: - Status

    @Test("Status reports all deployed files as present and unchanged")
    func statusCleanDeploy() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))
        _ = try await mgr.deploy()

        let status = await mgr.status()
        #expect(!status.deployed.isEmpty)
        #expect(status.missing.isEmpty)
        #expect(status.tampered.isEmpty)
    }

    @Test("Status flags a tampered file")
    func statusTampered() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))
        let written = try await mgr.deploy()
        let victim = try #require(written.first)

        // Attacker edits (or attempts to read and then rewrites) the canary.
        // We need write permission to change it — relax mode for the test.
        chmod(victim.path, 0o600)
        try "modified by attacker".data(using: .utf8)!.write(
            to: URL(fileURLWithPath: victim.path), options: .atomic
        )

        let status = await mgr.status()
        #expect(status.tampered.contains { $0.path == victim.path })
    }

    @Test("Status flags a missing file")
    func statusMissing() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))
        let written = try await mgr.deploy()
        let victim = try #require(written.first)

        try FileManager.default.removeItem(atPath: victim.path)

        let status = await mgr.status()
        #expect(status.missing.contains { $0.path == victim.path })
    }

    // MARK: - Remove

    @Test("Remove deletes every tracked file and clears manifest")
    func removeClearsEverything() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let mgr = HoneyfileManager(homeDir: home, manifestPath: makeManifestPath(home))
        let written = try await mgr.deploy()
        let paths = written.map(\.path)

        let removed = await mgr.remove()
        #expect(removed.count == written.count)
        #expect(await mgr.deployedCount() == 0)

        for p in paths {
            #expect(!FileManager.default.fileExists(atPath: p),
                    "Expected \(p) to be removed")
        }
    }

    // MARK: - Manifest persistence

    @Test("Manifest survives manager reinitialization")
    func manifestPersistence() async throws {
        let (home, cleanup) = try makeSandboxHome()
        defer { cleanup() }

        let manifest = makeManifestPath(home)
        let mgr1 = HoneyfileManager(homeDir: home, manifestPath: manifest)
        _ = try await mgr1.deploy()
        let originalCount = await mgr1.deployedCount()

        // Let the Task in init finish a save cycle. In practice saveManifest
        // runs synchronously inside deploy(). Belt-and-suspenders: read manifest.
        #expect(FileManager.default.fileExists(atPath: manifest))

        let mgr2 = HoneyfileManager(homeDir: home, manifestPath: manifest)
        // Give the init Task a moment to load the manifest.
        try await Task.sleep(nanoseconds: 50_000_000)

        let reloaded = await mgr2.deployedCount()
        #expect(reloaded == originalCount)
    }

    // MARK: - Canary content markers

    @Test("AWS canary contains recognizable AKIACANARY marker")
    func awsCanaryMarker() {
        let set = HoneyfileManager.defaultHoneyfileSet(homeDir: "/home/test")
        let aws = set.first { $0.type == .awsCredentials }
        #expect(aws?.content.contains("AKIACANARYCRAB") == true,
                "AWS canary should contain a recognizable marker so upstream CloudTrail can alert on use")
    }

    @Test("All canary content includes CANARY/honeytoken markers")
    func allCanaryHaveMarkers() {
        let set = HoneyfileManager.defaultHoneyfileSet(homeDir: "/home/test")
        for entry in set {
            let lower = entry.content.lowercased()
            let hasMarker = lower.contains("canary") ||
                            lower.contains("honeytoken") ||
                            lower.contains("do_not_use") ||
                            lower.contains("do not use")
            #expect(hasMarker,
                    "Canary for \(entry.type) must carry a recognizable marker")
        }
    }
}
