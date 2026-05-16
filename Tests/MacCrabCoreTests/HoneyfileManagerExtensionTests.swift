// HoneyfileManagerExtensionTests.swift
// v1.12.0 — Verifies the new package-manager credential bait
// (.npmrc, .pypirc, .gitconfig, GitHub hosts, .cargo/credentials)
// is included in the default deploy set.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.12.0: HoneyfileManager package-credential bait")
struct HoneyfileManagerExtensionTests {

    /// Build a fresh manager rooted in a unique tmp dir so tests don't
    /// touch the real home directory.
    private func makeManager() -> (HoneyfileManager, String) {
        let dir = NSTemporaryDirectory() + "maccrab-honey-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(
            atPath: dir, withIntermediateDirectories: true
        )
        let manager = HoneyfileManager(
            homeDir: dir,
            manifestPath: dir + "/honeyfiles.json"
        )
        return (manager, dir)
    }

    @Test("v1.12.0 package-manager HoneyfileTypes are all defined in the enum")
    func newHoneyfileTypesDefined() {
        let allCases = HoneyfileManager.HoneyfileType.allCases
        let newCases: Set<HoneyfileManager.HoneyfileType> = [
            .npmrc, .pypirc, .gitConfig, .githubHosts, .cargoCredentials,
        ]
        #expect(newCases.isSubset(of: Set(allCases)))
    }

    @Test("Default deploy set includes every v1.12.0 package-manager credential bait path")
    func defaultSetCoversNewTypes() {
        let dir = "/tmp/dummy-home"
        let set = HoneyfileManager.defaultHoneyfileSet(homeDir: dir)
        let paths = Set(set.map { $0.path })
        #expect(paths.contains("\(dir)/.npmrc.bak"))
        #expect(paths.contains("\(dir)/.pypirc.bak"))
        #expect(paths.contains("\(dir)/.gitconfig.bak"))
        #expect(paths.contains("\(dir)/.config/gh/hosts.yml.bak"))
        #expect(paths.contains("\(dir)/.cargo/credentials.toml.bak"))
    }

    @Test("Deploy plants the new bait files and isHoneyfile resolves them")
    func deployRegistersNewBaitPaths() async throws {
        let (manager, dir) = makeManager()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let deployed = try await manager.deploy()
        let baitPaths = [
            "\(dir)/.npmrc.bak",
            "\(dir)/.pypirc.bak",
            "\(dir)/.gitconfig.bak",
            "\(dir)/.config/gh/hosts.yml.bak",
            "\(dir)/.cargo/credentials.toml.bak",
        ]
        for path in baitPaths {
            #expect(FileManager.default.fileExists(atPath: path), "bait not planted at \(path)")
            let isHoney = await manager.isHoneyfile(path)
            #expect(isHoney, "isHoneyfile(\(path)) returned false")
        }
        #expect(deployed.count >= 5)
    }

    @Test(".npmrc bait contains the canonical _authToken format that Shai-Hulud worms scrape")
    func npmrcBaitMatchesWormScrapeFormat() throws {
        let (_, dir) = makeManager()
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let set = HoneyfileManager.defaultHoneyfileSet(homeDir: dir)
        let npmrcBait = set.first { $0.path == "\(dir)/.npmrc.bak" }
        #expect(npmrcBait != nil)
        #expect(npmrcBait?.content.contains("//registry.npmjs.org/:_authToken=") == true)
    }
}
