import Foundation
import Darwin
import Testing
@testable import MacCrabCore

@Suite("Privileged real-user-home contract")
struct RealUserHomeResolverTests {
    private func temporaryDirectory() throws -> URL {
        // macOS's `/var` and `/tmp` are symlink aliases, and NSString's
        // standardizingPath rewrites `/private/var` back to `/var`. An
        // O_NOFOLLOW fixture rooted there therefore fails at the alias before
        // reaching the directory under test. Keep fixtures in the physical
        // /Users-backed package build directory instead.
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let fixtureRoot = repository.appendingPathComponent(".build/maccrab-test-fixtures")
        try FileManager.default.createDirectory(
            at: fixtureRoot,
            withIntermediateDirectories: true
        )
        let url = fixtureRoot
            .appendingPathComponent("maccrab-real-home-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test("candidate requires no-follow directory, owner uid, passwd home, and passwd name agreement")
    func candidateValidation() throws {
        guard geteuid() != 0 else { return }
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }

        let uid = UInt32(geteuid())
        #expect(RealUserHomeResolver.validateCandidate(
            path: root.path,
            expectedUID: uid,
            expectedUserName: "fixture",
            passwdHome: root.path,
            passwdUserName: "fixture"
        ))
        #expect(!RealUserHomeResolver.validateCandidate(
            path: root.path,
            expectedUID: uid,
            expectedUserName: "fixture",
            passwdHome: root.path + "-other",
            passwdUserName: "fixture"
        ))
        #expect(!RealUserHomeResolver.validateCandidate(
            path: root.path,
            expectedUID: uid,
            expectedUserName: "fixture",
            passwdHome: root.path,
            passwdUserName: "other"
        ))
        #expect(!RealUserHomeResolver.validateCandidate(
            path: root.path,
            expectedUID: uid &+ 1,
            expectedUserName: "fixture",
            passwdHome: root.path,
            passwdUserName: "fixture"
        ))

        let link = root.deletingLastPathComponent()
            .appendingPathComponent("maccrab-home-link-\(UUID().uuidString)")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
        defer { try? FileManager.default.removeItem(at: link) }
        #expect(!RealUserHomeResolver.validateCandidate(
            path: link.path,
            expectedUID: uid,
            expectedUserName: "fixture",
            passwdHome: link.path,
            passwdUserName: "fixture"
        ))
    }

    @Test("multi-user selection and uid/path disagreement fail closed")
    func ambiguityAndMismatch() {
        let alice = RealUserHome(path: "/Users/alice", userID: 501, userName: "alice")
        let bob = RealUserHome(path: "/Users/bob", userID: 502, userName: "bob")
        #expect(RealUserHomeResolver.uniqueHome(from: []) == nil)
        #expect(RealUserHomeResolver.uniqueHome(from: [alice]) == alice)
        #expect(RealUserHomeResolver.uniqueHome(from: [alice, bob]) == nil)
        #expect(RealUserHomeResolver.reconcile(pathHome: alice, uidHome: alice) == alice)
        #expect(RealUserHomeResolver.reconcile(pathHome: nil, uidHome: alice) == alice)
        #expect(RealUserHomeResolver.reconcile(pathHome: bob, uidHome: alice) == nil)
        #expect(RealUserHomeResolver.reconcile(pathHome: alice, uidHome: nil) == nil)
        #expect(RealUserHomeResolver.reconcileProvenance(
            path: "/Users/forged/Downloads/payload",
            pathHome: nil,
            uidHome: alice
        ) == nil)
        #expect(RealUserHomeResolver.reconcileProvenance(
            path: "/Users",
            pathHome: nil,
            uidHome: alice
        ) == nil)
        #expect(RealUserHomeResolver.reconcileProvenance(
            path: "/Users/Shared/payload",
            pathHome: nil,
            uidHome: alice
        ) == alice)
        #expect(RealUserHomeResolver.reconcileProvenance(
            path: "/Applications/App.app/Contents/MacOS/App",
            pathHome: nil,
            uidHome: alice
        ) == alice)
    }

    @Test("path ownership metadata never opens a FIFO or follows a symlink carrier")
    func noFollowOwnerMetadata() throws {
        guard geteuid() != 0 else { return }
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let uid = UInt32(geteuid())

        let fifo = root.appendingPathComponent("carrier.fifo")
        #expect(mkfifo(fifo.path, 0o600) == 0)
        #expect(RealUserHomeResolver.noFollowOwner(of: fifo.path) == uid)

        let regular = root.appendingPathComponent("regular")
        try Data().write(to: regular)
        let leafLink = root.appendingPathComponent("leaf-link")
        try FileManager.default.createSymbolicLink(at: leafLink, withDestinationURL: regular)
        #expect(RealUserHomeResolver.noFollowOwner(of: leafLink.path) == nil)

        let directory = root.appendingPathComponent("directory")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let nested = directory.appendingPathComponent("nested")
        try Data().write(to: nested)
        let directoryLink = root.appendingPathComponent("directory-link")
        try FileManager.default.createSymbolicLink(at: directoryLink, withDestinationURL: directory)
        #expect(RealUserHomeResolver.noFollowOwner(
            of: directoryLink.appendingPathComponent("nested").path
        ) == nil)
    }

    @Test("directory listing is no-follow and counts every raw entry toward its cap")
    func boundedDirectoryListing() throws {
        guard geteuid() != 0 else { return }
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let uid = UInt32(geteuid())
        for index in 0..<12 {
            try Data().write(to: root.appendingPathComponent("entry-\(index)"))
        }
        let snapshot = try #require(BoundedDirectoryLister.list(
            at: root.path,
            maximumEntries: 4,
            expectedOwnerUID: uid
        ))
        #expect(snapshot.entries.count <= 4)
        #expect(snapshot.inspectedEntryCount == 4)
        #expect(snapshot.wasTruncated)

        let link = root.deletingLastPathComponent()
            .appendingPathComponent("maccrab-list-link-\(UUID().uuidString)")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root)
        defer { try? FileManager.default.removeItem(at: link) }
        #expect(BoundedDirectoryLister.list(
            at: link.path,
            maximumEntries: 4,
            expectedOwnerUID: uid
        ) == nil)

        let fifo = root.deletingLastPathComponent()
            .appendingPathComponent("maccrab-list-fifo-\(UUID().uuidString)")
        #expect(mkfifo(fifo.path, 0o600) == 0)
        defer { try? FileManager.default.removeItem(at: fifo) }
        #expect(BoundedDirectoryLister.list(
            at: fifo.path,
            maximumEntries: 4,
            expectedOwnerUID: uid
        ) == nil)

        let applications = root.appendingPathComponent("Applications")
        try FileManager.default.createDirectory(
            at: applications,
            withIntermediateDirectories: false
        )
        for index in 0..<8 {
            try FileManager.default.createDirectory(
                at: applications.appendingPathComponent("Fixture-\(index).app"),
                withIntermediateDirectories: false
            )
        }
        let applicationSnapshot = try #require(TCCMonitor.boundedApplicationEntries(
            at: applications.path,
            maximumEntries: 3,
            expectedDirectoryOwnerUID: uid
        ))
        #expect(applicationSnapshot.entries.count <= 3)
        #expect(applicationSnapshot.wasTruncated)
    }

    @Test("mapped root sensors enumerate every supplied home")
    func sensorMappings() {
        let alice = RealUserHome(path: "/Users/alice", userID: 501, userName: "alice")
        let bob = RealUserHome(path: "/Users/bob", userID: 502, userName: "bob")
        let homes = [alice, bob]

        #expect(EDRMonitor.plistDirectories(homes: homes) == [
            "/Library/LaunchDaemons", "/Library/LaunchAgents",
            "/Users/alice/Library/LaunchAgents", "/Users/bob/Library/LaunchAgents",
        ])
        #expect(CrashReportMiner.defaultReportDirectories(homes: homes).contains(
            "/Users/bob/Library/Logs/DiagnosticReports/"
        ))
        #expect(VulnerabilityScanner.applicationDirectories(homes: homes) == [
            "/Applications", "/Users/alice/Applications", "/Users/bob/Applications",
        ])
        #expect(PersistenceGuard.userProtectedPaths(homes: homes) == [
            "/Users/alice/Library/LaunchAgents", "/Users/bob/Library/LaunchAgents",
        ])
        #expect(QuarantineEnricher.databasePath(for: bob)
            == "/Users/bob/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2")
    }

    @Test("browser manifests are bounded/no-follow and identities include user browser profile version")
    func browserManifestBoundaryAndIdentity() throws {
        guard geteuid() != 0 else { return }
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let home = RealUserHome(
            path: root.path,
            userID: UInt32(geteuid()),
            userName: "fixture"
        )
        let chrome = root.appendingPathComponent(
            "Library/Application Support/Google/Chrome"
        )

        func manifest(profile: String, ext: String, version: String, data: Data) throws -> URL {
            let directory = chrome
                .appendingPathComponent(profile)
                .appendingPathComponent("Extensions")
                .appendingPathComponent(ext)
                .appendingPathComponent(version)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            let path = directory.appendingPathComponent("manifest.json")
            try data.write(to: path)
            return path
        }

        let good = try JSONSerialization.data(withJSONObject: [
            "name": "Fixture", "version": "1.2.3",
            "permissions": ["cookies"],
        ])
        _ = try manifest(profile: "Default", ext: "same-id", version: "1.2.3", data: good)
        _ = try manifest(profile: "Profile 1", ext: "same-id", version: "2.0.0", data: good)
        try FileManager.default.createSymbolicLink(
            at: chrome.appendingPathComponent("Profile symlink"),
            withDestinationURL: chrome.appendingPathComponent("Default")
        )

        let oversized = Data(repeating: 0x41, count: BrowserExtensionMonitor.maximumManifestBytes + 1)
        _ = try manifest(profile: "Default", ext: "oversized", version: "1", data: oversized)

        let target = root.appendingPathComponent("target.json")
        try good.write(to: target)
        let linked = try manifest(profile: "Default", ext: "linked", version: "1", data: Data())
        try FileManager.default.removeItem(at: linked)
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: target)

        let inventory = BrowserExtensionMonitor.snapshotResult(
            homes: [home],
            directoryEntryBudgetPerHome: BrowserExtensionMonitor.maximumDirectoryEntriesPerHomeScan
        )
        let snapshots = inventory.extensions
        #expect(snapshots.count == 2)
        #expect(inventory.coverage.isComplete)
        #expect(!inventory.coverage.wasTruncated)
        #expect(Set(snapshots.map(\.profile)) == Set(["Default", "Profile 1"]))
        #expect(snapshots.allSatisfy {
            $0.userId == home.userID
                && $0.id.contains(":chrome:")
                && $0.id.contains(":same-id:")
        })
        #expect(Set(snapshots.map(\.id)).count == 2)
        #expect(!snapshots.contains { $0.extensionId == "oversized" || $0.extensionId == "linked" })
    }

    @Test("browser profile and version padding is bounded and fail-visible")
    func browserPaddingCoverageDiagnostics() async throws {
        #expect(BrowserExtensionMonitor.saturatedAdd(UInt64.max - 1, 2) == UInt64.max)
        #expect(BrowserExtensionMonitor.saturatedIncrement(UInt64.max) == UInt64.max)
        guard geteuid() != 0 else { return }
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let home = RealUserHome(
            path: root.path,
            userID: UInt32(geteuid()),
            userName: "fixture"
        )
        let chrome = root.appendingPathComponent(
            "Library/Application Support/Google/Chrome"
        )

        // Profile-level padding: the first directory alone consumes the global
        // per-home test budget. The partial rows may be empty, but coverage may
        // never claim complete.
        for index in 0..<12 {
            try FileManager.default.createDirectory(
                at: chrome.appendingPathComponent("Padded Profile \(index)"),
                withIntermediateDirectories: true
            )
        }
        let profilePadded = BrowserExtensionMonitor.snapshotResult(
            homes: [home],
            directoryEntryBudgetPerHome: 8
        )
        #expect(profilePadded.coverage.wasTruncated)
        #expect(!profilePadded.coverage.isComplete)
        #expect(profilePadded.coverage.truncatedHomeCount == 1)
        #expect(profilePadded.coverage.truncatedDirectoryCount == 1)
        #expect(profilePadded.coverage.inspectedDirectoryEntries == 8)

        // Replace the profile fanout with one profile and pad its version level.
        try FileManager.default.removeItem(at: chrome)
        let versions = chrome
            .appendingPathComponent("Default")
            .appendingPathComponent("Extensions")
            .appendingPathComponent("padded-extension")
        for index in 0..<12 {
            try FileManager.default.createDirectory(
                at: versions.appendingPathComponent("\(index).0.0"),
                withIntermediateDirectories: true
            )
        }
        let versionPadded = BrowserExtensionMonitor.snapshotResult(
            homes: [home],
            directoryEntryBudgetPerHome: 6
        )
        #expect(versionPadded.coverage.wasTruncated)
        #expect(versionPadded.coverage.truncatedHomeCount == 1)
        #expect(versionPadded.coverage.truncatedDirectoryCount == 1)
        #expect(versionPadded.coverage.inspectedDirectoryEntries == 6)

        let monitor = BrowserExtensionMonitor(
            pollInterval: 999,
            homesProvider: { [home] },
            directoryEntryBudgetPerHome: 6
        )
        await monitor.scanNow()
        await monitor.scanNow()
        let diagnostics = await monitor.coverageDiagnostics()
        #expect(diagnostics.scansTotal == 2)
        #expect(diagnostics.truncatedScansTotal == 2)
        #expect(diagnostics.lastScanWasTruncated)
        #expect(!diagnostics.lastScanComplete)
        #expect(diagnostics.degraded)
        #expect(diagnostics.reason == "directory_budget_exhausted")
        #expect(diagnostics.lastScanTruncatedHomeCount == 1)
        #expect(diagnostics.lastScanInspectedDirectoryEntries == 6)
        #expect(diagnostics.inspectedDirectoryEntriesTotal == 12)
    }

    @Test("browser inventory has no cheap per-level hiding ceiling")
    func browserPerLevelCapsRetired() throws {
        let repository = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let monitorSource = try String(
            contentsOf: repository.appendingPathComponent(
                "Sources/MacCrabCore/Collectors/BrowserExtensionMonitor.swift"
            ),
            encoding: .utf8
        )
        #expect(!monitorSource.contains("maximumProfiles"))
        #expect(!monitorSource.contains("maximumExtensions"))
        #expect(!monitorSource.contains("maximumVersions"))
        #expect(monitorSource.contains("maximumEntries: budget.remainingEntries"))

        guard geteuid() != 0 else { return }
        let root = try temporaryDirectory()
        defer { try? FileManager.default.removeItem(at: root) }
        let home = RealUserHome(
            path: root.path,
            userID: UInt32(geteuid()),
            userName: "fixture"
        )
        let chrome = root.appendingPathComponent(
            "Library/Application Support/Google/Chrome"
        )

        // 300 profiles exceeds the retired 256 cap but remains far below the
        // one global budget. A target at that level must still be discovered.
        for index in 0..<299 {
            try FileManager.default.createDirectory(
                at: chrome.appendingPathComponent("Padding \(index)"),
                withIntermediateDirectories: true
            )
        }
        let versions = chrome
            .appendingPathComponent("Target Profile")
            .appendingPathComponent("Extensions")
            .appendingPathComponent("target-extension")
        // 80 versions exceeds the retired 64 cap. Only the lexically-last
        // candidate carries a manifest, proving the whole bounded level is used.
        for index in 0..<79 {
            try FileManager.default.createDirectory(
                at: versions.appendingPathComponent(String(format: "%03d.0.0", index)),
                withIntermediateDirectories: true
            )
        }
        let targetVersion = versions.appendingPathComponent("999.0.0")
        try FileManager.default.createDirectory(
            at: targetVersion,
            withIntermediateDirectories: true
        )
        let manifest = try JSONSerialization.data(withJSONObject: [
            "name": "Beyond retired caps",
            "version": "999.0.0",
            "permissions": ["cookies"],
        ])
        try manifest.write(to: targetVersion.appendingPathComponent("manifest.json"))

        let inventory = BrowserExtensionMonitor.snapshotResult(
            homes: [home],
            directoryEntryBudgetPerHome: 1_000
        )
        #expect(inventory.coverage.isComplete)
        #expect(inventory.extensions.contains {
            $0.profile == "Target Profile"
                && $0.extensionId == "target-extension"
                && $0.version == "999.0.0"
        })
    }
}

@Suite("Retired AI containment is truthful and mutation-free")
struct AIContainmentRetirementTests {
    @Test("enable/disable never changes credential mode and never reports enforcement")
    func noCredentialMutation() async throws {
        let file = FileManager.default.temporaryDirectory
            .appendingPathComponent("maccrab-containment-credential-\(UUID().uuidString)")
        try Data("secret".utf8).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        #expect(chmod(file.path, 0o640) == 0)
        let before = (try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions]
            as? NSNumber)?.uint16Value

        let containment = AIContainment()
        await containment.enable()
        await containment.disable()

        let after = (try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions]
            as? NSNumber)?.uint16Value
        let stats = await containment.stats()
        #expect(before == after)
        #expect(stats.enabled == false)
        #expect(stats.protectedCount == 0)
        #expect(await containment.wouldBlock(filePath: file.path, aiToolName: "fixture") == false)
        #expect(AIContainment.enforcementAvailable == false)
    }

    @Test("retired module is absent from advertised D3FEND mappings")
    func noD3FENDClaim() {
        #expect(!D3FENDMapping.all.map(\.id).contains("D3-EAL"))
        #expect(D3FENDMapping.forTactic("attack.execution").isEmpty)
        #expect(D3FENDMapping.forTactic("ai_safety").isEmpty)
    }

    @Test("root-reachable user sensors cannot regress to process-home APIs")
    func rootHomeCallsiteDrift() throws {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let relativePaths = [
            "Sources/MacCrabCore/AIGuard/AIToolRegistry.swift",
            "Sources/MacCrabCore/Collectors/BrowserExtensionMonitor.swift",
            "Sources/MacCrabCore/Collectors/EDRMonitor.swift",
            "Sources/MacCrabCore/Collectors/SystemPolicyMonitor.swift",
            "Sources/MacCrabCore/Detection/CrashReportMiner.swift",
            "Sources/MacCrabCore/Detection/NoiseFilter.swift",
            "Sources/MacCrabCore/Detection/SecurityScorer.swift",
            "Sources/MacCrabCore/Detection/VulnerabilityScanner.swift",
            "Sources/MacCrabCore/Enrichment/DeliveryProvenanceWeld.swift",
            "Sources/MacCrabCore/Enrichment/NotarizationChecker.swift",
            "Sources/MacCrabCore/Enrichment/QuarantineEnricher.swift",
            "Sources/MacCrabCore/Enrichment/YARAEnricher.swift",
            "Sources/MacCrabCore/Prevention/AIContainment.swift",
            "Sources/MacCrabCore/Prevention/PersistenceGuard.swift",
        ]
        for relative in relativePaths {
            let source = try String(
                contentsOf: repo.appendingPathComponent(relative),
                encoding: .utf8
            )
            #expect(!source.contains("NSHomeDirectory()"), "\(relative) regressed to process home")
            #expect(!source.contains(".userDomainMask"), "\(relative) regressed to user domain")
        }

        let setup = try String(
            contentsOf: repo.appendingPathComponent("Sources/MacCrabAgentKit/DaemonSetup.swift"),
            encoding: .utf8
        )
        let banner = try String(
            contentsOf: repo.appendingPathComponent("Sources/MacCrabAgentKit/StartupBanner.swift"),
            encoding: .utf8
        )
        let fsEvents = try String(
            contentsOf: repo.appendingPathComponent(
                "Sources/MacCrabCore/Collectors/FSEventsCollector.swift"
            ),
            encoding: .utf8
        )
        #expect(setup.contains("ResponseEngine(supportDirectory: supportDir)"))
        #expect(setup.contains("persistPath: supportDir + \"/baseline.json\""))
        #expect(setup.contains(
            "AINetworkSandbox(customConfigPath: supportDir + \"/ai_network_allowlist.json\")"
        ))
        #expect(setup.contains(
            "ProcessTreeAnalyzer(modelPath: supportDir + \"/process_tree_model.json\")"
        ))
        #expect(setup.contains("if !isRoot {\n            await fsEventsCollector.start()"))
        #expect(fsEvents.contains("Intended as a fallback when Endpoint Security is not available (non-root)."))
        #expect(!setup.contains("await aiContainment.enable()"))
        #expect(!setup.contains("persistence guard, AI containment"))
        #expect(!banner.contains("- AI containment,"))
        #expect(banner.contains("detection/attribution only"))
        #expect(setup.components(separatedBy: "reapOrphanUserDomainDBs(").count == 2,
                "retired orphan reaper must have a declaration but no startup call")
        #expect(setup.contains(
            "Automatic orphan user-domain DB mutation is retired; no files changed"
        ))
        let reaperStart = try #require(setup.range(
            of: "func reapOrphanUserDomainDBs(logger: os.Logger)"
        ))
        let reaperEnd = try #require(setup.range(
            of: "\nfunc isOverlayDirSecure(",
            range: reaperStart.upperBound..<setup.endIndex
        ))
        let retiredReaper = setup[reaperStart.lowerBound..<reaperEnd.lowerBound]
        #expect(!retiredReaper.contains("FileManager"))
        #expect(!retiredReaper.contains("Darwin."))
    }

    @Test("no source performs a raw local-home enumeration")
    func rawUsersWalkCensus() throws {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        let sourceRoots = [
            repo.appendingPathComponent("Sources/MacCrabCore"),
            repo.appendingPathComponent("Sources/MacCrabAgentKit"),
        ]
        for root in sourceRoots {
            guard let enumerator = FileManager.default.enumerator(
                at: root,
                includingPropertiesForKeys: nil
            ) else {
                Issue.record("could not enumerate \(root.path)")
                continue
            }
            for case let file as URL in enumerator where file.pathExtension == "swift" {
                let source = try String(contentsOf: file, encoding: .utf8)
                let compact = String(source.filter { !$0.isWhitespace })
                let rawPathWalk = compact.contains(
                    "contentsOfDirectory(atPath:\"/Users\")"
                ) || compact.contains(
                    "contentsOfDirectory(at:URL(fileURLWithPath:\"/Users\")"
                )
                let relative = file.path.replacingOccurrences(
                    of: repo.path + "/",
                    with: ""
                )
                #expect(!rawPathWalk,
                        "\(relative) bypasses the bounded real-user-home contract")
            }
        }
    }

    @Test("root user-directory readers stay on the bounded no-follow boundary")
    func userDirectoryEnumerationCensus() throws {
        let repo = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
        // Remaining Foundation enumerations in these files are intentionally
        // limited to fixed system-owned directories. Exact counts make a new
        // path-based reader fail review instead of silently joining the list.
        let expectedFoundationCounts: [String: Int] = [
            "Sources/MacCrabCore/Collectors/BrowserExtensionMonitor.swift": 0,
            "Sources/MacCrabCore/Collectors/EDRMonitor.swift": 1,
            "Sources/MacCrabCore/Collectors/SystemPolicyMonitor.swift": 4,
            "Sources/MacCrabCore/Collectors/TCCMonitor.swift": 1,
            "Sources/MacCrabCore/Detection/CrashReportMiner.swift": 0,
            "Sources/MacCrabCore/Detection/VulnerabilityScanner.swift": 0,
            "Sources/MacCrabCore/Detection/SecurityScorer.swift": 1,
            "Sources/MacCrabCore/Enrichment/DeliveryProvenanceWeld.swift": 0,
        ]
        for (relative, expectedCount) in expectedFoundationCounts {
            let source = try String(
                contentsOf: repo.appendingPathComponent(relative),
                encoding: .utf8
            )
            let count = source.components(separatedBy: "contentsOfDirectory(").count - 1
            #expect(count == expectedCount,
                    "\(relative) changed direct directory-enumeration inventory")
            #expect(source.contains("BoundedDirectoryLister."),
                    "\(relative) lost its bounded user-directory boundary")
        }
    }

    @Test("root-mode YARA defaults include real users and never var-root")
    func yaraRootDefaults() {
        let alice = RealUserHome(path: "/Users/alice", userID: 501, userName: "alice")
        let bob = RealUserHome(path: "/Users/bob", userID: 502, userName: "bob")
        let paths = YARAEnricher.defaultScanPaths(
            effectiveUID: 0,
            homes: [alice, bob]
        )
        #expect(paths.contains("/Users/alice/Downloads/"))
        #expect(paths.contains("/Users/bob/Desktop/"))
        #expect(paths.contains("/Users/alice/Library/LaunchAgents/"))
        #expect(!paths.contains { $0.hasPrefix("/var/root/") })
    }
}
