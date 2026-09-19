import Foundation
import Testing

@Suite("Root subprocess surface inventory")
struct RootSubprocessSurfaceTests {
    private static let repoRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()

    private func source(_ relative: String) throws -> String {
        try String(
            contentsOf: Self.repoRoot.appendingPathComponent(relative),
            encoding: .utf8
        )
    }

    private func processCount(in text: String) -> Int {
        // Count constructors, not identifiers whose names merely end in
        // `Process` (for example evictLRUProcess() and
        // logInvokingParentProcess()). Accept qualified and whitespace-varied
        // Foundation construction sites so the inverse census cannot be
        // bypassed by spelling drift.
        let regex = try! NSRegularExpression(
            pattern: #"(?<![A-Za-z0-9_])(?:Foundation\.)?Process\s*\(\s*\)"#
        )
        return regex.numberOfMatches(
            in: text,
            range: NSRange(text.startIndex..., in: text)
        )
    }

    @Test("every Foundation Process construction has an explicit ownership classification")
    func completeProcessCensus() throws {
        // Exact counts make additions and removals deliberate. MacCrabCore has
        // only the one shared bounded runner, three reviewed long-lived stream
        // collectors, and two dashboard/manual-response calls that are not
        // wired into the automated root response path. The remaining targets
        // are GUI/CLI/MCP/forensics processes and execute unprivileged.
        let allowed: [String: Int] = [
            // Unprivileged threat-intel refresh helper, Agent Traces dev
            // signal, and manual flush fallback. Rule reload now queues only
            // to the selected engine, removing AppState's fourth constructor
            // and V2DaemonControl's separate broad pkill fallback entirely.
            "Sources/MacCrabApp/AppState.swift": 3,
            "Sources/MacCrabApp/UserRuleInstaller.swift": 1,
            "Sources/MacCrabApp/V2/Data/V2LiveDataProvider.swift": 1,
            "Sources/MacCrabApp/V2/Forensics/RaveInstallConsentSheet.swift": 1,
            "Sources/MacCrabApp/V2/Workspaces/V2DetectionWorkspace.swift": 1,
            "Sources/MacCrabApp/V2/Workspaces/V2InvestigationWorkspace.swift": 1,
            "Sources/MacCrabApp/V2/Workspaces/V2RaveCatalogBrowserView.swift": 1,
            "Sources/MacCrabCore/Collectors/EsloggerCollector.swift": 1,
            "Sources/MacCrabCore/Collectors/KdebugCollector.swift": 1,
            "Sources/MacCrabCore/Collectors/UnifiedLogCollector.swift": 1,
            "Sources/MacCrabCore/Prevention/ManualResponse.swift": 2,
            "Sources/MacCrabCore/Utilities/PrivilegedExecutablePolicy.swift": 1,
            "Sources/MacCrabForensics/MCFP/MCFPStatic.swift": 1,
            "Sources/MacCrabForensics/MCFPResearch/ImposterHarness.swift": 1,
            "Sources/MacCrabForensics/Plugins/Collectors/FSEvents/FSEventsRecordParser.swift": 1,
            "Sources/MacCrabForensics/Plugins/Collectors/FileAnalyzers/ArchiveWalkerPlugin.swift": 1,
            "Sources/MacCrabForensics/Plugins/Collectors/FileAnalyzers/DMGPKGAnalyzerPlugin.swift": 1,
            "Sources/MacCrabForensics/Plugins/Collectors/FileAnalyzers/OfficeDocumentPlugin.swift": 1,
            "Sources/MacCrabForensics/Plugins/Collectors/MachOAnalyzer/MachOAnalyzerPlugin.swift": 2,
            "Sources/maccrab-mcp/AgentControl.swift": 1,
            "Sources/maccrab-mcp/main.swift": 1,
            "Sources/maccrabctl/MacCrabCtl.swift": 1,
            "Sources/maccrabctl/StatusCommand.swift": 1,
        ]

        let sourcesRoot = Self.repoRoot.appendingPathComponent("Sources")
        let enumerator = try #require(FileManager.default.enumerator(
            at: sourcesRoot,
            includingPropertiesForKeys: nil
        ))
        var observed: [String: Int] = [:]
        for case let file as URL in enumerator where file.pathExtension == "swift" {
            let text = try String(contentsOf: file, encoding: .utf8)
            let count = processCount(in: text)
            guard count > 0 else { continue }
            let relative = String(file.path.dropFirst(sourcesRoot.path.count + 1))
            observed["Sources/" + relative] = count
        }
        #expect(observed == allowed,
                "new subprocess sites require a root/unprivileged/lifecycle review and allowlist update")

        // Trace archive creation/extraction was deliberately migrated off a
        // raw Process to immutable snapshot helpers backed by the shared
        // bounded runner. Keep that removal classified, not merely absent from
        // the count above.
        let traceCommands = try source("Sources/maccrabctl/TraceCommands.swift")
        #expect(processCount(in: traceCommands) == 0)
        #expect(traceCommands.contains("SafeTraceArchivePackager.package("))
        #expect(traceCommands.contains("SafeTraceBundleResolver.resolve("))
    }

    @Test("all short root-reachable commands use the bounded shared runner")
    func rootShortCommandParity() throws {
        let migrated = [
            "Sources/MacCrabCore/Integrations/SecurityToolIntegrations.swift",
            "Sources/MacCrabCore/Fleet/FleetClient.swift",
            "Sources/MacCrabCore/Detection/SecurityScorer.swift",
            "Sources/MacCrabCore/Detection/SelfDefense.swift",
            "Sources/MacCrabCore/Detection/ResponseAction.swift",
            "Sources/MacCrabCore/Detection/ESClientMonitor.swift",
            "Sources/MacCrabCore/Collectors/SystemPolicyMonitor.swift",
            "Sources/MacCrabCore/Detection/PowerAnomalyDetector.swift",
            "Sources/MacCrabCore/Collectors/SDRDeviceMonitor.swift",
            "Sources/MacCrabCore/Collectors/BTMSnapshotMonitor.swift",
            "Sources/MacCrabCore/Prevention/NetworkBlocker.swift",
            "Sources/MacCrabCore/Prevention/SafeBlockableIP.swift",
            "Sources/MacCrabCore/Output/SFTPOutput.swift",
            "Sources/MacCrabCore/Enrichment/NotarizationChecker.swift",
            "Sources/MacCrabCore/Collectors/EsloggerCollector.swift",
            "Sources/MacCrabCore/Prevention/TCCRevocation.swift",
            "Sources/MacCrabCore/Prevention/PanicButton.swift",
            "Sources/MacCrabCore/Prevention/TravelMode.swift",
            "Sources/MacCrabCore/Enrichment/PackageScanner.swift",
            "Sources/maccrabd/main.swift",
            "Sources/maccrabctl/RepairCommand.swift",
        ]
        for path in migrated {
            let text = try source(path)
            #expect(text.contains("BoundedPrivilegedProcessRunner.run("),
                    "\(path) lost the common deadline/output/environment boundary")
            if !path.hasSuffix("EsloggerCollector.swift") {
                #expect(!text.contains("waitUntilExit()"), "legacy wait returned in \(path)")
            }
            #expect(!text.contains("readDataToEndOfFile()"),
                    "unbounded pipe read returned in \(path)")
        }
        #expect(processCount(in: try source("Sources/maccrabd/main.swift")) == 0)
        #expect(processCount(in: try source("Sources/maccrabctl/RepairCommand.swift")) == 0,
                "repair diagnostics must retain the shared bounded runner")
    }

    @Test("long-lived and unprivileged exceptions stay narrow and explicit")
    func intentionalExceptions() throws {
        let longLived = [
            "Sources/MacCrabCore/Collectors/KdebugCollector.swift": "/usr/bin/fs_usage",
            "Sources/MacCrabCore/Collectors/EsloggerCollector.swift": "/usr/bin/eslogger",
            "Sources/MacCrabCore/Collectors/UnifiedLogCollector.swift": "/usr/bin/log",
        ]
        for (path, executable) in longLived {
            let text = try source(path)
            #expect(processCount(in: text) == 1)
            #expect(text.contains(executable))
            #expect(text.contains("private var process: Process?")
                    || text.contains("private let process: Process"),
                    "stream collector must retain its child lifecycle")
        }
        let manual = try source("Sources/MacCrabCore/Prevention/ManualResponse.swift")
        #expect(processCount(in: manual) == 2,
                "manual dashboard response is the only unprivileged MacCrabCore exception")
    }

    @Test("root raw-spawn exceptions remain exact and lifecycle-specific")
    func rawSpawnExceptions() throws {
        let coreRoot = Self.repoRoot.appendingPathComponent("Sources/MacCrabCore")
        let coreEnumerator = try #require(FileManager.default.enumerator(
            at: coreRoot,
            includingPropertiesForKeys: nil
        ))
        for case let file as URL in coreEnumerator where file.pathExtension == "swift" {
            let text = try String(contentsOf: file, encoding: .utf8)
            #expect(!text.contains("posix_spawn(&"),
                    "MacCrabCore root code added a raw spawn outside the bounded runner")
            #expect(!text.contains("popen("),
                    "MacCrabCore root code added a shell subprocess outside the bounded runner")
        }

        let timers = try source("Sources/MacCrabAgentKit/DaemonTimers.swift")
        #expect(timers.components(separatedBy: "posix_spawn(&pid").count - 1 == 1)
        #expect(timers.contains("CoverageCanary.intermediaryBinaryPath"))
        #expect(timers.contains("CoverageCanary.spawnBinaryPath"))
        #expect(timers.contains("let envp: [UnsafeMutablePointer<CChar>?] = [nil]"),
                "the reviewed one-shot canary must retain its exact binaries and empty environment")

        let legacy = try source("Sources/maccrabd/main.swift")
        #expect(legacy.components(separatedBy: "posix_spawn(&pid").count - 1 == 1,
                "the legacy background self-spawn is the only long-lived raw exception")
        #expect(legacy.contains("// Re-spawn ourselves without --background flag"))
    }

    @Test("PF command files are private and blueutil never PATH-resolves as root")
    func predictableCommandInputRetired() throws {
        let panic = try source("Sources/MacCrabCore/Prevention/PanicButton.swift")
        let travel = try source("Sources/MacCrabCore/Prevention/TravelMode.swift")
        for text in [panic, travel] {
            #expect(text.contains("PrivatePrivilegedCommandFile.create("))
            #expect(text.contains("hasStableIdentity()"))
        }
        #expect(!panic.contains("/tmp/maccrab_emergency.conf"))
        #expect(!travel.contains("/tmp/maccrab_travel.conf"))
        #expect(panic.contains("MACCRAB_BLUEUTIL_PATH"))
        #expect(panic.contains("validatedExecutable(configured)"))
        #expect(!panic.contains("executable: \"/usr/bin/env\""))
        #expect(!panic.contains("arguments: [\"blueutil\""))
    }

    @Test("custom runner environments are constructed allowlists")
    func customEnvironmentAllowlist() throws {
        let sites: [(String, String, String)] = [
            (
                "Sources/MacCrabCore/Detection/PackageFreshnessChecker.swift",
                "let environment: [String: String] = [",
                "environment: environment,"
            ),
            (
                "Sources/MacCrabCore/Detection/ResponseAction.swift",
                "var environment = BoundedPrivilegedProcessRunner.minimalEnvironment",
                "environment: environment,"
            ),
            (
                "Sources/MacCrabCore/Output/SFTPOutput.swift",
                "let sftpEnvironment = [",
                "environment: sftpEnvironment,"
            ),
            (
                "Sources/MacCrabCore/TraceBundle/SafeTraceArchiveExtractor.swift",
                "static let tarEnvironment: [String: String] = [",
                "environment: tarEnvironment,"
            ),
            (
                "Sources/maccrabctl/SafePluginArchiveExtractor.swift",
                "static let archiveToolEnvironment: [String: String] = {",
                "environment: archiveToolEnvironment,"
            ),
        ]
        for (path, construction, use) in sites {
            let text = try source(path)
            #expect(text.contains(construction), "\(path) lost its explicit environment construction")
            #expect(text.contains(use), "\(path) lost its reviewed runner environment")
            #expect(!text.contains("ProcessInfo.processInfo.environment"),
                    "\(path) must not merge or inherit the caller environment")
            #expect(!text.contains("\"DYLD_"), "\(path) must not admit loader injection keys")
        }

        let packageFreshness = try source(
            "Sources/MacCrabCore/Detection/PackageFreshnessChecker.swift"
        )
        #expect(packageFreshness.contains(
            "guard Self.allowsInstalledInventoryExecution(effectiveUID: geteuid())"
        ), "PATH-resolved package tools must remain unreachable from root")
        let response = try source("Sources/MacCrabCore/Detection/ResponseAction.swift")
        #expect(response.contains("environment.merge(["),
                "response scripts may add only their fixed MACCRAB_* context keys")
    }
}
