// LLMConfigMigrationSweepTests.swift
// Drift guard for the centralized, no-secret llm_config.json boundary.
import Testing
import Foundation

@Suite("llm_config.json readers share one no-secret boundary")
struct LLMConfigMigrationSweepTests {

    private var repositoryRoot: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // MacCrabCoreTests
            .deletingLastPathComponent()   // Tests
            .deletingLastPathComponent()   // repo root
    }

    @Test("every shipped reader and merger calls loadAndScrub")
    func allReadersUseBoundary() throws {
        let expectedReaders: [(path: String, interaction: String)] = [
            ("Sources/MacCrabAgentKit/DaemonSetup.swift", ".disallowed"),
            ("Sources/MacCrabAgentKit/DaemonTimers.swift", ".disallowed"),
            // AppState is deliberately not a config-file reader: applied LLM
            // state comes only from a newer root-engine heartbeat. SettingsView
            // owns the interactive user-config migration boundary.
            ("Sources/MacCrabApp/Views/SettingsView.swift", ".allowed"),
            ("Sources/maccrabctl/Helpers.swift", ".allowed"),
            ("Sources/maccrab-mcp/main.swift", ".disallowed"),
        ]
        var offenders: [String] = []
        for reader in expectedReaders {
            let source = try String(
                contentsOf: repositoryRoot.appendingPathComponent(reader.path),
                encoding: .utf8
            )
            if !source.contains("LLMConfigFile.loadAndScrub") {
                offenders.append("\(reader.path) (missing boundary)")
            }
            if !source.contains("legacySecretMigration:") ||
                !source.contains("interaction: \(reader.interaction)") {
                offenders.append("\(reader.path) (missing \(reader.interaction) migration)")
            }
        }
        #expect(
            offenders.isEmpty,
            "llm_config reader(s) bypass the scrub boundary: \(offenders.joined(separator: ", "))"
        )
    }

    @Test("legacy JSON key literals exist only in the central denylist")
    func noManualSecretReadersOrWriters() throws {
        let sources = repositoryRoot.appendingPathComponent("Sources")
        let allowed = sources.appendingPathComponent("MacCrabCore/LLM/LLMConfigPersistence.swift").path
        let enumerator = FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil)
        var offenders: [String] = []
        while let url = enumerator?.nextObject() as? URL {
            guard url.pathExtension == "swift", url.path != allowed else { continue }
            let source = try String(contentsOf: url, encoding: .utf8)
            if source.contains("_api_key") {
                offenders.append("\(url.path): *_api_key")
            }
        }
        #expect(
            offenders.isEmpty,
            "manual plaintext LLM secret JSON site(s) found:\n\(offenders.joined(separator: "\n"))"
        )
    }

    @Test("runtime readers load Keychain secrets and never decode them from JSON")
    func runtimeSecretSourceDriftGuard() throws {
        let readers: [(path: String, interaction: String)] = [
            ("Sources/MacCrabAgentKit/DaemonSetup.swift", ".disallowed"),
            ("Sources/maccrabctl/Helpers.swift", ".allowed"),
            ("Sources/maccrab-mcp/main.swift", ".disallowed"),
        ]
        var offenders: [String] = []
        for reader in readers {
            let source = try String(
                contentsOf: repositoryRoot.appendingPathComponent(reader.path),
                encoding: .utf8
            )
            if !source.contains("LLMSecretLoader.applyKeychainSecrets") ||
                !source.contains("interaction: \(reader.interaction)") {
                offenders.append(reader.path)
            }
            if !source.contains("LLMSecretLoader.applyEnvironmentOverrides") {
                offenders.append("\(reader.path) (missing env override)")
            }
        }
        #expect(
            offenders.isEmpty,
            "runtime LLM secret source drift:\n\(offenders.joined(separator: "\n"))"
        )
    }

    @Test("unprivileged CLI and MCP share user-first config resolution")
    func runtimeConfigResolverParityGuard() throws {
        for relativePath in [
            "Sources/maccrabctl/Helpers.swift",
            "Sources/maccrab-mcp/main.swift",
        ] {
            let source = try String(
                contentsOf: repositoryRoot.appendingPathComponent(relativePath),
                encoding: .utf8
            )
            #expect(source.contains("LLMConfigFile.runtimeConfigReadPaths("))
            #expect(source.contains("environment[\"MACCRAB_DATA_DIR\"]"))
            #expect(source.contains("userSupportDir"))
        }
    }

    @Test("Settings writes through the defensive non-secret writer")
    func settingsWriterGuard() throws {
        let path = repositoryRoot.appendingPathComponent("Sources/MacCrabApp/Views/SettingsView.swift")
        let source = try String(contentsOf: path, encoding: .utf8)
        #expect(source.contains("LLMConfigFile.writeNonSecretJSON("))
        #expect(source.contains("legacySecretMigration: .sharedKeychain("))
        #expect(source.contains("interaction: .allowed"))
        #expect(source.contains("guard saveAPIKeyToKeychain() else { return }"))
        #expect(source.contains("let readBack = try secrets.get(key)"))
        #expect(source.contains("readBack == candidate"))
        #expect(source.contains("llmCredentialStatusIsError = true"))
        #expect(!source.contains("try? secrets.set"))
    }

    @Test("root inbox writes through the defensive non-secret writer")
    func rootWriterGuard() throws {
        let path = repositoryRoot.appendingPathComponent("Sources/MacCrabAgentKit/DaemonTimers.swift")
        let source = try String(contentsOf: path, encoding: .utf8)
        #expect(source.contains("LLMConfigFile.writeNonSecretJSON("))
        #expect(source.contains("legacySecretMigration: .sharedKeychain(interaction: .disallowed)"))
    }

    @Test("central boundary resists carrier swaps and publishes atomically")
    func centralFilesystemHardeningGuard() throws {
        let path = repositoryRoot.appendingPathComponent(
            "Sources/MacCrabCore/LLM/LLMConfigPersistence.swift"
        )
        let source = try String(contentsOf: path, encoding: .utf8)
        #expect(source.contains("O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW"))
        #expect(source.contains("metadata.st_nlink == 1"))
        #expect(source.contains("current.st_nlink == 1"))
        #expect(source.contains("Darwin.renameat("))
        #expect(source.contains("Darwin.fsync(directoryFD)"))
        #expect(!source.contains("Darwin.ftruncate"))
    }

    @Test("legacy credential removal is gated on exact secure-store read-back")
    func migrationOrderingGuard() throws {
        let path = repositoryRoot.appendingPathComponent(
            "Sources/MacCrabCore/LLM/LLMConfigPersistence.swift"
        )
        let source = try String(contentsOf: path, encoding: .utf8)
        #expect(source.contains("try migration.save(key, expected)"))
        #expect(source.contains("guard try migration.readBack(key) == expected"))
        guard let migration = source.range(of: "try migrateLegacySecrets(in: object"),
              let publication = source.range(of: "try secureWrite(") else {
            Issue.record("migration or secure publication boundary is missing")
            return
        }
        #expect(migration.lowerBound < publication.lowerBound)
    }

    @Test("non-interactive Keychain API forbids authentication UI")
    func nonInteractiveKeychainGuard() throws {
        let path = repositoryRoot.appendingPathComponent("Sources/MacCrabCore/Storage/SecretsStore.swift")
        let source = try String(contentsOf: path, encoding: .utf8)
        let marker = "public func getNonInteractive"
        guard let start = source.range(of: marker)?.lowerBound else {
            Issue.record("SecretsStore.getNonInteractive is missing")
            return
        }
        let tail = String(source[start...].prefix(800))
        #expect(tail.contains("interactionNotAllowed = true"))
        #expect(tail.contains("kSecUseAuthenticationContext"))
        #expect(tail.contains("migrateLegacy: false"))
        #expect(source.contains("public func setNonInteractive"))
        let persistence = try String(
            contentsOf: repositoryRoot.appendingPathComponent(
                "Sources/MacCrabCore/LLM/LLMConfigPersistence.swift"
            ),
            encoding: .utf8
        )
        #expect(persistence.contains("try store.setNonInteractive(key, value: value)"))
    }

    @Test("shipped bare CLI and MCP tools stay entitlement-free and runtime-probed")
    func toolSigningGuard() throws {
        // Bare executables do not inherit MacCrab.app's provisioning profile.
        // A restricted entitlement therefore makes taskgated/AMFI kill them
        // before main even though codesign verification and notarization pass.
        let obsoleteEntitlements = repositoryRoot
            .appendingPathComponent("Xcode/Resources/MacCrabTools.entitlements")
        #expect(
            !FileManager.default.fileExists(atPath: obsoleteEntitlements.path),
            "bare tools must not regain a provisioning-profile-bound entitlement input"
        )

        let buildScript = try String(
            contentsOf: repositoryRoot.appendingPathComponent("scripts/build-release.sh"),
            encoding: .utf8
        )
        #expect(!buildScript.contains("MacCrabTools.entitlements"))
        #expect(!buildScript.contains("TOOLS_ENT="))

        guard let guardStart = buildScript.range(of: "# BEGIN BARE_TOOL_RELEASE_GUARDS"),
              let guardEnd = buildScript.range(of: "# END BARE_TOOL_RELEASE_GUARDS") else {
            Issue.record("central bare-tool release guard block is missing")
            return
        }
        let releaseGuards = String(buildScript[guardStart.lowerBound..<guardEnd.upperBound])
        guard let verifierStart = releaseGuards.range(
            of: "verify_bare_tool_signature_contract()"
        ) else {
            Issue.record("central bare-tool signature verifier is missing")
            return
        }
        let signer = String(releaseGuards[..<verifierStart.lowerBound])
        #expect(signer.contains("--identifier \"com.maccrab.$name\""))
        #expect(signer.contains("--options runtime"))
        #expect(!signer.contains("--entitlements"))
        #expect(releaseGuards.contains("for arch in $archs"))
        #expect(releaseGuards.contains("'\\[Key\\]|<key>'"))
        #expect(releaseGuards.contains("verify_bare_tool_runtime()"))

        let signingCalls = buildScript.components(
            separatedBy: "sign_bare_tool \"$binary\" \"$DEVELOPER_ID\""
        ).count - 1
        #expect(signingCalls == 2, "loose and in-app copies must share exactly one signing path each")
        #expect(buildScript.contains("verify_bare_tool_runtime \"$APP\" \"post-sign\""))
        #expect(buildScript.contains(
            "verify_bare_tool_runtime \"$DMG_MNT/MacCrab.app\" \"mounted-DMG\""
        ))
    }

    @Test("MCP version probe exits before server startup side effects")
    func mcpVersionProbeIsEarly() throws {
        let source = try String(
            contentsOf: repositoryRoot.appendingPathComponent("Sources/maccrab-mcp/main.swift"),
            encoding: .utf8
        )
        guard let version = source.range(
            of: "if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == \"--version\""
        ),
        let buffering = source.range(of: "setbuf(stdout, nil)"),
        let logger = source.range(of: "private let logger = Logger"),
        let parentLog = source.range(of: "logInvokingParentProcess()", options: .backwards) else {
            Issue.record("MCP version/startup markers are missing")
            return
        }
        #expect(source.contains("print(\"maccrab-mcp \\(MacCrabVersion.current)\")"))
        #expect(version.lowerBound < buffering.lowerBound)
        #expect(version.lowerBound < logger.lowerBound)
        #expect(version.lowerBound < parentLog.lowerBound)
    }
}
