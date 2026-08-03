// LLMConfigPersistenceTests.swift
// Pure/filesystem contract tests. They never read or write the real Keychain.

import Foundation
import Testing
@testable import MacCrabCore

@Suite("LLM config no-secret persistence")
struct LLMConfigPersistenceTests {
    private enum FakeMigrationError: Error { case unavailable }

    private final class FakeLegacySecretStore {
        var values: [SecretKey: String] = [:]
        var saveFailures: Set<SecretKey> = []
        var readFailures: Set<SecretKey> = []
        var readOverrides: [SecretKey: String] = [:]
        var postSaveReadOverrides: [SecretKey: String] = [:]
        var saveCount: [SecretKey: Int] = [:]

        var migration: LLMLegacySecretMigration {
            LLMLegacySecretMigration(
                save: { [self] key, value in
                    saveCount[key, default: 0] += 1
                    if saveFailures.contains(key) { throw FakeMigrationError.unavailable }
                    values[key] = value
                },
                readBack: { [self] key in
                    if readFailures.contains(key) { throw FakeMigrationError.unavailable }
                    if saveCount[key, default: 0] > 0,
                       let override = postSaveReadOverrides[key] {
                        return override
                    }
                    if let override = readOverrides[key] { return override }
                    return values[key]
                }
            )
        }
    }

    private static let secretFields = [
        "ollama_api_key",
        "claude_api_key",
        "openai_api_key",
        "mistral_api_key",
        "gemini_api_key",
    ]

    private func makeDirectory() throws -> URL {
        let directory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
            .appendingPathComponent("maccrab-llm-config-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        return directory
    }

    @Test("sanitizer removes all legacy key fields and preserves unknown settings")
    func sanitizerPreservesNonSecrets() {
        var input: [String: Any] = [
            "provider": "openai",
            "openai_model": "gpt-sentinel-model",
            "future_non_secret_field": ["nested": true],
        ]
        for (index, key) in Self.secretFields.enumerated() {
            input[key] = "SECRET-SENTINEL-\(index)"
        }
        input["future_provider_api_key"] = "FUTURE-SECRET-SENTINEL"
        input["future_nested_settings"] = [[
            "future_nested_api_key": "NESTED-SECRET-SENTINEL",
            "safe_label": "preserved",
        ]]

        let result = LLMConfigFile.sanitizing(input)

        #expect(result.removedKeys == Set(Self.secretFields + [
            "future_provider_api_key", "future_nested_api_key",
        ]))
        #expect(result.values["provider"] as? String == "openai")
        #expect(result.values["openai_model"] as? String == "gpt-sentinel-model")
        #expect((result.values["future_non_secret_field"] as? [String: Bool])?["nested"] == true)
        for key in Self.secretFields { #expect(result.values[key] == nil) }
        #expect(result.values["future_provider_api_key"] == nil)
        let nested = (result.values["future_nested_settings"] as? [[String: String]])?.first
        #expect(nested?["future_nested_api_key"] == nil)
        #expect(nested?["safe_label"] == "preserved")
    }

    @Test("legacy file scrub leaves no secret in replacement, temp names, or errors")
    func legacyFileScrub() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")

        var legacy: [String: Any] = [
            "enabled": true,
            "provider": "gemini",
            "gemini_model": "gemini-sentinel-model",
            "future_non_secret_field": 42,
        ]
        var sentinels: [String] = []
        for (index, key) in Self.secretFields.enumerated() {
            let sentinel = "NEVER-PERSIST-SECRET-SENTINEL-\(index)"
            legacy[key] = sentinel
            sentinels.append(sentinel)
        }
        let original = try JSONSerialization.data(withJSONObject: legacy, options: [.prettyPrinted])
        try original.write(to: file)
        // Reproduce the old default-umask exposure. The scrub must tighten it.
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        let before = try FileManager.default.attributesOfItem(atPath: file.path)

        var scrubErrors: [String] = []
        let keychain = FakeLegacySecretStore()
        let loaded = try LLMConfigFile.loadAndScrub(
            atPath: file.path,
            legacySecretMigration: keychain.migration,
            onScrubFailure: { scrubErrors.append(String(describing: $0)) }
        )

        #expect(scrubErrors.isEmpty)
        #expect(loaded?["provider"] as? String == "gemini")
        #expect(loaded?["future_non_secret_field"] as? Int == 42)
        for key in Self.secretFields { #expect(loaded?[key] == nil) }
        #expect(keychain.values.count == Self.secretFields.count)

        let replacement = try Data(contentsOf: file)
        let replacementText = String(decoding: replacement, as: UTF8.self)
        for key in Self.secretFields { #expect(!replacementText.contains(key)) }
        for sentinel in sentinels {
            #expect(!replacementText.contains(sentinel))
            #expect(!scrubErrors.joined().contains(sentinel))
        }
        let decoded = try #require(
            JSONSerialization.jsonObject(with: replacement) as? [String: Any]
        )
        #expect(decoded["gemini_model"] as? String == "gemini-sentinel-model")
        #expect(decoded["future_non_secret_field"] as? Int == 42)

        let after = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((after[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect((after[.ownerAccountID] as? NSNumber) == (before[.ownerAccountID] as? NSNumber))
        #expect((after[.groupOwnerAccountID] as? NSNumber) == (before[.groupOwnerAccountID] as? NSNumber))
        let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
        #expect(names == ["llm_config.json"])
        for sentinel in sentinels {
            #expect(!names.joined().contains(sentinel))
        }
    }

    @Test("legacy credential is saved, read-back verified, then scrubbed")
    func successfulCredentialMigration() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        let sentinel = "MIGRATE-THEN-SCRUB-SENTINEL"
        let original = try JSONSerialization.data(withJSONObject: [
            "enabled": true,
            "provider": "claude",
            "claude_api_key": sentinel,
            "claude_model": "claude-test-model",
        ], options: [.prettyPrinted, .sortedKeys])
        try original.write(to: file)
        let keychain = FakeLegacySecretStore()

        let loaded = try LLMConfigFile.loadAndScrub(
            atPath: file.path,
            legacySecretMigration: keychain.migration
        )

        #expect(loaded?["claude_api_key"] == nil)
        #expect(keychain.values[.claudeAPIKey] == sentinel)
        #expect(keychain.saveCount[.claudeAPIKey] == 1)
        let replacement = try Data(contentsOf: file)
        #expect(!String(decoding: replacement, as: UTF8.self).contains(sentinel))
    }

    @Test("Keychain save failure preserves original bytes and returns redacted memory")
    func migrationSaveFailurePreservesFile() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        let sentinel = "SAVE-FAILURE-MUST-STAY-ONLY-IN-ORIGINAL"
        let original = Data(#"{"provider":"openai","openai_api_key":"SAVE-FAILURE-MUST-STAY-ONLY-IN-ORIGINAL","openai_model":"test"}"#.utf8)
        try original.write(to: file)
        let keychain = FakeLegacySecretStore()
        keychain.saveFailures = [.openaiAPIKey]
        var errors: [String] = []

        let loaded = try LLMConfigFile.loadAndScrub(
            atPath: file.path,
            legacySecretMigration: keychain.migration,
            onScrubFailure: { errors.append(String(describing: $0)) }
        )

        #expect(loaded?["openai_api_key"] == nil)
        #expect(try Data(contentsOf: file) == original)
        #expect(errors.count == 1)
        #expect(!errors.joined().contains(sentinel))
        #expect(keychain.values[.openaiAPIKey] == nil)
    }

    @Test("unsupported legacy field leaves no attacker-controlled name or value in errors")
    func unsupportedLegacyFieldErrorIsValueFree() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        let hostileField = "ATTACKER-FIELD-SENTINEL_api_key"
        let hostileValue = "ATTACKER-VALUE-SENTINEL"
        let original = try JSONSerialization.data(withJSONObject: [
            "provider": "future-provider",
            hostileField: hostileValue,
        ], options: [.sortedKeys])
        try original.write(to: file)
        var errors: [String] = []

        let loaded = try LLMConfigFile.loadAndScrub(
            atPath: file.path,
            legacySecretMigration: FakeLegacySecretStore().migration,
            onScrubFailure: { errors.append(String(describing: $0)) }
        )

        #expect(loaded?[hostileField] == nil)
        #expect(try Data(contentsOf: file) == original)
        #expect(errors.count == 1)
        #expect(!errors.joined().contains(hostileField))
        #expect(!errors.joined().contains(hostileValue))
    }

    @Test("Keychain read-back mismatch preserves the original plaintext file")
    func migrationReadBackMismatchPreservesFile() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        let sentinel = "READBACK-MISMATCH-MUST-STAY-IN-ORIGINAL"
        let original = Data(
            #"{"provider":"mistral","mistral_api_key":"READBACK-MISMATCH-MUST-STAY-IN-ORIGINAL"}"#.utf8
        )
        try original.write(to: file)
        let keychain = FakeLegacySecretStore()
        keychain.postSaveReadOverrides[.mistralAPIKey] = "A-DIFFERENT-READBACK-VALUE"
        var errors: [String] = []

        let loaded = try LLMConfigFile.loadAndScrub(
            atPath: file.path,
            legacySecretMigration: keychain.migration,
            onScrubFailure: { errors.append(String(describing: $0)) }
        )

        #expect(loaded?["mistral_api_key"] == nil)
        #expect(try Data(contentsOf: file) == original)
        #expect(errors.count == 1)
        #expect(!errors.joined().contains(sentinel))
        #expect(keychain.saveCount[.mistralAPIKey] == 1)
        #expect(keychain.values[.mistralAPIKey] == sentinel)
    }

    @Test("one provider failure leaves the whole file intact and rerun completes")
    func partialProviderFailureAndRerun() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        let claudeSentinel = "PARTIAL-CLAUDE-SENTINEL"
        let openAISentinel = "PARTIAL-OPENAI-SENTINEL"
        let original = try JSONSerialization.data(withJSONObject: [
            "provider": "claude",
            "claude_api_key": claudeSentinel,
            "openai_api_key": openAISentinel,
            "future_non_secret": 7,
        ], options: [.prettyPrinted, .sortedKeys])
        try original.write(to: file)
        let keychain = FakeLegacySecretStore()
        keychain.saveFailures = [.openaiAPIKey]
        var firstErrors: [String] = []

        let firstView = try LLMConfigFile.loadAndScrub(
            atPath: file.path,
            legacySecretMigration: keychain.migration,
            onScrubFailure: { firstErrors.append(String(describing: $0)) }
        )
        #expect(firstView?["claude_api_key"] == nil)
        #expect(firstView?["openai_api_key"] == nil)
        #expect(keychain.values[.claudeAPIKey] == claudeSentinel)
        #expect(keychain.values[.openaiAPIKey] == nil)
        #expect(try Data(contentsOf: file) == original)
        #expect(!firstErrors.joined().contains(claudeSentinel))
        #expect(!firstErrors.joined().contains(openAISentinel))

        keychain.saveFailures = []
        var secondErrors: [String] = []
        _ = try LLMConfigFile.loadAndScrub(
            atPath: file.path,
            legacySecretMigration: keychain.migration,
            onScrubFailure: { secondErrors.append(String(describing: $0)) }
        )
        #expect(secondErrors.isEmpty)
        #expect(keychain.values[.claudeAPIKey] == claudeSentinel)
        #expect(keychain.values[.openaiAPIKey] == openAISentinel)
        let scrubbed = try Data(contentsOf: file)
        let scrubbedText = String(decoding: scrubbed, as: UTF8.self)
        #expect(!scrubbedText.contains(claudeSentinel))
        #expect(!scrubbedText.contains(openAISentinel))
        #expect((try JSONSerialization.jsonObject(with: scrubbed) as? [String: Any])?["future_non_secret"] as? Int == 7)

        // A completed rerun sees no legacy fields and performs no extra writes.
        let countsBeforeIdempotentRun = keychain.saveCount
        _ = try LLMConfigFile.loadAndScrub(
            atPath: file.path,
            legacySecretMigration: keychain.migration
        )
        #expect(keychain.saveCount == countsBeforeIdempotentRun)
    }

    @Test("writer strips a caller-supplied sentinel before bytes reach disk")
    func writerIsDefensive() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        let sentinel = "WRITER-MUST-NEVER-SERIALIZE-THIS"

        try LLMConfigFile.writeNonSecretJSON([
            "enabled": true,
            "provider": "claude",
            "claude_model": "claude-test-model",
            "claude_api_key": sentinel,
        ], toPath: file.path)

        let bytes = try Data(contentsOf: file)
        let text = String(decoding: bytes, as: UTF8.self)
        #expect(!text.contains("claude_api_key"))
        #expect(!text.contains(sentinel))
        #expect(text.contains("claude-test-model"))
        let attrs = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["llm_config.json"])
    }

    @Test("writer cannot erase the sole legacy credential when migration fails")
    func writerMigrationFailurePreservesExistingBytes() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        let sentinel = "WRITER-MIGRATION-FAILURE-SENTINEL"
        let original = Data(
            #"{"enabled":true,"gemini_api_key":"WRITER-MIGRATION-FAILURE-SENTINEL","future_non_secret":11}"#.utf8
        )
        try original.write(to: file)
        let keychain = FakeLegacySecretStore()
        keychain.saveFailures = [.geminiAPIKey]

        #expect(throws: (any Error).self) {
            try LLMConfigFile.writeNonSecretJSON(
                ["provider": "ollama", "ollama_model": "new"],
                toPath: file.path,
                legacySecretMigration: keychain.migration
            )
        }

        let after = try Data(contentsOf: file)
        #expect(after == original)
        #expect(String(decoding: after, as: UTF8.self).contains(sentinel))
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["llm_config.json"])
    }

    @Test("existing config publication is atomic and replaces the complete inode")
    func atomicExistingFilePublication() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        try Data(#"{"provider":"ollama","ollama_model":"old"}"#.utf8).write(to: file)
        let before = try FileManager.default.attributesOfItem(atPath: file.path)
        let beforeInode = try #require(before[.systemFileNumber] as? NSNumber)

        try LLMConfigFile.writeNonSecretJSON([
            "provider": "ollama",
            "ollama_model": "complete-new-value",
        ], toPath: file.path)

        let after = try FileManager.default.attributesOfItem(atPath: file.path)
        let afterInode = try #require(after[.systemFileNumber] as? NSNumber)
        #expect(afterInode != beforeInode)
        let data = try Data(contentsOf: file)
        let object = try #require(
            JSONSerialization.jsonObject(with: data) as? [String: Any]
        )
        #expect(object["ollama_model"] as? String == "complete-new-value")
        #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["llm_config.json"])
    }

    @Test("FIFO carrier fails without blocking before fstat")
    func fifoDoesNotBlock() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("llm_config.json")
        try #require(mkfifo(file.path, 0o600) == 0)
        let started = Date()

        #expect(throws: (any Error).self) {
            _ = try LLMConfigFile.loadAndScrub(atPath: file.path)
        }
        #expect(Date().timeIntervalSince(started) < 1.0)
    }

    @Test("hard-linked config cannot rewrite an unrelated inode")
    func hardLinkSubstitutionFailsClosed() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let victim = directory.appendingPathComponent("unrelated.json")
        let config = directory.appendingPathComponent("llm_config.json")
        let sentinel = "HARDLINK-VICTIM-MUST-STAY-UNCHANGED"
        let original = Data(#"{"claude_api_key":"HARDLINK-VICTIM-MUST-STAY-UNCHANGED"}"#.utf8)
        try original.write(to: victim)
        try FileManager.default.linkItem(at: victim, to: config)

        #expect(throws: (any Error).self) {
            _ = try LLMConfigFile.loadAndScrub(atPath: config.path)
        }
        #expect(throws: (any Error).self) {
            try LLMConfigFile.writeNonSecretJSON(
                ["provider": "ollama"],
                toPath: config.path
            )
        }
        let after = try Data(contentsOf: victim)
        #expect(after == original)
        #expect(String(decoding: after, as: UTF8.self).contains(sentinel))
    }

    @Test("scrub and writer reject a symlink without modifying its target")
    func noSymlinkFollowing() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let victim = directory.appendingPathComponent("victim.json")
        let link = directory.appendingPathComponent("llm_config.json")
        let sentinel = "SYMLINK-TARGET-MUST-STAY-UNCHANGED"
        let victimBytes = Data(#"{"openai_api_key":"SYMLINK-TARGET-MUST-STAY-UNCHANGED"}"#.utf8)
        try victimBytes.write(to: victim)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: victim)

        #expect(throws: (any Error).self) {
            _ = try LLMConfigFile.loadAndScrub(atPath: link.path)
        }
        #expect(throws: (any Error).self) {
            try LLMConfigFile.writeNonSecretJSON(["provider": "ollama"], toPath: link.path)
        }

        let after = try Data(contentsOf: victim)
        #expect(after == victimBytes)
        #expect(String(decoding: after, as: UTF8.self).contains(sentinel))
    }

    @Test("scrub rejects a symlink in an ancestor component")
    func noAncestorSymlinkFollowing() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let realParent = directory.appendingPathComponent("real", isDirectory: true)
        let linkedParent = directory.appendingPathComponent("linked", isDirectory: true)
        try FileManager.default.createDirectory(at: realParent, withIntermediateDirectories: false)
        try FileManager.default.createSymbolicLink(at: linkedParent, withDestinationURL: realParent)
        let realConfig = realParent.appendingPathComponent("llm_config.json")
        let sentinel = "ANCESTOR-SYMLINK-TARGET-MUST-STAY-UNCHANGED"
        let original = Data(#"{"gemini_api_key":"ANCESTOR-SYMLINK-TARGET-MUST-STAY-UNCHANGED"}"#.utf8)
        try original.write(to: realConfig)

        #expect(throws: (any Error).self) {
            _ = try LLMConfigFile.loadAndScrub(
                atPath: linkedParent.appendingPathComponent("llm_config.json").path
            )
        }
        #expect(throws: (any Error).self) {
            try LLMConfigFile.writeNonSecretJSON(
                ["provider": "ollama"],
                toPath: linkedParent.appendingPathComponent("llm_config.json").path
            )
        }
        #expect(try Data(contentsOf: realConfig) == original)
        #expect(String(decoding: original, as: UTF8.self).contains(sentinel))
    }

    @Test("only the file owner may perform an on-disk scrub or rewrite")
    func ownerContextPolicy() {
        #expect(LLMConfigFile.isOwnedByEffectiveUser(501, effectiveUser: 501))
        #expect(LLMConfigFile.isOwnedByEffectiveUser(0, effectiveUser: 0))
        #expect(!LLMConfigFile.isOwnedByEffectiveUser(501, effectiveUser: 0))
        #expect(!LLMConfigFile.isOwnedByEffectiveUser(0, effectiveUser: 501))
    }

    @Test("runtime config resolver prefers user state and keeps explicit overrides hermetic")
    func runtimeConfigResolverOrder() {
        #expect(LLMConfigFile.runtimeConfigReadPaths(
            explicitDataDirectory: nil,
            userDataDirectory: "/Users/test/Library/Application Support/MacCrab",
            resolvedDataDirectory: "/Library/Application Support/MacCrab"
        ) == [
            "/Users/test/Library/Application Support/MacCrab/llm_config.json",
            "/Library/Application Support/MacCrab/llm_config.json",
        ])

        #expect(LLMConfigFile.runtimeConfigReadPaths(
            explicitDataDirectory: "/private/tmp/hermetic-mcp",
            userDataDirectory: "/Users/test/Library/Application Support/MacCrab",
            resolvedDataDirectory: "/Library/Application Support/MacCrab"
        ) == ["/private/tmp/hermetic-mcp/llm_config.json"])

        #expect(LLMConfigFile.runtimeConfigReadPaths(
            explicitDataDirectory: nil,
            userDataDirectory: "/private/tmp/same",
            resolvedDataDirectory: "/private/tmp/same",
            installedDataDirectory: "/private/tmp/same"
        ) == ["/private/tmp/same/llm_config.json"])
    }

    @Test("user-first runtime resolution scrubs before returning config")
    func runtimeResolutionNeverRepersistsSecret() throws {
        let directory = try makeDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let userDirectory = directory.appendingPathComponent("user", isDirectory: true)
        let installedDirectory = directory.appendingPathComponent("installed", isDirectory: true)
        try FileManager.default.createDirectory(at: userDirectory, withIntermediateDirectories: false)
        try FileManager.default.createDirectory(at: installedDirectory, withIntermediateDirectories: false)
        let userConfig = userDirectory.appendingPathComponent("llm_config.json")
        let installedConfig = installedDirectory.appendingPathComponent("llm_config.json")
        let sentinel = "RESOLVER-MUST-NOT-RETURN-SECRET-TO-DISK"
        try Data(
            #"{"enabled":true,"provider":"claude","claude_api_key":"RESOLVER-MUST-NOT-RETURN-SECRET-TO-DISK"}"#.utf8
        ).write(to: userConfig)
        let installedBytes = Data(#"{"enabled":false,"provider":"ollama"}"#.utf8)
        try installedBytes.write(to: installedConfig)
        let keychain = FakeLegacySecretStore()
        let paths = LLMConfigFile.runtimeConfigReadPaths(
            explicitDataDirectory: nil,
            userDataDirectory: userDirectory.path,
            resolvedDataDirectory: installedDirectory.path,
            installedDataDirectory: installedDirectory.path
        )

        var loaded: [String: Any]?
        for path in paths {
            if let candidate = try LLMConfigFile.loadAndScrub(
                atPath: path,
                legacySecretMigration: keychain.migration
            ) {
                loaded = candidate
                break
            }
        }

        #expect(loaded?["provider"] as? String == "claude")
        #expect(loaded?["claude_api_key"] == nil)
        #expect(keychain.values[.claudeAPIKey] == sentinel)
        let userBytes = try Data(contentsOf: userConfig)
        #expect(!String(decoding: userBytes, as: UTF8.self).contains(sentinel))
        #expect(try Data(contentsOf: installedConfig) == installedBytes)
        #expect(try FileManager.default.contentsOfDirectory(atPath: userDirectory.path) == ["llm_config.json"])
    }

    @Test("Keychain lookup is injectable and environment wins last")
    func secretResolutionOrder() {
        var config = LLMConfig()
        LLMSecretLoader.applyKeychainSecrets(to: &config) { key in
            "keychain-\(key.rawValue)"
        }
        #expect(config.claudeAPIKey == "keychain-llm.claude")
        #expect(config.openaiAPIKey == "keychain-llm.openai")
        #expect(config.mistralAPIKey == "keychain-llm.mistral")
        #expect(config.geminiAPIKey == "keychain-llm.gemini")
        #expect(config.ollamaAPIKey == "keychain-llm.ollama")

        let selected = LLMSecretLoader.applyEnvironmentOverrides([
            "MACCRAB_LLM_PROVIDER": "mistral",
            "MACCRAB_LLM_OLLAMA_KEY": "env-ollama",
            "MACCRAB_LLM_CLAUDE_KEY": "env-claude",
            "MACCRAB_LLM_OPENAI_KEY": "env-openai",
            "MACCRAB_LLM_MISTRAL_KEY": "env-mistral",
            "MACCRAB_LLM_GEMINI_KEY": "env-gemini",
        ], to: &config, providerSelectionEnables: true)

        #expect(selected)
        #expect(config.enabled)
        #expect(config.provider == .mistral)
        #expect(config.ollamaAPIKey == "env-ollama")
        #expect(config.claudeAPIKey == "env-claude")
        #expect(config.openaiAPIKey == "env-openai")
        #expect(config.mistralAPIKey == "env-mistral")
        #expect(config.geminiAPIKey == "env-gemini")
    }
}
