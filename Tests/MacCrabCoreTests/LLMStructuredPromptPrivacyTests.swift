import Foundation
import Testing
@testable import MacCrabCore

private actor StructuredPromptRecordingBackend: LLMBackend {
    let providerName = "StructuredPromptRecording"
    private var responses: [String]
    private var prompts: [(system: String, user: String)] = []

    init(responses: [String]) { self.responses = responses }
    func isAvailable() async -> Bool { true }
    func complete(systemPrompt: String, userPrompt: String,
                  maxTokens: Int, temperature: Double) async -> String? {
        prompts.append((systemPrompt, userPrompt))
        return responses.isEmpty ? nil : responses.removeFirst()
    }
    func receivedPrompts() -> [(system: String, user: String)] { prompts }
}

@Suite("Structured investigation prompt privacy")
struct LLMStructuredPromptPrivacyTests {
    private let alertID = "3BE98630-9D33-4A13-8D9E-294AA6215934"
    private let eventID = "D1E5C9C2-7C37-4B89-BB58-9A0F81473443"
    private let fakeCredential = "FAKE_ORDINARY_VALUE"

    private func config(_ provider: LLMProvider = .claude) -> LLMConfig {
        var config = LLMConfig()
        config.provider = provider
        config.sanitizeForCloud = true
        config.trustLocalEndpoint = false
        return config
    }

    private func alert() -> Alert {
        Alert(id: alertID, ruleId: "maccrab.test.credential.option",
              ruleTitle: "Keychain Password Extraction via security CLI",
              severity: .high, eventId: eventID,
              description: "Ordinary diagnostic credential option --password " + fakeCredential)
    }

    private func event() -> Event {
        Event(id: UUID(uuidString: eventID)!,
              timestamp: Date(timeIntervalSince1970: 1_780_000_000),
              eventCategory: .process, eventType: .start, eventAction: "exec",
              process: MacCrabCore.ProcessInfo(
                pid: 42, ppid: 1, rpid: 42, name: "example-client",
                executable: "/usr/local/bin/example-client",
                commandLine: "example-client --password " + fakeCredential,
                args: ["example-client"], workingDirectory: "/tmp",
                userId: 501, userName: "synthetic-user", groupId: 20,
                startTime: Date(timeIntervalSince1970: 1_780_000_000)))
    }

    private func context(in prompt: String) throws -> [String: Any] {
        let prefix = "UNTRUSTED_ALERT_CONTEXT_JSON:\n"
        #expect(prompt.hasPrefix(prefix))
        let line = try #require(prompt.dropFirst(prefix.count).split(separator: "\n").first)
        return try #require(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
    }

    private func prompt(_ object: [String: Any], suffix: String = "\n\nReturn JSON.") throws -> String {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        return "UNTRUSTED_ALERT_CONTEXT_JSON:\n" + String(decoding: data, as: UTF8.self) + suffix
    }

    private func keyPaths(in value: Any, prefix: String = "") -> Set<String> {
        if let object = value as? [String: Any] {
            return object.reduce(into: Set<String>()) { result, entry in
                let path = prefix + "/" + entry.key
                result.insert(path)
                result.formUnion(keyPaths(in: entry.value, prefix: path))
            }
        }
        if let array = value as? [Any] {
            return array.enumerated().reduce(into: Set<String>()) { result, entry in
                result.formUnion(keyPaths(in: entry.element, prefix: prefix + "/" + String(entry.offset)))
            }
        }
        return []
    }

    private func response(eventReference: String) throws -> String {
        let value: [String: Any] = [
            "alertId": alertID, "confidence": 0.2, "verdict": "needs_human",
            "summary": "The supplied event requires ordinary human review.",
            "evidenceChain": [
                ["kind": "alert", "id": alertID, "note": "Supplied alert"],
                ["kind": "event", "id": eventReference, "note": "Supplied event"]],
            "mitreReasoning": [], "suggestedActions": [], "confidencePenalties": []]
        return String(decoding: try JSONSerialization.data(withJSONObject: value), as: UTF8.self)
    }

    @Test("First and retry investigation prompts redact credentials while retaining grounded UUIDs")
    func firstAndRetryPreserveStructure() async throws {
        for provider in [LLMProvider.claude, .ollama] {
            let backend = StructuredPromptRecordingBackend(responses: [
                try response(eventReference: "00000000-0000-4000-8000-000000000099"),
                try response(eventReference: eventID)])
            let service = LLMService(backend: backend, config: config(provider), minInterval: 0)
            let investigation = await service.investigate(alert: alert(), event: event())
            #expect(investigation?.alertId == alertID)
            #expect(investigation?.evidenceChain.last?.id == eventID)
            let received = await backend.receivedPrompts()
            #expect(received.count == 2)
            let originalContext = try context(in: LLMPrompts.alertInvestigationUser(alert: alert(), event: event()))
            for receivedPrompt in received {
                #expect(!receivedPrompt.user.contains(fakeCredential))
                let object = try context(in: receivedPrompt.user)
                #expect(keyPaths(in: object) == keyPaths(in: originalContext))
                let alertObject = try #require(object["alert"] as? [String: Any])
                let eventObject = try #require(object["event"] as? [String: Any])
                #expect(alertObject["id"] as? String == alertID)
                #expect(alertObject["event_id"] as? String == eventID)
                #expect(eventObject["id"] as? String == eventID)
                #expect((alertObject["description"] as? String)?.contains("[REDACTED]") == true)
            }
            #expect(received.last?.user.contains("Failure reason: evidence_grounding") == true)
            let counters = await service.runtimeTelemetrySnapshot().counters(for: .alertInvestigation)
            #expect(counters?.downstreamValidation.retryRequested == 1)
            #expect(counters?.downstreamValidation.accepted == 1)
            #expect(counters?.downstreamValidation.finalRejection == 0)
        }
    }

    @Test("Structured privacy still sanitizes surrounding text and unexpected keys and values")
    func surroundingAndUnexpectedContent() async throws {
        let secretKey = "/Users/synthetic-person/private"
        let object: [String: Any] = ["alert": ["id": alertID, "event_id": eventID],
                                   secretKey: ["--password " + fakeCredential]]
        let user = try prompt(object, suffix: "\n\nRetry note --password " + fakeCredential)
        let backend = StructuredPromptRecordingBackend(responses: ["ok"])
        let service = LLMService(backend: backend, config: config(), minInterval: 0)
        _ = await service.query(systemPrompt: "Instruction --password " + fakeCredential,
                                userPrompt: user, useCache: false, feature: .alertInvestigation)
        let received = try #require(await backend.receivedPrompts().first)
        #expect(!received.system.contains(fakeCredential))
        #expect(!received.user.contains(fakeCredential))
        let objectAfter = try context(in: received.user)
        #expect(objectAfter[secretKey] == nil)
        let sanitizedKey = LLMSanitizer.sanitize(secretKey)
        #expect((objectAfter[sanitizedKey] as? [String])?.first?.contains("[REDACTED]") == true)
        #expect(received.user.contains("Retry note --password [REDACTED]"))
    }

    @Test("Malformed structured context and colliding redacted keys are refused before backend admission")
    func invalidContextRefused() async throws {
        let collision = try prompt(["alert": ["id": alertID],
            "/Users/synthetic-a/private": "one", "/Users/synthetic-b/private": "two"])
        for user in ["UNTRUSTED_ALERT_CONTEXT_JSON:\n{\ninvalid", collision] {
            let backend = StructuredPromptRecordingBackend(responses: ["must not be used"])
            let service = LLMService(backend: backend, config: config(), minInterval: 0)
            let result = await service.query(systemPrompt: "instruction", userPrompt: user,
                                             useCache: false, feature: .alertInvestigation)
            #expect(result == nil)
            #expect(await backend.receivedPrompts().isEmpty)
            let counters = await service.runtimeTelemetrySnapshot().counters(for: .alertInvestigation)
            #expect(counters?.outcomes.privacyRejection == 1)
            #expect(counters?.backendCallsStartedTotal == 0)
        }
    }

    @Test("Documented ID fields preserve only UUIDs and never bypass credential redaction")
    func nonUUIDIDsAreSanitized() async throws {
        let user = try prompt(["alert": ["id": "--password " + fakeCredential,
                                         "event_id": eventID]])
        let backend = StructuredPromptRecordingBackend(responses: ["ok"])
        let service = LLMService(backend: backend, config: config(), minInterval: 0)
        _ = await service.query(systemPrompt: "instruction", userPrompt: user,
                                useCache: false, feature: .alertInvestigation)
        let received = try #require(await backend.receivedPrompts().first)
        let after = try context(in: received.user)
        let alertAfter = try #require(after["alert"] as? [String: Any])
        #expect(alertAfter["id"] as? String == "--password [REDACTED]")
        #expect(alertAfter["event_id"] as? String == eventID)
        #expect(!received.user.contains(fakeCredential))
    }

    @Test("Plain investigation prompts and other feature prompts keep ordinary sanitation")
    func unrelatedPromptsKeepPolicy() async throws {
        let plain = "Ordinary text --password " + fakeCredential
        let structured = LLMPrompts.alertInvestigationUser(alert: alert(), event: event())
        for (feature, user) in [(LLMRuntimeFeature.alertInvestigation, plain), (.unspecified, structured)] {
            let backend = StructuredPromptRecordingBackend(responses: ["ok"])
            let service = LLMService(backend: backend, config: config(), minInterval: 0)
            _ = await service.query(systemPrompt: "instruction", userPrompt: user,
                                    useCache: false, feature: feature)
            let received = try #require(await backend.receivedPrompts().first)
            #expect(received.user == LLMSanitizer.sanitize(user))
            #expect(!received.user.contains(fakeCredential))
        }
    }
}
