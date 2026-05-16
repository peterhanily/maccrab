// PackageMetadataAnalyzerTests.swift
// v1.12.0 — Registry-metadata anomaly scorer (mocked fetcher).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.12.0: PackageMetadataAnalyzer")
struct PackageMetadataAnalyzerTests {

    // MARK: - Helpers

    private func mockedAnalyzer(returning json: [String: Any]) -> PackageMetadataAnalyzer {
        let data = try! JSONSerialization.data(withJSONObject: json)
        let fetcher: PackageMetadataAnalyzer.Fetcher = { _ in data }
        return PackageMetadataAnalyzer(cacheTTL: 60, fetcher: fetcher)
    }

    // MARK: - Tests

    @Test("Top-version squat (first publish 99.0.0) is flagged")
    func topVersionSquat() {
        #expect(PackageMetadataAnalyzer.isHighFirstVersion("99.0.0"))
        #expect(PackageMetadataAnalyzer.isHighFirstVersion("100.0.0"))
        #expect(!PackageMetadataAnalyzer.isHighFirstVersion("0.1.0"))
        #expect(!PackageMetadataAnalyzer.isHighFirstVersion("1.2.3"))
    }

    @Test("Free-host homepage is classified correctly")
    func freeHostClassification() {
        #expect(PackageMetadataAnalyzer.classifyHomepage("https://my-attack.vercel.app") == .freeHost)
        #expect(PackageMetadataAnalyzer.classifyHomepage("https://example.netlify.app") == .freeHost)
        #expect(PackageMetadataAnalyzer.classifyHomepage("https://maintainer.github.io") == .freeHost)
        #expect(PackageMetadataAnalyzer.classifyHomepage("https://corp.example.com") == .corporate)
        #expect(PackageMetadataAnalyzer.classifyHomepage(nil) == .missing)
        #expect(PackageMetadataAnalyzer.classifyHomepage("") == .missing)
    }

    @Test("npm: empty description, free-host homepage, noreply email, 99.x first version → high score")
    func npmHighRiskPackage() async {
        let json: [String: Any] = [
            "description": "",
            "homepage": "https://attacker.vercel.app",
            "repository": ["url": "https://github.com/throwaway/evil"],
            "maintainers": [
                ["email": "12345+throwaway@users.noreply.github.com"],
            ],
            "time": [
                "99.0.0": "2026-05-13T00:00:00Z",
                "99.0.1": "2026-05-13T01:00:00Z",
                "99.0.2": "2026-05-13T02:00:00Z",
            ],
            "dist-tags": ["latest": "99.0.2"],
        ]
        let analyzer = mockedAnalyzer(returning: json)
        let result = await analyzer.analyze(packageName: "totally-legit", registry: .npm)
        #expect(result != nil)
        guard let r = result else { return }
        // Empty desc (25) + freeHost (15) + noreply (10) + topVersionSquat (20)
        #expect(r.score >= 50, "expected >= 50, got \(r.score). reasons: \(r.reasons)")
        #expect(r.reasons.contains(where: { $0.contains("empty description") }))
        #expect(r.reasons.contains(where: { $0.contains("free-host") }))
        #expect(r.reasons.contains(where: { $0.contains("top-version-squat") }))
        #expect(r.reasons.contains(where: { $0.contains("noreply") }))
    }

    @Test("npm: clean package (corporate homepage, real desc, no anomalies) scores 0")
    func npmCleanPackage() async {
        let json: [String: Any] = [
            "description": "A well-loved utility library for working with strings.",
            "homepage": "https://example.com/string-utils",
            "repository": ["url": "https://github.com/example/string-utils"],
            "maintainers": [["email": "team@example.com"]],
            "time": ["1.0.0": "2024-01-01T00:00:00Z"],
            "dist-tags": ["latest": "1.0.0"],
        ]
        let analyzer = mockedAnalyzer(returning: json)
        let result = await analyzer.analyze(packageName: "string-utils", registry: .npm)
        #expect(result?.score == 0)
    }

    @Test("Boilerplate description phrase fires the boilerplate signal")
    func boilerplateDescription() async {
        let json: [String: Any] = [
            "description": "This is a Node.js module that provides Hello World functionality",
            "homepage": "https://example.com",
            "maintainers": [["email": "team@example.com"]],
            "time": ["1.0.0": "2024-01-01T00:00:00Z"],
        ]
        let analyzer = mockedAnalyzer(returning: json)
        let result = await analyzer.analyze(packageName: "boring", registry: .npm)
        #expect(result?.reasons.contains(where: { $0.contains("boilerplate") }) == true)
    }

    @Test("PyPI: empty summary, free-host homepage scores up")
    func pypiHighRisk() async {
        let json: [String: Any] = [
            "info": [
                "summary": "",
                "home_page": "https://attacker.netlify.app",
                "author_email": "user@users.noreply.github.com",
                "version": "99.0.0",
            ],
            "releases": [
                "99.0.0": [["upload_time_iso_8601": "2026-05-13T00:00:00Z"]],
            ],
        ]
        let analyzer = mockedAnalyzer(returning: json)
        let result = await analyzer.analyze(packageName: "evil-py", registry: .pypi)
        #expect(result != nil)
        guard let r = result else { return }
        #expect(r.score >= 50)
    }

    @Test("Cache returns the same result on second call within TTL")
    func caching() async {
        var calls = 0
        let json: [String: Any] = ["description": "x", "time": ["1.0.0": "2024-01-01T00:00:00Z"]]
        let data = try! JSONSerialization.data(withJSONObject: json)
        let fetcher: PackageMetadataAnalyzer.Fetcher = { _ in
            calls += 1
            return data
        }
        let analyzer = PackageMetadataAnalyzer(cacheTTL: 60, fetcher: fetcher)
        _ = await analyzer.analyze(packageName: "x", registry: .npm)
        _ = await analyzer.analyze(packageName: "x", registry: .npm)
        #expect(calls == 1, "second call should hit cache; got \(calls) calls")
    }
}
