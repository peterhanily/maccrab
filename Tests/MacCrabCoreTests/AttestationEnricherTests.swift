// AttestationEnricherTests.swift
// v1.12.0 — Sigstore / PEP 740 provenance verifier (mocked fetcher).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("v1.12.0: AttestationEnricher")
struct AttestationEnricherTests {

    private func mockedEnricher(returning json: [String: Any]?) -> AttestationEnricher {
        let data = json.map { try! JSONSerialization.data(withJSONObject: $0) }
        let fetcher: AttestationEnricher.Fetcher = { _ in data }
        return AttestationEnricher(cacheTTL: 60, fetcher: fetcher)
    }

    @Test("npm verified attestation: present builder + source repo → .verified")
    func npmVerified() async {
        let json: [String: Any] = [
            "attestations": [[
                "predicate": [
                    "buildDefinition": [
                        "externalParameters": [
                            "workflow": ["repository": "https://github.com/sigstore/sigstore-js"],
                        ],
                    ],
                    "runDetails": [
                        "builder": ["id": "https://github.com/actions/runner-images"],
                    ],
                ],
            ]],
        ]
        let enricher = mockedEnricher(returning: json)
        let result = await enricher.verify(packageName: "sigstore-js", version: "1.0.0", registry: .npm)
        #expect(result.status == .verified)
        #expect(result.builder != nil)
        #expect(result.sourceRepo?.contains("github.com") == true)
    }

    @Test("npm absent attestation: empty attestations array → .absent")
    func npmAbsent() async {
        let json: [String: Any] = ["attestations": [[String: Any]]()]
        let enricher = mockedEnricher(returning: json)
        let result = await enricher.verify(packageName: "no-attest", version: "0.1.0", registry: .npm)
        #expect(result.status == .absent)
    }

    @Test("npm fetch failure (nil data) → .fetchFailed")
    func npmFetchFailed() async {
        let enricher = mockedEnricher(returning: nil)
        let result = await enricher.verify(packageName: "unreachable", version: "1.0.0", registry: .npm)
        #expect(result.status == .fetchFailed)
        #expect(result.warnings.contains(where: { $0.contains("fetch failed") }))
    }

    @Test("npm builder mismatch flagged when current ≠ prior builder")
    func npmBuilderMismatch() async {
        let json: [String: Any] = [
            "attestations": [[
                "predicate": [
                    "buildDefinition": [
                        "externalParameters": [
                            "workflow": ["repository": "https://github.com/attacker/sigstore-js"],
                        ],
                    ],
                    "runDetails": [
                        "builder": ["id": "https://github.com/actions/runner-images-attacker"],
                    ],
                ],
            ]],
        ]
        let enricher = mockedEnricher(returning: json)
        let result = await enricher.verify(
            packageName: "sigstore-js", version: "2.0.0", registry: .npm,
            priorBuilder: "https://github.com/actions/runner-images"
        )
        #expect(result.status == .mismatched)
        #expect(result.warnings.first?.contains("builder identity changed") == true)
    }

    @Test("PyPI provenance present in urls[].provenance → .verified")
    func pypiVerified() async {
        let json: [String: Any] = [
            "info": ["version": "1.0.0"],
            "urls": [["provenance": "https://pypi.org/integrity/foo/1.0.0/foo-1.0.0.whl/provenance"]],
        ]
        let enricher = mockedEnricher(returning: json)
        let result = await enricher.verify(packageName: "foo", version: "1.0.0", registry: .pypi)
        #expect(result.status == .verified)
        #expect(result.builder == "pypi-trusted-publisher")
    }

    @Test("PyPI no provenance markers → .absent")
    func pypiAbsent() async {
        let json: [String: Any] = [
            "info": ["version": "1.0.0"],
            "urls": [["filename": "foo-1.0.0.whl"]],
        ]
        let enricher = mockedEnricher(returning: json)
        let result = await enricher.verify(packageName: "foo", version: "1.0.0", registry: .pypi)
        #expect(result.status == .absent)
    }
}
