// SigV4SignerTests.swift
// Shape + determinism coverage for the hand-rolled SigV4 signer.
// AWS-vector verification is done against their documented example.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SigV4 signer")
struct SigV4SignerTests {

    private let fixedNow = {
        // 2013-05-24T00:00:00Z — matches the AWS SDK documentation example
        // for a GET request with no payload; we just use it as a stable
        // timestamp to get deterministic output.
        let comps = DateComponents(
            calendar: Calendar(identifier: .gregorian),
            timeZone: TimeZone(identifier: "UTC"),
            year: 2013, month: 5, day: 24,
            hour: 0, minute: 0, second: 0
        )
        return comps.date!
    }()

    @Test("Signed headers include Authorization + x-amz-date + content-sha256")
    func headersPresent() {
        let signed = SigV4Signer.sign(
            method: "PUT",
            url: URL(string: "https://examplebucket.s3.amazonaws.com/test.txt")!,
            headers: ["Content-Type": "text/plain"],
            body: Data("hello".utf8),
            region: "us-east-1",
            service: "s3",
            accessKey: "AKIAIOSFODNN7EXAMPLE",
            secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            now: fixedNow
        )

        #expect(signed.headers["Authorization"] != nil)
        #expect(signed.headers["x-amz-date"] == "20130524T000000Z")
        #expect(signed.headers["x-amz-content-sha256"] ==
                "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    }

    @Test("Authorization header has the expected SigV4 format")
    func authorizationShape() {
        let signed = SigV4Signer.sign(
            method: "PUT",
            url: URL(string: "https://example.s3.amazonaws.com/k")!,
            body: Data(),
            region: "us-east-1",
            service: "s3",
            accessKey: "AKIATEST",
            secretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            now: fixedNow
        )
        let auth = signed.headers["Authorization"] ?? ""
        #expect(auth.hasPrefix("AWS4-HMAC-SHA256 Credential=AKIATEST/20130524/us-east-1/s3/aws4_request"))
        #expect(auth.contains("SignedHeaders="))
        #expect(auth.contains("Signature="))
    }

    @Test("Signing is deterministic for identical inputs")
    func deterministic() {
        let params = (
            url: URL(string: "https://example.s3.amazonaws.com/deterministic")!,
            body: Data("abc".utf8),
            region: "us-west-2",
            service: "s3",
            access: "AKIA000",
            secret: "secret-xyz"
        )

        let a = SigV4Signer.sign(
            method: "PUT", url: params.url, body: params.body,
            region: params.region, service: params.service,
            accessKey: params.access, secretKey: params.secret,
            now: fixedNow
        )
        let b = SigV4Signer.sign(
            method: "PUT", url: params.url, body: params.body,
            region: params.region, service: params.service,
            accessKey: params.access, secretKey: params.secret,
            now: fixedNow
        )
        #expect(a.headers["Authorization"] == b.headers["Authorization"])
    }

    @Test("Session token is included when provided")
    func sessionToken() {
        let signed = SigV4Signer.sign(
            method: "PUT",
            url: URL(string: "https://example.s3.amazonaws.com/k")!,
            body: Data(),
            region: "us-east-1",
            service: "s3",
            accessKey: "AKIA",
            secretKey: "secret",
            sessionToken: "FwoGZXIvYXdzSTS_TOKEN_XYZ",
            now: fixedNow
        )
        #expect(signed.headers["x-amz-security-token"] == "FwoGZXIvYXdzSTS_TOKEN_XYZ")
    }

    @Test("Different payloads produce different signatures")
    func differentPayloads() {
        let a = SigV4Signer.sign(
            method: "PUT",
            url: URL(string: "https://x.s3.amazonaws.com/k")!,
            body: Data("A".utf8),
            region: "us-east-1", service: "s3",
            accessKey: "AK", secretKey: "sec",
            now: fixedNow
        )
        let b = SigV4Signer.sign(
            method: "PUT",
            url: URL(string: "https://x.s3.amazonaws.com/k")!,
            body: Data("B".utf8),
            region: "us-east-1", service: "s3",
            accessKey: "AK", secretKey: "sec",
            now: fixedNow
        )
        #expect(a.headers["Authorization"] != b.headers["Authorization"])
    }
}
