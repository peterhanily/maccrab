// SPKIPinningTests.swift
// MacCrabCoreTests
//
// SecureURLSession's TLS pinning compares the SHA-256 of each presented
// certificate's SubjectPublicKeyInfo (SPKI) against a base64 pin. The risky
// part is extractSPKIHash: it re-wraps the raw key in the ASN.1
// AlgorithmIdentifier header by hand, and that must byte-for-byte reproduce
// what OpenSSL produces — otherwise a correct cert silently fails to pin (or,
// worse, the wrong header makes two keys collide). These fixtures are real
// certs generated with openssl; the expected pins are computed with:
//   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER \
//     | openssl dgst -sha256 -binary | base64
// Covers both the EC P-256 and RSA-2048 header paths.

import Testing
import Foundation
import Security
@testable import MacCrabCore

@Suite("SPKI certificate pinning")
struct SPKIPinningTests {

    // EC P-256 self-signed cert + its canonical OpenSSL SPKI pin.
    static let ecDER = "MIIBJDCBygIJAKS1/7qFy/AtMAoGCCqGSM49BAMCMBoxGDAWBgNVBAMMD21hY2NyYWItZWMtdGVzdDAeFw0yNjA2MDUyMDA4NDJaFw0zNjA2MDIyMDA4NDJaMBoxGDAWBgNVBAMMD21hY2NyYWItZWMtdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLSu55TfEJc6vWkI/oP2dxr2kGES58q66erK2xV2IF59PYbB4U22GnY/9VLNOu0ubflAWt58HRPox1gVu3fMbiUwCgYIKoZIzj0EAwIDSQAwRgIhANYEV6PRxZkP7Hy6dBiK4in/rzLOQlJ3nkeU/OhLABl7AiEAvmtiYyUirPabr0vpA/jwo2/WfBkmvpQpAUWcACwKzuA="
    static let ecPin = "Q1ckMwVCcutgHLUPL7HLpufLjyL09s7JHn4HGn01O4E="

    // RSA-2048 self-signed cert + its canonical OpenSSL SPKI pin.
    static let rsaDER = "MIICsjCCAZoCCQCAwt/DKhUFKTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBtYWNjcmFiLXJzYS10ZXN0MB4XDTI2MDYwNTIwMDQ0NVoXDTM2MDYwMjIwMDQ0NVowGzEZMBcGA1UEAwwQbWFjY3JhYi1yc2EtdGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ7SbOblJKUUfGKMWwY7yfOifiAn/IUDbztEfxg2vikuFB6/Zym9rMfZDQywyADmP45rsPrp0jym8n2oZ5yGE9I7GVJmKiZ0a26hj7+lI5/Opyns+ojrNc4FdE8A3L+8yPWa5iJisOzf7g904i/+zkk1QAYC0IbiR7jaWClBsT2pRjmUnXRbxjhmeX7XQgWry1m0gGn1YReGZ0NvaaD5U21w2mwh1GpAVpgnBEASd282+Saa8iHyoRnuh31JuYj7WbMmNbvkgTwwZS70AV6aePxcg7F2i7oPcMRHknmGaOXu896ciwrzGIYe7kBAclrOIIlqZDPL0QX5OcnTZpN4va8CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAGOFG8cCcIfz8ADMsj/5XYdrAq5jgXtEyx9QTNDZ1lci6X+0LQYF7NyGQ72oWEsOOb8N0/6QoqkZzPzggHZprWbpEksheSClpFy/wcNInSe4V6ysmVFEn0Dp7Qj33L5QLAdcrB72pb+fmzkbtA1pS6myskJ45JJ55+fk0L4p7HkHf+ypJjAMEKzY3NNWoUHiv9FO79C2PwsHMDAABCZffE4bUJujeuI899ipr+neWNOzDuyxMPM6gtIhEFI9UrYECm3GHMAgklMrWXf9n/bcubIH7Gn+9viSXydtwaOCK606A5MBShBhQqwCHlU64ajhJ+0EjHXEQXST0oH2oNsWgHw=="
    static let rsaPin = "JmGB3+vkajXzTzFXvOrfZSs2sccln6N+BoUXqlP8YFc="

    private func cert(_ b64: String) throws -> SecCertificate {
        let der = try #require(Data(base64Encoded: b64))
        return try #require(SecCertificateCreateWithData(nil, der as CFData))
    }

    @Test("EC P-256 SPKI hash matches the OpenSSL-computed pin")
    func ecPinMatches() throws {
        #expect(SecureURLSession.extractSPKIHash(from: try cert(Self.ecDER)) == Self.ecPin)
    }

    @Test("RSA-2048 SPKI hash matches the OpenSSL-computed pin")
    func rsaPinMatches() throws {
        #expect(SecureURLSession.extractSPKIHash(from: try cert(Self.rsaDER)) == Self.rsaPin)
    }

    @Test("Distinct certs produce distinct pins (no wrong-cert / collision accept)")
    func distinctPins() throws {
        let ec = SecureURLSession.extractSPKIHash(from: try cert(Self.ecDER))
        let rsa = SecureURLSession.extractSPKIHash(from: try cert(Self.rsaDER))
        #expect(ec != nil)
        #expect(rsa != nil)
        #expect(ec != rsa)
    }
}
