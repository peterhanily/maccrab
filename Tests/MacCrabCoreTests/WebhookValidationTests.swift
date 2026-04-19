// WebhookValidationTests.swift
// MacCrabCoreTests
//
// Unit tests for WebhookOutput.validate — the SSRF-mitigation policy that
// gates the MACCRAB_WEBHOOK_URL env var before a webhook client is built.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("Webhook URL validation")
struct WebhookValidationTests {

    @Test("Accepts standard https public URL")
    func acceptsHttpsPublic() throws {
        try WebhookOutput.validate(url: URL(string: "https://alerts.example.com/hook")!)
    }

    @Test("Accepts http on localhost")
    func acceptsHttpLocalhost() throws {
        try WebhookOutput.validate(url: URL(string: "http://localhost:8080/hook")!)
        try WebhookOutput.validate(url: URL(string: "http://127.0.0.1:8080/hook")!)
    }

    @Test("Rejects http on non-loopback")
    func rejectsHttpPublic() {
        #expect(throws: WebhookOutput.ValidationError.self) {
            try WebhookOutput.validate(url: URL(string: "http://alerts.example.com/hook")!)
        }
    }

    @Test("Rejects unknown schemes")
    func rejectsWeirdSchemes() {
        #expect(throws: WebhookOutput.ValidationError.self) {
            try WebhookOutput.validate(url: URL(string: "file:///etc/passwd")!)
        }
        #expect(throws: WebhookOutput.ValidationError.self) {
            try WebhookOutput.validate(url: URL(string: "gopher://example.com/")!)
        }
    }

    @Test("Blocks AWS/GCP/Azure metadata address unconditionally")
    func blocksMetadataAddress() {
        // Even with allowPrivate=true the metadata IP stays blocked.
        #expect(throws: WebhookOutput.ValidationError.self) {
            try WebhookOutput.validate(
                url: URL(string: "https://169.254.169.254/latest/meta-data/")!,
                allowPrivate: true
            )
        }
    }

    @Test("Rejects RFC1918 by default")
    func rejectsRFC1918ByDefault() {
        for host in ["10.0.0.1", "192.168.1.1", "172.16.0.1", "172.31.255.255"] {
            #expect(throws: WebhookOutput.ValidationError.self) {
                try WebhookOutput.validate(url: URL(string: "https://\(host)/hook")!)
            }
        }
    }

    @Test("Allows RFC1918 when allowPrivate=true")
    func allowsPrivateOptIn() throws {
        try WebhookOutput.validate(
            url: URL(string: "https://10.0.0.1/hook")!,
            allowPrivate: true
        )
        try WebhookOutput.validate(
            url: URL(string: "https://192.168.1.1/hook")!,
            allowPrivate: true
        )
    }

    @Test("Rejects IPv4 link-local (169.254/16 except loopback)")
    func rejectsLinkLocal() {
        #expect(throws: WebhookOutput.ValidationError.self) {
            try WebhookOutput.validate(url: URL(string: "https://169.254.10.20/hook")!)
        }
    }

    @Test("Rejects IPv6 unique-local and link-local")
    func rejectsIPv6Private() {
        #expect(throws: WebhookOutput.ValidationError.self) {
            try WebhookOutput.validate(url: URL(string: "https://[fc00::1]/hook")!)
        }
        #expect(throws: WebhookOutput.ValidationError.self) {
            try WebhookOutput.validate(url: URL(string: "https://[fe80::1]/hook")!)
        }
    }

    @Test("Accepts public IPv6")
    func acceptsIPv6Public() throws {
        try WebhookOutput.validate(url: URL(string: "https://[2001:db8::1]/hook")!)
    }
}
