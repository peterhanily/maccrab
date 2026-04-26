// DNSSinkholeAllowlistTests.swift
// MacCrabCoreTests
//
// Validates the v1.6.19 protected-domain allowlist on DNSSinkhole.
// A malicious or hallucinated threat-intel feed must never cause us to
// sinkhole a domain whose loss would brick the system (ocsp.apple.com,
// gateway.icloud.com, github.com, our own appcast, etc.).

import Testing
import Foundation
@testable import MacCrabCore

@Suite("DNSSinkhole protected-domain allowlist")
struct DNSSinkholeAllowlistTests {

    // MARK: - isProtected

    @Test("Rejects exact-match Apple critical endpoints")
    func rejectsAppleCriticalExact() {
        #expect(DNSSinkhole.isProtected("ocsp.apple.com"))
        #expect(DNSSinkhole.isProtected("gateway.icloud.com"))
        #expect(DNSSinkhole.isProtected("time.apple.com"))
        #expect(DNSSinkhole.isProtected("crl.apple.com"))
        #expect(DNSSinkhole.isProtected("crl3.apple.com"))
        #expect(DNSSinkhole.isProtected("albert.apple.com"))
    }

    @Test("Rejects Apple wildcard subdomains")
    func rejectsAppleWildcards() {
        #expect(DNSSinkhole.isProtected("apple.com"))
        #expect(DNSSinkhole.isProtected("foo.apple.com"))
        #expect(DNSSinkhole.isProtected("deeply.nested.subdomain.apple.com"))
        #expect(DNSSinkhole.isProtected("icloud.com"))
        #expect(DNSSinkhole.isProtected("photos.icloud.com"))
        #expect(DNSSinkhole.isProtected("mzstatic.com"))
    }

    @Test("Rejects GitHub and dependency-hosting domains")
    func rejectsGitHub() {
        #expect(DNSSinkhole.isProtected("github.com"))
        #expect(DNSSinkhole.isProtected("api.github.com"))
        #expect(DNSSinkhole.isProtected("raw.githubusercontent.com"))
        #expect(DNSSinkhole.isProtected("foo.github.io"))
    }

    @Test("Rejects Google API endpoints (Chrome, sign-in, browsing)")
    func rejectsGoogleAPIs() {
        #expect(DNSSinkhole.isProtected("googleapis.com"))
        #expect(DNSSinkhole.isProtected("oauth2.googleapis.com"))
        #expect(DNSSinkhole.isProtected("gstatic.com"))
        #expect(DNSSinkhole.isProtected("fonts.gstatic.com"))
    }

    @Test("Rejects MacCrab's own update / appcast surfaces")
    func rejectsMacCrabSelf() {
        #expect(DNSSinkhole.isProtected("maccrab.com"))
        #expect(DNSSinkhole.isProtected("www.maccrab.com"))
    }

    @Test("Rejects Microsoft / Office 365 / Outlook")
    func rejectsMicrosoft() {
        #expect(DNSSinkhole.isProtected("microsoft.com"))
        #expect(DNSSinkhole.isProtected("login.microsoftonline.com"))
        #expect(DNSSinkhole.isProtected("teams.office.com"))
        #expect(DNSSinkhole.isProtected("outlook.com"))
    }

    @Test("Rejects AWS / S3 / CloudFront infra")
    func rejectsAWS() {
        #expect(DNSSinkhole.isProtected("aws.amazon.com"))
        #expect(DNSSinkhole.isProtected("s3.amazonaws.com"))
        #expect(DNSSinkhole.isProtected("d1234.cloudfront.amazonaws.com"))
    }

    @Test("Rejects Stripe / Adobe / JetBrains / Mozilla / Zoom / Slack / Linear")
    func rejectsCommonSaaS() {
        #expect(DNSSinkhole.isProtected("api.stripe.com"))
        #expect(DNSSinkhole.isProtected("adobe.com"))
        #expect(DNSSinkhole.isProtected("ide.jetbrains.com"))
        #expect(DNSSinkhole.isProtected("addons.mozilla.org"))
        #expect(DNSSinkhole.isProtected("us04web.zoom.us"))
        #expect(DNSSinkhole.isProtected("api.slack.com"))
        #expect(DNSSinkhole.isProtected("linear.app"))
    }

    @Test("Rejects password manager sync endpoints")
    func rejectsPasswordManagers() {
        #expect(DNSSinkhole.isProtected("my.1password.com"))
        #expect(DNSSinkhole.isProtected("vault.bitwarden.com"))
    }

    @Test("Rejects public CA OCSP / CRL infrastructure")
    func rejectsCAInfra() {
        #expect(DNSSinkhole.isProtected("ocsp.digicert.com"))
        #expect(DNSSinkhole.isProtected("crl.sectigo.com"))
        #expect(DNSSinkhole.isProtected("letsencrypt.org"))
        #expect(DNSSinkhole.isProtected("ocsp.globalsign.com"))
    }

    @Test("Rejects localhost and .local (Bonjour) hostnames")
    func rejectsLocalhost() {
        #expect(DNSSinkhole.isProtected("localhost"))
        #expect(DNSSinkhole.isProtected("foo.localhost"))
        #expect(DNSSinkhole.isProtected("printer.local"))
        #expect(DNSSinkhole.isProtected("airdrop.local"))
    }

    @Test("Rejects IPv4 and IPv6 literals")
    func rejectsIPLiterals() {
        #expect(DNSSinkhole.isProtected("127.0.0.1"))
        #expect(DNSSinkhole.isProtected("0.0.0.0"))
        #expect(DNSSinkhole.isProtected("8.8.8.8"))
        #expect(DNSSinkhole.isProtected("192.168.1.1"))
        #expect(DNSSinkhole.isProtected("::1"))
        #expect(DNSSinkhole.isProtected("fe80::1"))
        #expect(DNSSinkhole.isProtected("2001:4860:4860::8888"))
    }

    @Test("Rejects empty / whitespace input")
    func rejectsEmpty() {
        #expect(DNSSinkhole.isProtected(""))
        #expect(DNSSinkhole.isProtected("   "))
        #expect(DNSSinkhole.isProtected("\t\n"))
    }

    @Test("Allows actual malicious domains")
    func allowsMaliciousDomains() {
        // Real-world C2 / malware domains we WOULD want to sinkhole.
        #expect(DNSSinkhole.isProtected("evil.example") == false)
        #expect(DNSSinkhole.isProtected("malware-c2.xyz") == false)
        #expect(DNSSinkhole.isProtected("phishing-site.tk") == false)
        #expect(DNSSinkhole.isProtected("randomdomain.io") == false)
    }

    @Test("Treats input as case-insensitive")
    func caseInsensitive() {
        #expect(DNSSinkhole.isProtected("APPLE.COM"))
        #expect(DNSSinkhole.isProtected("Foo.Apple.Com"))
        #expect(DNSSinkhole.isProtected("LOCALHOST"))
    }

    @Test("Wildcard pattern only matches at the suffix, not partial substring")
    func wildcardSuffixDiscipline() {
        // "*.apple.com" should match "apple.com" and "foo.apple.com"
        // but NOT "fakeapple.com" or "apple.com.evil.example"
        #expect(DNSSinkhole.isProtected("fakeapple.com") == false)
        #expect(DNSSinkhole.isProtected("apple.com.evil.example") == false)
        #expect(DNSSinkhole.isProtected("notgithub.com") == false)
    }

    // MARK: - filterProtected

    @Test("filterProtected partitions input into accepted and rejected")
    func filterPartitions() {
        let input: Set<String> = [
            "ocsp.apple.com",       // protected
            "evil.example",         // accepted
            "github.com",           // protected
            "malware-c2.xyz",       // accepted
            "127.0.0.1",            // protected (IP literal)
        ]
        let result = DNSSinkhole.filterProtected(input)
        #expect(result.accepted.count == 2)
        #expect(result.accepted.contains("evil.example"))
        #expect(result.accepted.contains("malware-c2.xyz"))
        #expect(result.rejected.count == 3)
        #expect(result.rejected.contains("ocsp.apple.com"))
        #expect(result.rejected.contains("github.com"))
        #expect(result.rejected.contains("127.0.0.1"))
    }

    @Test("filterProtected handles empty input")
    func filterEmpty() {
        let result = DNSSinkhole.filterProtected([])
        #expect(result.accepted.isEmpty)
        #expect(result.rejected.isEmpty)
    }

    @Test("filterProtected accepts everything when nothing is protected")
    func filterAllAccepted() {
        let input: Set<String> = ["evil.example", "malware.xyz", "c2.tk"]
        let result = DNSSinkhole.filterProtected(input)
        #expect(result.accepted == input)
        #expect(result.rejected.isEmpty)
    }

    @Test("filterProtected rejects everything when all are protected")
    func filterAllRejected() {
        let input: Set<String> = ["apple.com", "github.com", "localhost", "127.0.0.1"]
        let result = DNSSinkhole.filterProtected(input)
        #expect(result.accepted.isEmpty)
        #expect(result.rejected == input)
    }

    // MARK: - end-to-end on the actor

    @Test("enable() drops protected entries silently")
    func enableDropsProtected() async {
        let sinkhole = DNSSinkhole()
        // Mix protected + actual-bad domains. Without root we won't actually
        // write to /etc/hosts, but the actor's internal sinkholdDomains set
        // will reflect the filter.
        await sinkhole.enable(domains: [
            "ocsp.apple.com",
            "github.com",
            "evil.example",
            "malware-c2.xyz",
        ])
        let stats = await sinkhole.stats()
        // Only the 2 non-protected entries should have been kept.
        #expect(stats.domainCount == 2)
        #expect(stats.enabled == true)
    }

    @Test("addDomains() drops protected entries on incremental add")
    func addDomainsDropsProtected() async {
        let sinkhole = DNSSinkhole()
        await sinkhole.enable(domains: ["initial-evil.example"])
        await sinkhole.addDomains([
            "apple.com",          // dropped
            "127.0.0.1",          // dropped (IP literal)
            "another-evil.xyz",   // kept
        ])
        let stats = await sinkhole.stats()
        #expect(stats.domainCount == 2)  // initial-evil + another-evil
    }
}
