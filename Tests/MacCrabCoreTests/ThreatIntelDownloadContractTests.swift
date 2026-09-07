import Testing
import Foundation
@testable import MacCrabCore

@Suite("Threat intel download vendor contract")
struct ThreatIntelDownloadContractTests {
    @Test("Public Feodo request does not receive a credential")
    func publicFeed() throws {
        let request = try ThreatIntelDownloadContract.request(feed: .feodo, authKey: "fixture-key")
        #expect(request.url?.host == "feodotracker.abuse.ch")
        #expect(request.url?.path == "/downloads/ipblocklist.csv")
        #expect(request.value(forHTTPHeaderField: "Auth-Key") == nil)
        #expect(request.timeoutInterval == 30)
    }

    @Test("Authenticated exports use the documented recent CSV route", arguments: [
        ThreatIntelDownloadContract.Feed.urlhaus, .malwareBazaar
    ])
    func authenticatedExport(feed: ThreatIntelDownloadContract.Feed) throws {
        let request = try ThreatIntelDownloadContract.request(feed: feed, authKey: "fixture-key")
        let expectedHost = feed == .urlhaus ? "urlhaus-api.abuse.ch" : "mb-api.abuse.ch"
        #expect(request.url?.host == expectedHost)
        #expect(request.url?.scheme == "https")
        #expect(request.url?.path == "/v2/files/exports/fixture-key/recent.csv")
        #expect(request.url?.query == nil)
        #expect(request.value(forHTTPHeaderField: "Auth-Key") == nil)
    }

    @Test("Absent credentials yield an actionable unavailable result without a request")
    func absentCredential() {
        #expect(throws: ThreatIntelDownloadContract.Failure.self) {
            try ThreatIntelDownloadContract.request(feed: .urlhaus, authKey: nil)
        }
        #expect(throws: ThreatIntelDownloadContract.Failure.self) {
            try ThreatIntelDownloadContract.request(feed: .malwareBazaar, authKey: "  ")
        }
    }

    @Test("Network diagnostics retain the reason code without request URLs")
    func sanitizedDiagnostic() {
        let error = URLError(.timedOut, userInfo: [NSURLErrorFailingURLStringErrorKey:
            "https://urlhaus-api.abuse.ch/v2/files/exports/fixture-key/recent.csv"])
        let message = ThreatIntelDownloadContract.sanitizedFailure(error)
        #expect(message.contains(String(URLError.timedOut.rawValue)))
        #expect(!message.contains("fixture-key"))
        #expect(!message.contains("https://"))
    }
}
