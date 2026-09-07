import Foundation

/// Download-only vendor contract verified against the official export docs on
/// 2026-09-07. Credentials belong in the URL path for the two v2 export APIs;
/// request URLs and Foundation error descriptions must therefore never be logged.
enum ThreatIntelDownloadContract {
    enum Feed: String, Sendable { case feodo = "Feodo", urlhaus = "URLhaus", malwareBazaar = "MalwareBazaar" }
    enum Failure: Error, LocalizedError {
        case credentialRequired, credentialUnavailable, invalidCredential, invalidEndpoint, oversizedResponse
        var errorDescription: String? {
            switch self {
            case .credentialRequired: return "An abuse.ch Auth-Key is required; configure it in Settings → Network enrichment. Cached indicators are retained."
            case .credentialUnavailable: return "The abuse.ch Auth-Key is unavailable from Keychain. Cached indicators are retained."
            case .invalidCredential: return "The abuse.ch Auth-Key has an unsupported format. Update it in Settings → Network enrichment."
            case .invalidEndpoint: return "The feed download endpoint could not be constructed."
            case .oversizedResponse: return "The feed exceeded the 64 MiB download limit; cached indicators are retained."
            }
        }
    }
    static let maximumResponseBytes = 64 * 1024 * 1024

    static func request(feed: Feed, authKey: String?) throws -> URLRequest {
        let endpoint: String
        switch feed {
        case .feodo:
            endpoint = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        case .urlhaus, .malwareBazaar:
            guard let key = authKey?.trimmingCharacters(in: .whitespacesAndNewlines), !key.isEmpty else {
                throw Failure.credentialRequired
            }
            let allowed = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~")
            guard key.utf8.count <= 512, key.unicodeScalars.allSatisfy(allowed.contains) else {
                throw Failure.invalidCredential
            }
            let host = feed == .urlhaus ? "urlhaus-api.abuse.ch" : "mb-api.abuse.ch"
            endpoint = "https://" + host + "/v2/files/exports/" + key + "/recent.csv"
        }
        guard let url = URL(string: endpoint) else { throw Failure.invalidEndpoint }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.setValue("MacCrab/\(MacCrabVersion.current)", forHTTPHeaderField: "User-Agent")
        return request
    }

    static func sanitizedFailure(_ error: Error) -> String {
        if let failure = error as? Failure { return failure.localizedDescription }
        if let urlError = error as? URLError { return "Feed network request failed (URL error \(urlError.code.rawValue)); cached indicators are retained." }
        return "Feed download failed; cached indicators are retained."
    }
}

/// Export credentials are embedded in a path. These fixed-host downloads never
/// follow redirects, persist cookies, cache request URLs, or log error userInfo.
private final class ThreatIntelDownloadDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

enum ThreatIntelDownloadSession {
    static let shared: URLSession = {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.tlsMinimumSupportedProtocolVersion = .TLSv12
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 60
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        return URLSession(configuration: configuration, delegate: ThreatIntelDownloadDelegate(), delegateQueue: nil)
    }()
}
