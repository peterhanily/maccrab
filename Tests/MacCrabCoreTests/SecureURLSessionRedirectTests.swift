// SecureURLSessionRedirectTests.swift
// enrich-01 (audit Wave 3): the redirect SSRF guard. The webhook / stream /
// notification sessions validate only the initial URL; without a redirect
// delegate, a 302 to cloud-metadata / RFC1918 space bypassed the check.

import Testing
import Foundation
@testable import MacCrabCore

@Suite("SecureURLSession redirect SSRF guard")
struct SecureURLSessionRedirectTests {

    @Test("Generic and shared sessions install a redirect-validating delegate")
    func redirectDelegateInstalled() {
        let generic = SecureURLSession.makeGeneric()
        #expect(generic.delegate is URLSessionTaskDelegate,
                "makeGeneric session must carry a URLSessionTaskDelegate for redirect validation")
        #expect(SecureURLSession.shared.delegate is URLSessionTaskDelegate,
                "shared session must carry a URLSessionTaskDelegate for redirect validation")
    }

    @Test("Redirect delegate cancels a 302 into cloud-metadata space")
    func redirectToMetadataIsCancelled() async {
        let delegate = SecureURLSession.makeGeneric().delegate as? SecureURLSession
        #expect(delegate != nil, "generic session delegate should be a SecureURLSession")
        guard let delegate else { return }

        let session = URLSession.shared
        let task = session.dataTask(with: URL(string: "https://alerts.example.com/hook")!)
        let response = HTTPURLResponse(
            url: URL(string: "https://alerts.example.com/hook")!,
            statusCode: 302, httpVersion: "HTTP/1.1", headerFields: nil)!
        let redirect = URLRequest(url: URL(string: "https://169.254.169.254/latest/meta-data/")!)

        let resolved: URLRequest? = await withCheckedContinuation { cont in
            delegate.urlSession(session, task: task,
                                willPerformHTTPRedirection: response,
                                newRequest: redirect) { cont.resume(returning: $0) }
        }
        #expect(resolved == nil, "redirect to 169.254.169.254 must be cancelled")
    }

    @Test("Redirect delegate allows a 301 to another public https host")
    func redirectToPublicIsAllowed() async {
        let delegate = SecureURLSession.makeGeneric().delegate as? SecureURLSession
        #expect(delegate != nil)
        guard let delegate else { return }

        let session = URLSession.shared
        let task = session.dataTask(with: URL(string: "https://alerts.example.com/hook")!)
        let response = HTTPURLResponse(
            url: URL(string: "https://alerts.example.com/hook")!,
            statusCode: 301, httpVersion: "HTTP/1.1", headerFields: nil)!
        let redirect = URLRequest(url: URL(string: "https://alerts.example.org/hook2")!)

        let resolved: URLRequest? = await withCheckedContinuation { cont in
            delegate.urlSession(session, task: task,
                                willPerformHTTPRedirection: response,
                                newRequest: redirect) { cont.resume(returning: $0) }
        }
        #expect(resolved != nil, "redirect to a public https host must be followed")
    }
}
