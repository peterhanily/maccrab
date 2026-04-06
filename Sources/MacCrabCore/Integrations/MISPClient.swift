// MISPClient.swift
// MacCrabCore
//
// Bidirectional integration with MISP (Malware Information Sharing Platform).
// Imports IOCs from MISP events and exports MacCrab detections as MISP events.

import Foundation
import os.log

/// Bidirectional integration with MISP (Malware Information Sharing Platform).
/// Imports IOCs from MISP events and exports MacCrab detections as MISP events.
public actor MISPClient {
    private let logger = Logger(subsystem: "com.maccrab.integrations", category: "misp")

    private var baseURL: String?
    private var apiKey: String?

    public init() {
        self.baseURL = Foundation.ProcessInfo.processInfo.environment["MACCRAB_MISP_URL"]
        self.apiKey = Foundation.ProcessInfo.processInfo.environment["MACCRAB_MISP_KEY"]
    }

    public func configure(baseURL: String, apiKey: String) {
        self.baseURL = baseURL
        self.apiKey = apiKey
    }

    public var isConfigured: Bool { baseURL != nil && apiKey != nil }

    // MARK: - Import IOCs from MISP

    public struct MISPAttribute: Sendable {
        public let type: String     // "ip-dst", "domain", "md5", "sha256", "url"
        public let value: String
        public let category: String
        public let comment: String

        public init(type: String, value: String, category: String, comment: String) {
            self.type = type
            self.value = value
            self.category = category
            self.comment = comment
        }
    }

    /// Fetch recent IOCs from MISP (last N days).
    public func fetchIOCs(lastDays: Int = 7) async -> [MISPAttribute] {
        guard let baseURL = baseURL, let apiKey = apiKey else { return [] }

        let endpoint = "\(baseURL)/attributes/restSearch"
        let body: [String: Any] = [
            "last": "\(lastDays)d",
            "type": ["ip-dst", "ip-src", "domain", "hostname", "md5", "sha256", "sha1", "url"],
            "enforceWarninglist": true,
            "limit": 10000
        ]

        guard let data = await postMISP(endpoint: endpoint, body: body, apiKey: apiKey) else { return [] }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let response = json["response"] as? [String: Any],
              let attributes = response["Attribute"] as? [[String: Any]] else { return [] }

        return attributes.compactMap { attr in
            guard let type = attr["type"] as? String,
                  let value = attr["value"] as? String,
                  let category = attr["category"] as? String else { return nil }
            return MISPAttribute(
                type: type, value: value, category: category,
                comment: attr["comment"] as? String ?? ""
            )
        }
    }

    /// Fetch IOCs and categorize them for MacCrab's threat intel.
    public func fetchCategorized(lastDays: Int = 7) async -> (ips: [String], domains: [String], hashes: [String], urls: [String]) {
        let attrs = await fetchIOCs(lastDays: lastDays)
        var ips: [String] = [], domains: [String] = [], hashes: [String] = [], urls: [String] = []

        for attr in attrs {
            switch attr.type {
            case "ip-dst", "ip-src": ips.append(attr.value)
            case "domain", "hostname": domains.append(attr.value)
            case "md5", "sha256", "sha1": hashes.append(attr.value)
            case "url": urls.append(attr.value)
            default: break
            }
        }

        logger.info("MISP import: \(ips.count) IPs, \(domains.count) domains, \(hashes.count) hashes, \(urls.count) URLs")
        return (ips, domains, hashes, urls)
    }

    // MARK: - Export Detections to MISP

    /// Create a MISP event from a MacCrab alert/campaign.
    public func exportEvent(
        title: String,
        description: String,
        severity: String,
        indicators: [(type: String, value: String)],
        mitreTechniques: [String]
    ) async -> Bool {
        guard let baseURL = baseURL, let apiKey = apiKey else { return false }

        let threatLevel: Int
        switch severity.lowercased() {
        case "critical": threatLevel = 1
        case "high": threatLevel = 2
        case "medium": threatLevel = 3
        default: threatLevel = 4
        }

        // Create the event
        let event: [String: Any] = [
            "Event": [
                "info": "MacCrab Detection: \(title)",
                "distribution": 0,  // Organization only
                "threat_level_id": threatLevel,
                "analysis": 2,  // Completed
                "Tag": mitreTechniques.map { technique in
                    ["name": "mitre-attack:\(technique)"] as [String: String]
                },
                "Attribute": indicators.map { ind in
                    [
                        "type": ind.type,
                        "value": ind.value,
                        "category": categoryForType(ind.type),
                        "comment": "Detected by MacCrab: \(String(description.prefix(200)))",
                        "to_ids": true
                    ] as [String: Any]
                }
            ] as [String: Any]
        ]

        let endpoint = "\(baseURL)/events/add"
        guard let _ = await postMISP(endpoint: endpoint, body: event, apiKey: apiKey) else {
            logger.warning("Failed to export event to MISP")
            return false
        }

        logger.info("Exported event to MISP: \(title)")
        return true
    }

    // MARK: - STIX 2.1 Export

    /// Generate a STIX 2.1 bundle from MacCrab IOCs.
    public func generateSTIX(indicators: [(type: String, value: String)]) -> String {
        let stixObjects = indicators.map { ind -> [String: Any] in
            let pattern: String
            switch ind.type {
            case "ip-dst", "ip-src": pattern = "[ipv4-addr:value = '\(ind.value)']"
            case "domain", "hostname": pattern = "[domain-name:value = '\(ind.value)']"
            case "sha256": pattern = "[file:hashes.'SHA-256' = '\(ind.value)']"
            case "md5": pattern = "[file:hashes.MD5 = '\(ind.value)']"
            case "url": pattern = "[url:value = '\(ind.value)']"
            default: pattern = "[x-maccrab:value = '\(ind.value)']"
            }

            return [
                "type": "indicator",
                "spec_version": "2.1",
                "id": "indicator--\(UUID().uuidString)",
                "created": ISO8601DateFormatter().string(from: Date()),
                "modified": ISO8601DateFormatter().string(from: Date()),
                "name": "MacCrab: \(ind.type) indicator",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ISO8601DateFormatter().string(from: Date()),
                "labels": ["malicious-activity"]
            ]
        }

        let bundle: [String: Any] = [
            "type": "bundle",
            "id": "bundle--\(UUID().uuidString)",
            "objects": stixObjects
        ]

        guard let data = try? JSONSerialization.data(withJSONObject: bundle, options: .prettyPrinted),
              let json = String(data: data, encoding: .utf8) else { return "{}" }
        return json
    }

    // MARK: - Helpers

    private func postMISP(endpoint: String, body: [String: Any], apiKey: String) async -> Data? {
        guard let url = URL(string: endpoint),
              let httpBody = try? JSONSerialization.data(withJSONObject: body) else { return nil }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(apiKey, forHTTPHeaderField: "Authorization")
        request.httpBody = httpBody
        request.timeoutInterval = 30

        guard let (data, response) = try? await URLSession.shared.data(for: request),
              let http = response as? HTTPURLResponse,
              http.statusCode == 200 else { return nil }
        return data
    }

    private func categoryForType(_ type: String) -> String {
        switch type {
        case "ip-dst", "ip-src": return "Network activity"
        case "domain", "hostname": return "Network activity"
        case "sha256", "md5", "sha1": return "Payload delivery"
        case "url": return "External analysis"
        default: return "Other"
        }
    }
}
