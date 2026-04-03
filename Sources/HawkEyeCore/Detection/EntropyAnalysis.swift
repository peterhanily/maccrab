// EntropyAnalysis.swift
// HawkEyeCore
//
// Shannon entropy calculation for detecting obfuscation, DGA domains,
// and DNS tunneling. Feeds results into BehaviorScoring.

import Foundation

/// Entropy analysis utilities for command lines, domain names, and payloads.
public enum EntropyAnalysis {

    /// Calculate Shannon entropy of a string (bits per character).
    /// English text: ~3.5-4.5, Base64: ~5.5-6.0, Random/encrypted: ~7.5+
    public static func shannonEntropy(_ string: String) -> Double {
        guard !string.isEmpty else { return 0 }
        var freq: [Character: Int] = [:]
        for c in string { freq[c, default: 0] += 1 }
        let len = Double(string.count)
        return -freq.values.reduce(0.0) { sum, count in
            let p = Double(count) / len
            return sum + p * log2(p)
        }
    }

    /// Check if a command line contains suspicious high-entropy segments.
    /// Returns the highest entropy segment and its value.
    public static func analyzeCommandLine(_ cmdline: String) -> (entropy: Double, suspicious: Bool, segment: String?) {
        // Split into arguments and check each
        let args = cmdline.split(separator: " ").map(String.init)
        var maxEntropy = 0.0
        var maxSegment: String?

        for arg in args where arg.count >= 16 {
            let e = shannonEntropy(arg)
            if e > maxEntropy {
                maxEntropy = e
                maxSegment = String(arg.prefix(80))
            }
        }

        // Also check the full command line
        let fullEntropy = shannonEntropy(cmdline)

        let highestEntropy = max(maxEntropy, cmdline.count > 100 ? fullEntropy : 0)
        let suspicious = highestEntropy > 5.5 // Above base64 range

        return (highestEntropy, suspicious, maxSegment)
    }

    /// Check if a domain name looks like a DGA (Domain Generation Algorithm) output.
    /// DGA domains have high entropy and unusual character distributions.
    public static func analyzeDomain(_ domain: String) -> (entropy: Double, isDGA: Bool, reason: String?) {
        // Strip TLD for analysis
        let parts = domain.split(separator: ".")
        guard parts.count >= 2 else { return (0, false, nil) }

        // Analyze the second-level domain (SLD)
        let sld = String(parts[parts.count - 2])
        let entropy = shannonEntropy(sld)

        // DGA indicators
        var reasons: [String] = []

        // High entropy SLD
        if entropy > 4.0 && sld.count > 8 {
            reasons.append("high entropy SLD (\(String(format: "%.2f", entropy)))")
        }

        // Unusual consonant-to-vowel ratio
        let vowels = Set("aeiou")
        let vowelCount = sld.lowercased().filter { vowels.contains($0) }.count
        let consonantCount = sld.lowercased().filter { $0.isLetter && !vowels.contains($0) }.count
        if consonantCount > 0 {
            let ratio = Double(vowelCount) / Double(consonantCount)
            if ratio < 0.15 && sld.count > 6 {
                reasons.append("low vowel ratio (\(String(format: "%.2f", ratio)))")
            }
        }

        // Excessive length with numbers mixed in
        if sld.count > 15 && sld.contains(where: { $0.isNumber }) && sld.contains(where: { $0.isLetter }) {
            reasons.append("long mixed alphanumeric SLD (\(sld.count) chars)")
        }

        // Long subdomain chains (common in DNS tunneling)
        if parts.count > 4 {
            reasons.append("deep subdomain nesting (\(parts.count) levels)")
        }

        let isDGA = !reasons.isEmpty
        return (entropy, isDGA, isDGA ? reasons.joined(separator: "; ") : nil)
    }

    /// Check if DNS traffic suggests tunneling (high-entropy queries, excessive TXT records).
    public static func isDNSTunneling(queryName: String, queryType: UInt16) -> (Bool, String?) {
        let parts = queryName.split(separator: ".")

        // Check for data encoded in subdomain labels
        if parts.count > 3 {
            let subdomains = parts.dropLast(2) // Remove TLD + domain
            let totalSubdomainLen = subdomains.reduce(0) { $0 + $1.count }
            let avgLabelEntropy = subdomains.map { shannonEntropy(String($0)) }
                .reduce(0, +) / Double(max(subdomains.count, 1))

            if totalSubdomainLen > 50 && avgLabelEntropy > 3.5 {
                return (true, "long high-entropy subdomains (\(totalSubdomainLen) chars, avg entropy \(String(format: "%.1f", avgLabelEntropy)))")
            }
        }

        // TXT queries with high-entropy names are suspicious
        if queryType == 16 { // TXT
            let sld = parts.count >= 2 ? String(parts[parts.count - 2]) : queryName
            if shannonEntropy(sld) > 3.8 || queryName.count > 100 {
                return (true, "TXT query with suspicious domain (entropy \(String(format: "%.1f", shannonEntropy(sld))))")
            }
        }

        return (false, nil)
    }
}
