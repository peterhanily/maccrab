// LoopbackEndpoint.swift
// MacCrabCore
//
// Strict loopback classification for URL hosts. The engine-side LLM
// config bridge default-denies non-loopback endpoints (SSRF / exfil
// guard); the Ollama backend refuses to send a Bearer token in clear
// to a non-loopback host; LLMService skips prompt sanitization only for
// a genuinely-local Ollama. All three decisions MUST agree on what
// "loopback" means, and a textual `hasPrefix("127.")` does NOT — it
// accepts attacker hostnames like `127.0.0.1.evil.com` / `127.evil.com`.
// This helper parses the host as an IP literal instead.

import Foundation

public enum LoopbackEndpoint {

    /// True iff `rawHost` (a URL host component — `URL.host` has already
    /// stripped IPv6 brackets) is a loopback destination:
    /// - the exact name `localhost`
    /// - the IPv6 loopback literal `::1`
    /// - any IPv4 literal in `127.0.0.0/8`, validated via `inet_pton`
    ///
    /// Because `inet_pton(AF_INET,...)` only succeeds for a well-formed
    /// dotted quad, a DNS name that merely *begins* with `127.`
    /// (`127.0.0.1.evil.com`, `127.evil.com`) fails the IPv4 parse and is
    /// correctly rejected — the exact bypass a `hasPrefix("127.")` test
    /// allowed through.
    public static func isLoopback(host rawHost: String) -> Bool {
        let host = rawHost.lowercased()
        guard !host.isEmpty else { return false }
        if host == "localhost" { return true }
        if host == "::1" { return true }

        // IPv4 literal in 127.0.0.0/8? inet_pton writes network byte
        // order into s_addr; UInt32(bigEndian:) reads it back as a host
        // integer so the first octet is the high byte on every platform.
        var addr = in_addr()
        if inet_pton(AF_INET, host, &addr) == 1 {
            return (UInt32(bigEndian: addr.s_addr) >> 24) == 127
        }
        // Any other IPv6 literal or DNS name is non-loopback.
        return false
    }

    /// Convenience: parse `urlString` and classify its host. Returns
    /// false for an unparseable URL or a missing host (default-deny).
    public static func isLoopback(urlString: String) -> Bool {
        guard let url = URL(string: urlString), let host = url.host else { return false }
        return isLoopback(host: host)
    }
}
