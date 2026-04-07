// LLMSanitizer.swift
// MacCrabCore
//
// Redacts sensitive data (usernames, private IPs, hostnames) from prompts
// before sending to cloud LLM APIs. Ollama (local) bypasses this.

import Foundation

public enum LLMSanitizer {

    /// Sanitize a prompt payload for cloud API submission.
    public static func sanitize(_ text: String) -> String {
        var result = CommandSanitizer.sanitize(text)
        result = redactUserPaths(result)
        result = redactHostnames(result)
        result = redactPrivateIPs(result)
        result = redactEmails(result)
        return result
    }

    private static func redactUserPaths(_ text: String) -> String {
        let regex = try! NSRegularExpression(pattern: #"/Users/([^/\s]+)/"#)
        return regex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "/Users/[USER]/"
        )
    }

    private static func redactHostnames(_ text: String) -> String {
        let regex = try! NSRegularExpression(
            pattern: #"\b[a-zA-Z][\w\-]*\.(local|internal|corp|lan)\b"#
        )
        return regex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[HOSTNAME]"
        )
    }

    private static func redactPrivateIPs(_ text: String) -> String {
        // RFC1918 + loopback + link-local
        let regex = try! NSRegularExpression(
            pattern: #"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b"#
        )
        return regex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[PRIVATE_IP]"
        )
    }

    private static func redactEmails(_ text: String) -> String {
        let regex = try! NSRegularExpression(
            pattern: #"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"#
        )
        return regex.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text),
            withTemplate: "[EMAIL]"
        )
    }
}
