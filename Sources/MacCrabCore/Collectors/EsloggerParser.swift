// EsloggerParser.swift
// MacCrabCore
//
// Parses eslogger JSON output into MacCrab Event objects.
// Produces byte-for-byte identical events to ESCollector for the same
// underlying kernel data — enabling a fallback collection path that does
// not require the Endpoint Security entitlement.

import Foundation
import os.log

// MARK: - EsloggerParser

/// Parses eslogger JSON output into MacCrab Event objects.
/// Produces identical events to ESCollector for the same underlying kernel data.
public enum EsloggerParser {

    private static let logger = Logger(subsystem: "com.maccrab", category: "eslogger-parser")

    /// CS_VALID from <sys/codesign.h>, mirrors ESHelpers.
    private static let CS_VALID: UInt32 = 0x00000001

    // MARK: - Main Entry Point

    /// Parse a single eslogger JSON line into an Event, or nil if it should be dropped.
    public static func parse(_ json: [String: Any]) -> Event? {
        // Extract top-level fields.
        let timeStr = str(json, "time")
        let timestamp = parseTimestamp(timeStr)

        let processDict = dict(json, "process") ?? [:]
        let processInfo = extractProcess(from: processDict)

        guard let eventDict = json["event"] as? [String: Any] else {
            logger.warning("Missing 'event' dict in eslogger JSON")
            return nil
        }

        // The event dict has a single key matching the event name.
        guard let eventName = eventDict.keys.first,
              let eventPayload = eventDict[eventName] as? [String: Any] else {
            logger.warning("Cannot determine event type from eslogger JSON")
            return nil
        }

        let event: Event?
        switch eventName {
        case "exec":    event = parseExec(eventPayload, timestamp: timestamp)
        case "fork":    event = parseFork(eventPayload, timestamp: timestamp)
        case "exit":    event = Event(timestamp: timestamp, eventCategory: .process, eventType: .end, eventAction: "exit", process: processInfo, severity: .informational)
        case "create":  event = parseCreate(eventPayload, timestamp: timestamp, process: processInfo)
        case "write":   event = parseWrite(eventPayload, timestamp: timestamp, process: processInfo)
        case "close":   event = parseClose(eventPayload, timestamp: timestamp, process: processInfo)
        case "rename":  event = parseRename(eventPayload, timestamp: timestamp, process: processInfo)
        case "unlink":  event = parseUnlink(eventPayload, timestamp: timestamp, process: processInfo)
        case "signal":  event = parseSignal(eventPayload, timestamp: timestamp, process: processInfo)
        case "kextload": event = parseKextload(eventPayload, timestamp: timestamp, process: processInfo)
        case "mmap":    event = parseMmap(eventPayload, timestamp: timestamp, process: processInfo)
        case "mprotect": event = parseMprotect(eventPayload, timestamp: timestamp, process: processInfo)
        case "setowner": event = parseSetowner(eventPayload, timestamp: timestamp, process: processInfo)
        case "setmode": event = parseSetmode(eventPayload, timestamp: timestamp, process: processInfo)
        default:
            logger.debug("Unhandled eslogger event type: \(eventName)")
            event = nil
        }

        // Enrich event with eslogger-specific metadata not in ProcessInfo
        guard var result = event else { return nil }

        // CDHash — binary identity hash for threat intel matching
        let cdhash = str(processDict, "cdhash")
        if !cdhash.isEmpty {
            result.enrichments["process.cdhash"] = cdhash
        }

        // Session ID — for lateral movement detection across login sessions
        let sessionId = int(processDict, "session_id")
        if sessionId != 0 {
            result.enrichments["process.session_id"] = String(sessionId)
        }

        // Sequence numbers — for gap/drop detection
        if let globalSeq = json["global_seq_num"] as? Int {
            result.enrichments["es.global_seq_num"] = String(globalSeq)
        }

        // Environment variables — detect DYLD injection in env, not just command line
        if eventName == "exec" {
            let envVars = extractEnvVars(from: eventPayload)
            for envVar in envVars {
                if envVar.hasPrefix("DYLD_INSERT_LIBRARIES=") ||
                   envVar.hasPrefix("DYLD_FRAMEWORK_PATH=") ||
                   envVar.hasPrefix("DYLD_LIBRARY_PATH=") {
                    result.enrichments["exec.dyld_env"] = envVar
                }
            }
            // dyld_exec_path — Rosetta/DYLD path manipulation
            if let dyldPath = (eventPayload["dyld_exec_path"] as? [String: Any])?["path"] as? String,
               !dyldPath.isEmpty {
                result.enrichments["exec.dyld_exec_path"] = dyldPath
            }
        }

        return result
    }

    /// Extract environment variables from exec event payload.
    private static func extractEnvVars(from payload: [String: Any]) -> [String] {
        // Real eslogger: { "count": N, "items": [{"value": "VAR=val"}, ...] }
        if let envObj = payload["env"] as? [String: Any],
           let items = envObj["items"] as? [[String: Any]] {
            return items.compactMap { $0["value"] as? String }
        }
        // Fallback: simple array
        if let envArray = payload["env"] as? [String] { return envArray }
        return []
    }

    // MARK: - Process Extraction

    /// Extract a `ProcessInfo` from an eslogger process dictionary.
    ///
    /// - Parameters:
    ///   - dict: The process dictionary from eslogger JSON.
    ///   - architecture: Optional architecture override (used by exec to pass cputype).
    /// - Returns: A fully populated `ProcessInfo`.
    static func extractProcess(from processDict: [String: Any], architecture: String? = nil) -> ProcessInfo {
        let auditToken = dict(processDict, "audit_token") ?? [:]
        let pid = Int32(int(auditToken, "pid"))
        let uid = uint32(auditToken, "euid")

        let ppid: Int32 = {
            let directPpid = int(processDict, "ppid")
            if directPpid != 0 {
                return Int32(directPpid)
            }
            // Alternative source
            if let parentToken = dict(processDict, "parent_audit_token") {
                let parentPid = int(parentToken, "pid")
                if parentPid != 0 {
                    return Int32(parentPid)
                }
            }
            return 0
        }()

        let executableDict = dict(processDict, "executable") ?? [:]
        let executablePath = str(executableDict, "path")
        let processName = (executablePath as NSString).lastPathComponent

        // Code signing info
        let signingId = str(processDict, "signing_id")
        let teamId = str(processDict, "team_id")
        let flags = uint32(processDict, "codesigning_flags")
        let isPlatformBinary = bool(processDict, "is_platform_binary")

        let signerType: SignerType = {
            if flags & CS_VALID != 0 {
                if !teamId.isEmpty {
                    if teamId == "apple" || signingId.hasPrefix("com.apple.") {
                        return .apple
                    }
                    return .devId
                }
                return .adHoc
            }
            return .unsigned
        }()

        // CDHash — enables threat intel binary hash matching
        let cdhash = str(processDict, "cdhash")

        let codeSignature = CodeSignatureInfo(
            signerType: signerType,
            teamId: teamId.isEmpty ? nil : teamId,
            signingId: signingId.isEmpty ? nil : signingId,
            flags: flags
        )

        // Responsible PID (macOS-specific attribution)
        let rpid: Int32 = {
            if let responsibleToken = dict(processDict, "responsible_audit_token") {
                let rPid = int(responsibleToken, "pid")
                if rPid != 0 { return Int32(rPid) }
            }
            return 0
        }()

        // Ancestor from ppid (matches ESHelpers behavior)
        var ancestors: [ProcessAncestor] = []
        if ppid > 0 {
            ancestors.append(ProcessAncestor(
                pid: ppid,
                executable: "",
                name: ""
            ))
        }

        // Start time from eslogger (real process birth time, not event time)
        let startTimeStr = str(processDict, "start_time")
        let startTime = startTimeStr.isEmpty ? Date() : parseTimestamp(startTimeStr)

        // Session ID for lateral movement detection
        let sessionId = int(processDict, "session_id")

        let process = ProcessInfo(
            pid: pid,
            ppid: ppid,
            rpid: rpid,
            name: processName,
            executable: executablePath,
            commandLine: "",
            args: [],
            workingDirectory: "",
            userId: uid,
            userName: "",
            groupId: UInt32(int(processDict, "group_id")),
            startTime: startTime,
            codeSignature: codeSignature,
            ancestors: ancestors,
            architecture: architecture,
            isPlatformBinary: isPlatformBinary
        )

        // Store cdhash and session_id as enrichments won't fit in ProcessInfo struct
        // They'll be accessible via the Event.enrichments dict when set by the caller
        _ = cdhash  // Used by parseExec to set enrichments
        _ = sessionId

        return process
    }

    // MARK: - Event-Specific Parsers

    private static func parseExec(_ payload: [String: Any], timestamp: Date) -> Event {
        let targetDict = dict(payload, "target") ?? [:]

        // Determine architecture from image_cputype
        let cputype = int(payload, "image_cputype")
        let architecture: String? = {
            switch cputype {
            case 0x100000C: return "arm64"    // CPU_TYPE_ARM64 (16777228)
            case 0xC:       return "x86_64"   // CPU_TYPE_X86_64 mapped (12)
            case 0x7:       return "x86"      // CPU_TYPE_I386 (7)
            default:        return nil
            }
        }()

        let targetInfo = extractProcess(from: targetDict, architecture: architecture)

        // Args — eslogger uses { "count": N, "items": [{"value": "arg"}, ...] }
        let args: [String] = {
            // Try the structured format first (real eslogger output)
            if let argsObj = payload["args"] as? [String: Any],
               let items = argsObj["items"] as? [[String: Any]] {
                return items.compactMap { $0["value"] as? String }
            }
            // Fallback: simple string array (test fixtures)
            if let argsArray = payload["args"] as? [String] { return argsArray }
            return []
        }()
        let commandLine = args.joined(separator: " ")

        // CWD
        let cwd: String = {
            if let cwdDict = dict(payload, "cwd") {
                return str(cwdDict, "path")
            }
            return ""
        }()

        // Reconstruct ProcessInfo with args, commandLine, and cwd populated.
        let enrichedTarget = ProcessInfo(
            pid: targetInfo.pid,
            ppid: targetInfo.ppid,
            rpid: targetInfo.rpid,
            name: targetInfo.name,
            executable: targetInfo.executable,
            commandLine: commandLine,
            args: args,
            workingDirectory: cwd,
            userId: targetInfo.userId,
            userName: targetInfo.userName,
            groupId: targetInfo.groupId,
            startTime: targetInfo.startTime,
            codeSignature: targetInfo.codeSignature,
            ancestors: targetInfo.ancestors,
            architecture: targetInfo.architecture,
            isPlatformBinary: targetInfo.isPlatformBinary
        )

        return Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "exec",
            process: enrichedTarget,
            severity: .informational
        )
    }

    private static func parseFork(_ payload: [String: Any], timestamp: Date) -> Event {
        let childDict = dict(payload, "child") ?? [:]
        let childInfo = extractProcess(from: childDict)
        return Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "fork",
            process: childInfo,
            severity: .informational
        )
    }

    /// Check if destination_type indicates an existing file.
    /// eslogger uses strings ("existing_file"/"new_path") while the ES C API uses ints (0/1).
    private static func isExistingFile(_ payload: [String: Any]) -> Bool {
        if let s = payload["destination_type"] as? String { return s == "existing_file" }
        if let n = payload["destination_type"] as? Int { return n == 0 }
        return false
    }

    private static func parseCreate(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event {
        let destDict = dict(payload, "destination") ?? [:]
        let path: String
        if isExistingFile(payload) {
            let existingFile = dict(destDict, "existing_file") ?? [:]
            path = str(existingFile, "path")
        } else {
            // new_path: eslogger nests dir+filename under destination directly (not under new_path)
            let dir: String
            let filename: String
            if let newPathDict = dict(destDict, "new_path") {
                // Some versions nest under new_path
                let dirDict = dict(newPathDict, "dir") ?? [:]
                dir = str(dirDict, "path")
                filename = str(newPathDict, "filename")
            } else {
                // Others put existing_file as the parent dir + filename at destination level
                let dirDict = dict(destDict, "existing_file") ?? [:]
                dir = str(dirDict, "path")
                filename = str(destDict, "filename")
            }
            path = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
        }

        let fileInfo = FileInfo(path: path, action: .create)
        return Event(
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .creation,
            eventAction: "create",
            process: process,
            file: fileInfo,
            severity: .informational
        )
    }

    private static func parseWrite(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event {
        let targetDict = dict(payload, "target") ?? [:]
        let path = str(targetDict, "path")
        let fileInfo = FileInfo(path: path, action: .write)
        return Event(
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .change,
            eventAction: "write",
            process: process,
            file: fileInfo,
            severity: .informational
        )
    }

    private static func parseClose(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event? {
        // CRITICAL: Only emit for files that were actually modified.
        guard bool(payload, "modified") else { return nil }

        let targetDict = dict(payload, "target") ?? [:]
        let path = str(targetDict, "path")
        let fileInfo = FileInfo(path: path, action: .close)
        return Event(
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .change,
            eventAction: "close_modified",
            process: process,
            file: fileInfo,
            severity: .informational
        )
    }

    private static func parseRename(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event {
        let sourceDict = dict(payload, "source") ?? [:]
        let sourcePath = str(sourceDict, "path")

        let destDict = dict(payload, "destination") ?? [:]
        let destPath: String
        if isExistingFile(payload) {
            let existingFile = dict(destDict, "existing_file") ?? [:]
            destPath = str(existingFile, "path")
        } else {
            let dir: String
            let filename: String
            if let newPathDict = dict(destDict, "new_path") {
                let dirDict = dict(newPathDict, "dir") ?? [:]
                dir = str(dirDict, "path")
                filename = str(newPathDict, "filename")
            } else {
                let dirDict = dict(destDict, "existing_file") ?? [:]
                dir = str(dirDict, "path")
                filename = str(destDict, "filename")
            }
            destPath = dir.hasSuffix("/") ? dir + filename : dir + "/" + filename
        }

        let fileInfo = FileInfo(path: destPath, action: .rename, sourcePath: sourcePath)
        return Event(
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .change,
            eventAction: "rename",
            process: process,
            file: fileInfo,
            severity: .informational
        )
    }

    private static func parseUnlink(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event {
        let targetDict = dict(payload, "target") ?? [:]
        let path = str(targetDict, "path")
        let fileInfo = FileInfo(path: path, action: .delete)
        return Event(
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .deletion,
            eventAction: "unlink",
            process: process,
            file: fileInfo,
            severity: .informational
        )
    }

    private static func parseSignal(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event {
        let sig = int(payload, "sig")
        let targetDict = dict(payload, "target") ?? [:]
        let targetInfo = extractProcess(from: targetDict)

        let enrichments: [String: String] = [
            "target.pid": String(targetInfo.pid),
            "target.executable": targetInfo.executable,
            "target.name": targetInfo.name,
        ]

        return Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .info,
            eventAction: "signal(\(sig))",
            process: process,
            enrichments: enrichments,
            severity: .informational
        )
    }

    private static func parseKextload(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event {
        let kextId = str(payload, "identifier")
        return Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .start,
            eventAction: "kextload",
            process: process,
            file: FileInfo(path: kextId, action: .create),
            severity: .medium
        )
    }

    private static func parseMmap(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event? {
        let protection = int(payload, "protection")

        // CRITICAL: Only emit for W+X mappings (potential code injection).
        let isWritable = (protection & 0x2) != 0   // PROT_WRITE
        let isExecutable = (protection & 0x4) != 0  // PROT_EXEC
        guard isWritable && isExecutable else { return nil }

        let sourceDict = dict(payload, "source") ?? [:]
        let filePath = str(sourceDict, "path")
        let fileInfo = FileInfo(path: filePath, action: .create)

        return Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .change,
            eventAction: "mmap_wx",
            process: process,
            file: fileInfo,
            enrichments: ["mmap.protection": String(protection)],
            severity: .high
        )
    }

    private static func parseMprotect(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event? {
        let protection = int(payload, "protection")

        // CRITICAL: Only emit for transitions TO W+X.
        let isWritable = (protection & 0x2) != 0   // PROT_WRITE
        let isExecutable = (protection & 0x4) != 0  // PROT_EXEC
        guard isWritable && isExecutable else { return nil }

        return Event(
            timestamp: timestamp,
            eventCategory: .process,
            eventType: .change,
            eventAction: "mprotect_wx",
            process: process,
            enrichments: ["mprotect.protection": String(protection)],
            severity: .high
        )
    }

    private static func parseSetowner(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event {
        let targetDict = dict(payload, "target") ?? [:]
        let filePath = str(targetDict, "path")
        let uid = int(payload, "uid")
        let gid = int(payload, "gid")

        let fileInfo = FileInfo(path: filePath, action: .write)
        return Event(
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .change,
            eventAction: "setowner",
            process: process,
            file: fileInfo,
            enrichments: ["file.uid": String(uid), "file.gid": String(gid)],
            severity: .informational
        )
    }

    private static func parseSetmode(_ payload: [String: Any], timestamp: Date, process: ProcessInfo) -> Event {
        let targetDict = dict(payload, "target") ?? [:]
        let filePath = str(targetDict, "path")
        let mode = int(payload, "mode")

        let fileInfo = FileInfo(path: filePath, action: .write)
        return Event(
            timestamp: timestamp,
            eventCategory: .file,
            eventType: .change,
            eventAction: "setmode",
            process: process,
            file: fileInfo,
            enrichments: ["file.mode": String(mode, radix: 8)],
            severity: .informational
        )
    }

    // MARK: - Helper Methods

    /// Safe dictionary access for nested dicts.
    private static func dict(_ d: [String: Any], _ key: String) -> [String: Any]? {
        return d[key] as? [String: Any]
    }

    /// Safe string access; returns empty string if missing or wrong type.
    private static func str(_ d: [String: Any], _ key: String) -> String {
        return d[key] as? String ?? ""
    }

    /// Safe integer access; returns 0 if missing or wrong type.
    private static func int(_ d: [String: Any], _ key: String) -> Int {
        if let v = d[key] as? Int { return v }
        if let v = d[key] as? Double { return Int(v) }
        if let v = d[key] as? NSNumber { return v.intValue }
        return 0
    }

    /// Safe UInt32 access; returns 0 if missing or wrong type.
    private static func uint32(_ d: [String: Any], _ key: String) -> UInt32 {
        if let v = d[key] as? UInt32 { return v }
        if let v = d[key] as? Int { return UInt32(v) }
        if let v = d[key] as? Double { return UInt32(v) }
        if let v = d[key] as? NSNumber { return v.uint32Value }
        return 0
    }

    /// Safe boolean access; returns false if missing or wrong type.
    private static func bool(_ d: [String: Any], _ key: String) -> Bool {
        if let v = d[key] as? Bool { return v }
        if let v = d[key] as? Int { return v != 0 }
        if let v = d[key] as? NSNumber { return v.boolValue }
        return false
    }

    // MARK: - Timestamp Parsing

    /// ISO 8601 formatter with fractional seconds for eslogger timestamps.
    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    /// Fallback ISO 8601 formatter without fractional seconds.
    private static let isoFormatterNoFrac: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f
    }()

    /// Parse an ISO 8601 timestamp string into a Date.
    /// Falls back to `Date()` if parsing fails.
    private static func parseTimestamp(_ s: String) -> Date {
        if s.isEmpty { return Date() }
        if let d = isoFormatter.date(from: s) { return d }
        if let d = isoFormatterNoFrac.date(from: s) { return d }
        logger.warning("Failed to parse timestamp: \(s)")
        return Date()
    }
}
