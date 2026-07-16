// ESHelpers.swift
// MacCrabCore
//
// Helper functions for converting Endpoint Security C API types
// into Swift-native MacCrab model objects.

import Foundation
import EndpointSecurity
import Darwin.POSIX

// MARK: - String Conversion

/// Convert an `es_string_token_t` (pointer + length) into a Swift `String`.
/// Returns an empty string if the data pointer is nil or length is zero.
///
/// The underlying memory is owned by the ES framework and is only valid for
/// the duration of the callback, so we **copy** the bytes into a new Swift
/// `String` rather than using a no-copy wrapper.
func esStringToSwift(_ token: es_string_token_t) -> String {
    guard token.length > 0, let data = token.data else {
        return ""
    }
    // es_string_token_t is NOT guaranteed to be null-terminated,
    // so we must use the explicit length via a buffer pointer copy.
    // data is UnsafePointer<CChar> (Int8); rebind to UInt8 for String(bytes:encoding:).
    let bufferPointer = UnsafeBufferPointer(
        start: data,
        count: token.length
    )
    return bufferPointer.withMemoryRebound(to: UInt8.self) { uint8Buffer in
        String(bytes: uint8Buffer, encoding: .utf8)
            ?? String(repeating: "\u{FFFD}", count: token.length)
    }
}

/// Extract the path string from an `es_file_t` pointer.
func esFileToPath(_ file: UnsafePointer<es_file_t>) -> String {
    return esStringToSwift(file.pointee.path)
}

// MARK: - Process Conversion

/// Build a `ProcessInfo` from an `es_process_t` pointer.
///
/// Uses `audit_token_to_pid` and `audit_token_to_euid` from the BSM
/// library to extract the numeric pid and effective uid from the audit token.
/// The primitive, decoded ES process fields MacCrab consumes. This is the
/// TESTABLE SEAM between the raw `es_process_t` (which only the kernel can
/// build, at euid 0 + entitlement, so it can't be synthesized in a unit test)
/// and the `ProcessInfo` mapping. `processFromESProcess` extracts these from
/// the live struct; `esProcessInfo(from:)` does the pure mapping so the field
/// logic (signer classification, responsible-pid, codesig) is unit-testable.
struct ESProcessFields {
    var pid: Int32
    var ppid: Int32
    /// Responsible pid (from `responsible_audit_token`) — the originator macOS
    /// attributes this process to, vs `ppid` (launchd/xpcproxy for GUI/agent
    /// launches). Parity field with the eslogger path.
    var rpid: Int32
    var euid: uid_t
    var executablePath: String
    var signingId: String
    var teamId: String
    var codesigningFlags: UInt32
    var isPlatformBinary: Bool
    /// Real process birth time from `es_process_t.start_time`. Defaulted so
    /// test constructors stay source-compatible; the live ES path always
    /// supplies the kernel value. Previously hardcoded to Date() (event-
    /// processing time), which drifted per-event and broke any consumer that
    /// keys on a stable per-process identity (agent-session id, trace anti-
    /// recycle).
    var startTime: Date = Date()
    /// v1.21.4 (P6 fix): the real audit identity of this process, extracted
    /// from the ES `audit_token`. Defaulted nil so test constructors stay
    /// source-compatible and the eslogger/kdebug parity paths (which have no
    /// audit_token) simply carry nil. The live ES path always supplies it so
    /// agent-trace correlation can match the TraceRegistry binding.
    var auditIdentity: AuditIdentity? = nil
}

/// Pure, unit-testable mapping from decoded ES fields to `ProcessInfo`. Mirrors
/// the field set the eslogger path produces (EsloggerParser) so the two
/// collectors can't silently diverge on what reaches detection.
func esProcessInfo(from f: ESProcessFields) -> ProcessInfo {
    let processName = (f.executablePath as NSString).lastPathComponent

    // v1.17.1: classify via the shared SignerType.classify so the ES and
    // eslogger paths can't drift. See SignerType.classify for the trust model
    // (kernel platform-binary + team-gated com.apple.* identifier).
    let signerType = SignerType.classify(
        codesigningFlags: f.codesigningFlags,
        teamId: f.teamId,
        signingId: f.signingId,
        isPlatformBinary: f.isPlatformBinary
    )

    // v1.18 NOTE (file-event-codesig-fields-partial): only signerType /
    // teamId / signingId / flags are populated from the raw ES event.
    // isNotarized / isAdhocSigned / issuerChain / certHashes are left nil
    // here — EventEnricher's NotarizationChecker backfills them via a cached
    // Security query. SignerType (populated here) is the reliable trust gate.
    let codeSignature = CodeSignatureInfo(
        signerType: signerType,
        teamId: f.teamId.isEmpty ? nil : f.teamId,
        signingId: f.signingId.isEmpty ? nil : f.signingId,
        flags: f.codesigningFlags
    )

    // ppid recorded as a minimal ancestor; name/path are filled by enrichment.
    var ancestors: [ProcessAncestor] = []
    if f.ppid > 0 {
        ancestors.append(ProcessAncestor(pid: f.ppid, executable: "", name: ""))
    }

    // Architecture from compile-time target (ES doesn't expose CPU type).
    let architecture: String? = {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return nil
        #endif
    }()

    return ProcessInfo(
        pid: f.pid,
        ppid: f.ppid,
        rpid: f.rpid,
        name: processName,
        executable: f.executablePath,
        commandLine: "",
        args: [],            // Populated separately for exec events
        workingDirectory: "",
        userId: f.euid,
        userName: "",        // Resolved later by enrichment
        groupId: 0,
        startTime: f.startTime,
        codeSignature: codeSignature,
        ancestors: ancestors,
        architecture: architecture,
        isPlatformBinary: f.isPlatformBinary,
        auditIdentity: f.auditIdentity
    )
}

/// Build a `ProcessInfo` from an `es_process_t`. Thin adapter: extract the
/// primitive fields (the part that genuinely needs the live kernel struct)
/// then delegate to the pure, testable `esProcessInfo(from:)`. The
/// `responsible_audit_token` → `rpid` extraction here is the parity fix that
/// restores responsible-originator lineage on the shipping sysext (was 0).
func processFromESProcess(_ proc: UnsafePointer<es_process_t>) -> ProcessInfo {
    let p = proc.pointee
    return esProcessInfo(from: ESProcessFields(
        pid: audit_token_to_pid(p.audit_token),
        ppid: p.ppid,
        rpid: audit_token_to_pid(p.responsible_audit_token),
        euid: audit_token_to_euid(p.audit_token),
        executablePath: esFileToPath(p.executable),
        signingId: esStringToSwift(p.signing_id),
        teamId: esStringToSwift(p.team_id),
        codesigningFlags: p.codesigning_flags,
        isPlatformBinary: p.is_platform_binary,
        // Real birth time from the kernel (struct timeval) — gives every
        // event of a process a STABLE startTime so session/trace identity
        // doesn't drift. Falls back to now if the field is unset (tv_sec<=0).
        startTime: p.start_time.tv_sec > 0
            ? Date(timeIntervalSince1970: Double(p.start_time.tv_sec) + Double(p.start_time.tv_usec) / 1_000_000)
            : Date(),
        // v1.21.4 (P6 fix): the real audit identity (pidversion/asid/uids) so
        // agent-trace correlation reconstructs the SAME ProcessIdentity the
        // TraceRegistry binding was keyed on.
        auditIdentity: AuditIdentity(from: p.audit_token)
    ))
}

// MARK: - Exec Argument Extraction

/// Extract the full argv array from an exec event.
///
/// The ES framework provides `es_exec_arg_count` / `es_exec_arg` helpers
/// to walk the argument list. These functions operate on the
/// `es_event_exec_t` (not the outer `es_message_t`).
func argsFromExecMessage(_ message: UnsafePointer<es_message_t>) -> [String] {
    // es_exec_arg_count / es_exec_arg expect a pointer to es_event_exec_t.
    return withUnsafePointer(to: message.pointee.event.exec) { execEvent in
        let argCount = es_exec_arg_count(execEvent)
        guard argCount > 0 else { return [] }

        var args: [String] = []
        args.reserveCapacity(Int(argCount))

        for i in 0 ..< argCount {
            let token = es_exec_arg(execEvent, i)
            args.append(esStringToSwift(token))
        }
        return args
    }
}

// MARK: - Exec Environment Extraction (TRACEPARENT/TRACESTATE only)

/// v1.9 Agent Traces — bounded scan of an exec event's environment block
/// for W3C trace context.
///
/// IMPORTANT INVARIANT: this function does NOT return the env block. It
/// inspects only `TRACEPARENT` and `TRACESTATE`, parses the former under
/// strict v00 rules via `TraceExtractor.parseTraceparent`, and returns a
/// `TraceContext` with no other env data attached. The env block itself is
/// never copied, persisted, logged, or sent to LLMs.
///
/// Bound: at most `TraceExtractor.maxEnvVarsScanned` entries OR
/// `TraceExtractor.maxEnvBytesScanned` cumulative bytes, whichever first.
/// Protects the exec hot path from pathologically-large envs (Xcode
/// toolchains, dense Node spawns).
///
/// Returns nil if no valid TRACEPARENT was present within the scan bounds.
func traceContextFromExecMessage(_ message: UnsafePointer<es_message_t>) -> TraceContext? {
    return withUnsafePointer(to: message.pointee.event.exec) { execEvent in
        let envCount = es_exec_env_count(execEvent)
        guard envCount > 0 else { return nil }
        return TraceExtractor.scanEnv(count: Int(envCount)) { i in
            let token = es_exec_env(execEvent, UInt32(i))
            return esStringToSwift(token)
        }
    }
}
