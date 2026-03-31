// ESHelpers.swift
// HawkEyeCore
//
// Helper functions for converting Endpoint Security C API types
// into Swift-native HawkEye model objects.

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
    let bufferPointer = UnsafeBufferPointer(
        start: data,
        count: token.length
    )
    return String(bytes: bufferPointer, encoding: .utf8)
        ?? String(cString: data) // fallback: treat as null-terminated C string
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
func processFromESProcess(_ proc: UnsafePointer<es_process_t>) -> ProcessInfo {
    let p = proc.pointee

    let pid = audit_token_to_pid(p.audit_token)
    let uid = audit_token_to_euid(p.audit_token)
    let ppid = p.ppid

    let executablePath = esFileToPath(p.executable)
    let processName = (executablePath as NSString).lastPathComponent

    // Code signing info
    let signingId = esStringToSwift(p.signing_id)
    let teamId = esStringToSwift(p.team_id)

    let signerType: SignerType = {
        if p.codesigning_flags & UInt32(CS_VALID) != 0 {
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

    let codeSignature = CodeSignatureInfo(
        signingId: signingId.isEmpty ? nil : signingId,
        teamId: teamId.isEmpty ? nil : teamId,
        signerType: signerType,
        cdHash: nil
    )

    // Build a minimal ancestor entry from the responsible process if available.
    // The `responsible_audit_token` gives us the responsible parent; for a
    // deeper ancestry chain we'd need to walk /proc or cache earlier events.
    var ancestors: [ProcessAncestor] = []
    if ppid > 0 {
        // We record ppid but without an es_process_t pointer for the parent
        // we cannot resolve name/path here — enrichment fills those in later.
        ancestors.append(ProcessAncestor(
            pid: ppid,
            name: nil,
            path: nil
        ))
    }

    return ProcessInfo(
        pid: pid,
        ppid: ppid,
        name: processName,
        path: executablePath,
        args: nil,           // Populated separately for exec events
        uid: Int(uid),
        userName: nil,       // Resolved later by enrichment
        codeSignature: codeSignature,
        ancestors: ancestors.isEmpty ? nil : ancestors
    )
}

// MARK: - Exec Argument Extraction

/// Extract the full argv array from an exec event.
///
/// The ES framework provides `es_exec_arg_count` / `es_exec_arg` helpers
/// to walk the argument list. These functions operate on the full
/// `es_message_t`, not the inner event union member.
func argsFromExecMessage(_ message: UnsafePointer<es_message_t>) -> [String] {
    let argCount = es_exec_arg_count(message)
    guard argCount > 0 else { return [] }

    var args: [String] = []
    args.reserveCapacity(Int(argCount))

    for i in 0 ..< argCount {
        let token = es_exec_arg(message, i)
        args.append(esStringToSwift(token))
    }
    return args
}
