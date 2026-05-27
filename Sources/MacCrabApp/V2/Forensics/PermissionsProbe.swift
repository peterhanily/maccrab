// PermissionsProbe.swift
//
// rc.11 — proactive Full Disk Access detection for the Forensics
// tab. Most scanners need FDA; if it's not granted every scan
// quietly comes back with "5 scanners didn't run" and the
// operator's left guessing why.
//
// Strategy: try to enumerate TCC-protected paths. macOS's TCC
// layer returns "Operation not permitted" (EPERM) for the
// `readDirectory` call when FDA isn't granted, even though the
// directory exists. Probing multiple candidate paths handles
// the case where any one of them doesn't exist on this Mac
// (no Mail.app set up, no Safari history yet, etc.).
//
// Detection runs synchronously and is cheap (a few stat calls);
// the view calls it on .task / .onAppear.

import Foundation

public enum FullDiskAccessStatus: Sendable, Equatable {
    /// Probe could read protected dirs — FDA granted.
    case granted
    /// Probe was denied — FDA NOT granted, scanners will fail.
    case denied
    /// None of the probe paths exist or are readable — can't tell.
    /// Treated as granted by the UI (no false-alarm banner).
    case unknown
}

public enum PermissionsProbe {

    /// Probe whether this MacCrabApp.app has Full Disk Access.
    public static func fullDiskAccess() -> FullDiskAccessStatus {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let candidates: [URL] = [
            home.appendingPathComponent("Library/Messages"),
            home.appendingPathComponent("Library/Mail"),
            home.appendingPathComponent("Library/Safari"),
            URL(fileURLWithPath: "/Library/Application Support/com.apple.TCC"),
        ]
        var sawEPERM = false
        var sawReadable = false
        for url in candidates {
            switch probe(url: url) {
            case .granted:   sawReadable = true
            case .denied:    sawEPERM = true
            case .unknown:   break
            }
        }
        if sawReadable { return .granted }
        if sawEPERM    { return .denied  }
        return .unknown
    }

    /// Open System Settings to the Full Disk Access pane.
    public static func openSystemSettingsFullDiskAccess() {
        if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles") {
            #if canImport(AppKit)
            NSWorkspace.shared.open(url)
            #endif
        }
    }

    // MARK: - Internals

    private static func probe(url: URL) -> FullDiskAccessStatus {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else {
            return .unknown
        }
        do {
            _ = try fm.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)
            return .granted
        } catch let error as NSError {
            // POSIX EPERM (1) under NSPOSIXErrorDomain, or
            // NSCocoaErrorDomain code 257 ("you don't have
            // permission") both indicate TCC denial.
            if error.domain == NSPOSIXErrorDomain && error.code == 1 { return .denied }
            if error.domain == NSCocoaErrorDomain && error.code == 257 { return .denied }
            return .unknown
        }
    }
}

#if canImport(AppKit)
import AppKit
#endif
