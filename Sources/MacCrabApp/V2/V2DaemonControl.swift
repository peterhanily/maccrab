// V2DaemonControl.swift
// Out-of-process actions targeting the running MacCrab daemon /
// system extension. Mirrors v1's `RuleBundleInstaller` pattern.

import Foundation

public enum V2DaemonControl {
    /// Send SIGHUP to both the system extension and the legacy
    /// standalone daemon. Either one may be running depending on
    /// install path; whichever isn't installed simply returns no-op
    /// from pkill.
    @discardableResult
    public static func reloadDetectionRules() -> Bool {
        var anySent = false
        for target in ["com.maccrab.agent", "maccrabd"] {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
            p.arguments = ["-HUP", target]
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            do {
                try p.run()
                p.waitUntilExit()
                // pkill exit 0 = at least one match; 1 = no match;
                // we still consider it a "tried" success — the user
                // doesn't need to know which target was hit.
                if p.terminationStatus == 0 { anySent = true }
            } catch {
                // pkill not present or sandbox-denied — surface false.
            }
        }
        return anySent
    }
}
