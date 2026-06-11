// RaveStagingPubOverride — debug-only seam (S2-13) that lets a *debug* build
// point the rave catalog signature check at a staging signing key, so a
// staging dry-run can verify a catalog signed offline with a non-production
// key without rebuilding with a different bundled catalog.pub.
//
// Hard rule: this override is compiled OUT of release builds. In a `#if DEBUG`
// build it reads the path from the `MACCRAB_RAVE_STAGING_PUB` environment
// variable (a 32-byte raw Ed25519 public key file). In a release build the
// function body is empty and always returns nil — there is no code path that
// can swap the bundled production key. (The pre-existing
// `MACCRAB_RAVE_CATALOG_PUB_PATH` local-dev override is a separate, broader
// seam; this one is narrower and release-refused on purpose so a staging
// rehearsal can be wired up without re-enabling the broad dev override.)
//
// Returns the raw 32-byte key data; the caller constructs the
// Curve25519.Signing.PublicKey (keeping CryptoKit out of this file's surface).

import Foundation

public enum RaveStagingPubOverride {
    /// Environment variable holding a path to a 32-byte raw Ed25519 public key.
    public static let envVar = "MACCRAB_RAVE_STAGING_PUB"

    /// Returns the raw 32-byte staging public key data when a debug build has
    /// `MACCRAB_RAVE_STAGING_PUB` set to a readable 32-byte file; nil otherwise.
    /// ALWAYS nil on release builds (the body is compiled out).
    public static func rawKeyData() -> Data? {
        #if DEBUG
        guard let path = ProcessInfo.processInfo.environment[envVar], !path.isEmpty else {
            return nil
        }
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)),
              data.count == 32 else {
            return nil
        }
        return data
        #else
        // Release builds: no staging-key override seam. Compiled out.
        return nil
        #endif
    }

    /// True when the staging override is active (debug build + env set + key
    /// readable). Lets callers surface a loud "STAGING KEY IN USE" diagnostic.
    public static var isActive: Bool { rawKeyData() != nil }
}
