// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "MacCrab",
    defaultLocalization: "en",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "MacCrabCore", targets: ["MacCrabCore"]),
        // MacCrabForensics: Mac Context Plugin Platform (Track 2,
        // plan §3). Hosts the plugin runtime, encrypted ArtifactStore,
        // Case model. Linked by maccrabctl + MacCrabApp + maccrab-mcp;
        // intentionally NOT linked by MacCrabAgent (sysext) or maccrabd
        // (legacy daemon) — the plugin runtime must not crash the
        // detection engine.
        .library(name: "MacCrabForensics", targets: ["MacCrabForensics"]),
        .executable(name: "maccrabd", targets: ["maccrabd"]),
        .executable(name: "maccrabctl", targets: ["maccrabctl"]),
        .executable(name: "MacCrabApp", targets: ["MacCrabApp"]),
        .executable(name: "maccrab-mcp", targets: ["maccrab-mcp"]),
        // MacCrabAgent is built as a regular executable and then wrapped
        // into a .systemextension bundle by scripts/build-release.sh.
        // xcodebuild would do this automatically but we don't require
        // full Xcode — the bundle layout is just a directory with
        // Info.plist + MacOS/<binary> + codesign-generated _CodeSignature.
        .executable(name: "MacCrabAgent", targets: ["MacCrabAgent"]),
        // maccrab-tierb-sandbox-host: the signed self-sandboxing trampoline that
        // runs an UNTRUSTED third-party Tier-B plugin under a manifest-derived
        // deny-default profile (sandbox_init post-startup, then execv — the
        // Stream-0-spike-validated mechanism). Spawned by SandboxedTierBRunner.
        // A tiny C program so the deprecated sandbox_init lives in a binary we
        // own + sign. Release bundling/signing is a build-release.sh follow-up.
        .executable(name: "maccrab-tierb-sandbox-host", targets: ["maccrab-tierb-sandbox-host"]),
    ],
    dependencies: [
        // Test-only dep. Pinned to an exact tagged release rather than a
        // branch or bare revision so CI can't be broken by an upstream push
        // to release/6.2 — and so the manifest names a verifiable release.
        // 6.2.4 is the swift-6.2.4-RELEASE tag, == revision
        // 5ee435b15ad40ec1f644b5eb9d247f263ccd2170 (recorded in
        // Package.resolved). Bump deliberately, not implicitly.
        .package(
            url: "https://github.com/swiftlang/swift-testing.git",
            exact: "6.2.4"
        ),
        // Sparkle 2: auto-update framework for MacCrabApp only. Release
        // builds poll https://maccrab.com/appcast.xml and install signed
        // updates via SUPublicEDKey verification. Sysext updates cascade
        // through OSSystemExtensionRequest(.replace) on host-app relaunch,
        // so no Sparkle wiring is needed in the sysext target itself.
        //
        // Pinned to .exact rather than `from:` — Sparkle runs privileged
        // update installs, so a compromised upstream release could push
        // code to every MacCrab user. Bump deliberately, not implicitly.
        //
        // 2.9.2 (2026-05-17) fixes two medium advisories present in <= 2.9.1:
        //   - GHSA-g3hp-f6mg-559v: AppInstaller post-stage-1 XPC listener
        //     accepted unvalidated connections (spoofed appcast item data).
        //   - GHSA-hg88-v3cw-3qrh: binary-delta intermediate-symlink traversal
        //     in a malicious .delta (we ship full DMGs only, so unreachable
        //     for our users, but closed regardless).
        .package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.9.2"),
    ],
    targets: [
        // SQLCipher amalgamation, vendored from sqlcipher/sqlcipher v4.16.0
        // (SQLite 3.53.1). The only SQLite implementation in the codebase —
        // no target links the macOS-bundled libsqlite3 anymore. SQLCipher in
        // non-codec mode (no PRAGMA key issued) behaves identically to
        // upstream SQLite, so existing un-encrypted stores (events.db,
        // alerts.db, etc.) continue to work transparently. Encryption is
        // available on demand via PRAGMA key at the per-store level.
        //
        // See Sources/CSQLCipher/REBUILD.md for amalgamation regen steps
        // when bumping SQLCipher versions.
        .target(
            name: "CSQLCipher",
            path: "Sources/CSQLCipher",
            sources: ["sqlite3.c"],
            publicHeadersPath: "include",
            cSettings: [
                .define("SQLITE_HAS_CODEC"),
                .define("SQLCIPHER_CRYPTO_CC"),
                // SQLCipher's codec wires itself into SQLite's startup /
                // shutdown via these hooks. The amalgamation #error's at
                // compile time if they're missing.
                .define("SQLITE_EXTRA_INIT", to: "sqlcipher_extra_init"),
                .define("SQLITE_EXTRA_SHUTDOWN", to: "sqlcipher_extra_shutdown"),
                .define("SQLITE_TEMP_STORE", to: "2"),
                .define("SQLITE_THREADSAFE", to: "1"),
                .define("SQLITE_ENABLE_FTS5"),
                .define("SQLITE_ENABLE_RTREE"),
                .define("SQLITE_DEFAULT_FOREIGN_KEYS", to: "1"),
                .define("SQLITE_ENABLE_BYTECODE_VTAB"),
                .define("SQLITE_ENABLE_DBSTAT_VTAB"),
                .define("SQLITE_DQS", to: "0"),
                .define("SQLITE_STRICT_SUBTYPE", to: "1"),
                .define("HAVE_USLEEP", to: "1"),
                // Required even in SPM debug builds: SQLite's amalgamation
                // gates its internal debug helpers (sqlite3BtreeHoldsAllMutexes,
                // sqlite3SchemaMutexHeld, sqlite3NoTempsInRange, etc.) behind
                // SQLITE_DEBUG, but its assert() calls expect those helpers
                // to be declared. Defining NDEBUG turns the assert() calls
                // into no-ops, matching the standard "release-mode" SQLite
                // build documented at sqlite.org/howtocompile.html. We do
                // not enable SQLITE_DEBUG; we're not SQLite contributors and
                // its asserts are not security checks.
                .define("NDEBUG", to: "1"),
                // Suppress non-actionable warnings from the SQLite/SQLCipher
                // amalgamation. These come from upstream source we don't
                // edit; surfacing them in our build output just buries
                // legitimate diagnostics in MacCrabCore code.
                .unsafeFlags([
                    "-Wno-unused-function",
                    "-Wno-unused-but-set-variable",
                    "-Wno-shorten-64-to-32",
                    "-Wno-comma",
                    "-Wno-implicit-fallthrough",
                    "-Wno-ambiguous-macro",
                ]),
            ],
            linkerSettings: [
                .linkedFramework("Security"),
                .linkedFramework("Foundation"),
            ]
        ),
        .target(
            name: "MacCrabCore",
            dependencies: ["CSQLCipher"],
            resources: [
                .process("Resources"),
            ],
            linkerSettings: [
                .linkedLibrary("EndpointSecurity"),
                .linkedLibrary("bsm"),
                .linkedFramework("Security"),
                .linkedFramework("OSLog"),
            ]
        ),
        .executableTarget(
            name: "maccrabd",
            dependencies: ["MacCrabCore", "MacCrabAgentKit"]
        ),
        .executableTarget(
            name: "maccrabctl",
            dependencies: ["MacCrabCore", "MacCrabForensics"]
        ),
        .executableTarget(
            name: "MacCrabApp",
            dependencies: [
                "MacCrabCore",
                "MacCrabForensics",
                .product(name: "Sparkle", package: "Sparkle"),
            ],
            resources: [
                .process("Resources", localization: nil),
            ]
        ),
        .executableTarget(
            name: "maccrab-mcp",
            dependencies: ["MacCrabCore", "MacCrabForensics"]
        ),
        // Mac Context Plugin Platform — see Sources/MacCrabForensics/
        // README for module layout. Depends on MacCrabCore for shared
        // event / alert / process-identity types, and on CSQLCipher for
        // the encrypted per-case ArtifactStore + blob vault.
        .target(
            name: "MacCrabForensics",
            dependencies: ["MacCrabCore", "CSQLCipher"],
            exclude: [
                "README.md",
                "TierB/README.md",
                "MCFPResearch/README.md",
            ]
        ),
        // Shared daemon bootstrap — wraps everything that used to sit
        // inside the `maccrabd` executable target except for the entry
        // point. Both `maccrabd` (the legacy/standalone LaunchDaemon
        // fallback) and `MacCrabAgent` (the Endpoint Security sysext)
        // link this library and only differ in their outermost main.swift.
        .target(
            name: "MacCrabAgentKit",
            dependencies: ["MacCrabCore"]
        ),
        // System Extension target. Compiles to a plain Mach-O; the
        // build-release.sh script wraps it into a .systemextension
        // bundle at MacCrab.app/Contents/Library/SystemExtensions/
        // com.maccrab.agent.systemextension.
        .executableTarget(
            name: "MacCrabAgent",
            dependencies: ["MacCrabAgentKit"]
        ),
        // The third-party Tier-B sandbox trampoline (C executable). No deps:
        // it links only libSystem (sandbox_init, setrlimit, execv). The SBPL it
        // applies is written by the host at spawn time; this binary just reads
        // it, sets rlimits, applies the sandbox to itself, and execs the plugin.
        .executableTarget(
            name: "maccrab-tierb-sandbox-host",
            path: "Sources/maccrab-tierb-sandbox-host"
        ),
        .testTarget(
            name: "MacCrabCoreTests",
            dependencies: [
                "MacCrabCore",
                "MacCrabAgentKit",
                .product(name: "Testing", package: "swift-testing"),
            ],
            // LLMEvalTests reads these fixtures via `#filePath` (source-tree
            // path), but SPM still needs them declared so it stops emitting
            // `found 3 file(s) which are unhandled` warnings on every build.
            // `.copy` preserves the directory layout; the test code keeps
            // working unchanged.
            resources: [
                .copy("LLMEvalFixtures"),
                .copy("fixtures"),
            ]
        ),
        .testTarget(
            name: "MacCrabAppTests",
            dependencies: [
                "MacCrabApp",
                "MacCrabCore",
                .product(name: "Testing", package: "swift-testing"),
            ]
        ),
        .testTarget(
            name: "MacCrabForensicsTests",
            dependencies: [
                "MacCrabForensics",
                .product(name: "Testing", package: "swift-testing"),
            ]
        ),
    ]
)

// Note: MacCrabApp + MacCrabAgent are both SPM executable targets
// built via `swift build`, but the release-bundle layout (app + sysext
// Info.plist, entitlements, Developer ID code signing, .systemextension
// wrapping) is generated by xcodegen + xcodebuild on top of the plain
// Mach-O outputs:
//
//   cd Xcode && xcodegen   # regenerates MacCrab.xcodeproj (gitignored)
//
// The release flow runs `swift build -c release` for SPM products
// (MacCrabCore, maccrabctl, maccrab-mcp, maccrabd, MacCrabApp,
// MacCrabAgent), then `xcodebuild` against the xcodegen project to
// produce the signed + bundled .app + sysext, then signs + notarizes
// the resulting DMG. End-to-end pipeline: see RELEASE_PROCESS.md.
