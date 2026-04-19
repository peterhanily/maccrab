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
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-testing.git", branch: "release/6.2"),
        // Sparkle 2: auto-update framework for MacCrabApp only. Release
        // builds poll https://maccrab.com/appcast.xml and install signed
        // updates via SUPublicEDKey verification. Sysext updates cascade
        // through OSSystemExtensionRequest(.replace) on host-app relaunch,
        // so no Sparkle wiring is needed in the sysext target itself.
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.6.4"),
    ],
    targets: [
        .target(
            name: "MacCrabCore",
            dependencies: [],
            linkerSettings: [
                .linkedLibrary("EndpointSecurity"),
                .linkedLibrary("bsm"),
                .linkedFramework("Security"),
                .linkedFramework("OSLog"),
                .linkedLibrary("sqlite3"),
            ]
        ),
        .executableTarget(
            name: "maccrabd",
            dependencies: ["MacCrabCore", "MacCrabAgentKit"]
        ),
        .executableTarget(
            name: "maccrabctl",
            dependencies: ["MacCrabCore"]
        ),
        .executableTarget(
            name: "MacCrabApp",
            dependencies: [
                "MacCrabCore",
                .product(name: "Sparkle", package: "Sparkle"),
            ],
            resources: [
                .process("Resources"),
            ]
        ),
        .executableTarget(
            name: "maccrab-mcp",
            dependencies: ["MacCrabCore"]
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
        .testTarget(
            name: "MacCrabCoreTests",
            dependencies: [
                "MacCrabCore",
                "MacCrabAgentKit",
                .product(name: "Testing", package: "swift-testing"),
            ]
        ),
    ]
)

// Note: MacCrabApp (SwiftUI status bar app) is built as a separate
// Xcode project since it requires an app bundle, Info.plist, entitlements,
// and code signing that Swift Package Manager doesn't handle well.
// See Sources/MacCrabApp/ for the app source.
// Build with: xcodebuild -project MacCrab.xcodeproj -scheme MacCrabApp
