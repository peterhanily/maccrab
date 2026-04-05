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
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-testing.git", branch: "release/6.2"),
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
            dependencies: ["MacCrabCore"]
        ),
        .executableTarget(
            name: "maccrabctl",
            dependencies: ["MacCrabCore"]
        ),
        .executableTarget(
            name: "MacCrabApp",
            dependencies: ["MacCrabCore"],
            resources: [
                .process("Resources"),
            ]
        ),
        .testTarget(
            name: "MacCrabCoreTests",
            dependencies: [
                "MacCrabCore",
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
