// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "HawkEye",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .library(name: "HawkEyeCore", targets: ["HawkEyeCore"]),
        .executable(name: "hawkeyed", targets: ["hawkeyed"]),
        .executable(name: "hawkctl", targets: ["hawkctl"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "HawkEyeCore",
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
            name: "hawkeyed",
            dependencies: ["HawkEyeCore"]
        ),
        .executableTarget(
            name: "hawkctl",
            dependencies: ["HawkEyeCore"]
        ),
        .testTarget(
            name: "HawkEyeCoreTests",
            dependencies: ["HawkEyeCore"]
        ),
    ]
)

// Note: HawkEyeApp (SwiftUI status bar app) is built as a separate
// Xcode project since it requires an app bundle, Info.plist, entitlements,
// and code signing that Swift Package Manager doesn't handle well.
// See Sources/HawkEyeApp/ for the app source.
// Build with: xcodebuild -project HawkEye.xcodeproj -scheme HawkEyeApp
