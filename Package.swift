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
        .executable(name: "HawkEyeApp", targets: ["HawkEyeApp"]),
    ],
    dependencies: [
        .package(url: "https://github.com/swiftlang/swift-testing.git", branch: "release/6.2"),
    ],
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
        .executableTarget(
            name: "HawkEyeApp",
            dependencies: ["HawkEyeCore"]
        ),
        .testTarget(
            name: "HawkEyeCoreTests",
            dependencies: [
                "HawkEyeCore",
                .product(name: "Testing", package: "swift-testing"),
            ]
        ),
    ]
)

// Note: HawkEyeApp (SwiftUI status bar app) is built as a separate
// Xcode project since it requires an app bundle, Info.plist, entitlements,
// and code signing that Swift Package Manager doesn't handle well.
// See Sources/HawkEyeApp/ for the app source.
// Build with: xcodebuild -project HawkEye.xcodeproj -scheme HawkEyeApp
