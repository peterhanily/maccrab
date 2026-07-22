// swift-tools-version:5.9
import PackageDescription

// assessment-framework (P0): this is a NON-SHIPPING sub-package. The root MacCrab
// package never references it, so nothing here can ever end up in a release build.
// Trigger/orchestrate logic lives here; the shipping engine only OBSERVES.
let package = Package(
    name: "AssessmentHarness",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(name: "HarnessCore", targets: ["HarnessCore"]),
        .executable(name: "maccrab-assess", targets: ["maccrab-assess"]),
    ],
    dependencies: [
        // Reach MacCrabCore in the repo root without vendoring it.
        .package(name: "MacCrab", path: "../.."),
    ],
    targets: [
        .target(
            name: "HarnessCore",
            dependencies: [
                .product(name: "MacCrabCore", package: "MacCrab"),
            ]
        ),
        .executableTarget(
            name: "maccrab-assess",
            dependencies: ["HarnessCore"]
        ),
        .testTarget(
            name: "HarnessCoreTests",
            dependencies: ["HarnessCore"]
        ),
    ]
)
