// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "TigaseSwiftOMEMO",
    platforms: [.iOS(.v13), .macOS(.v10_15)],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "TigaseSwiftOMEMO",
            targets: ["TigaseSwiftOMEMO"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(name: "TigaseSwift", url: "https://github.com/tigase/tigase-swift", .upToNextMinor(from: "3.2.0")),
        .package(url: "https://github.com/tigase/libsignal", .upToNextMinor(from: "1.0.0"))
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "TigaseSwiftOMEMO",
            dependencies: ["TigaseSwift", "libsignal"]),
        .testTarget(
            name: "TigaseSwiftOMEMOTests",
            dependencies: ["TigaseSwiftOMEMO"]),
    ]
)
