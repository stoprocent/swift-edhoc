// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SwiftEDHOC",
    platforms: [.iOS(.v16), .macOS(.v13), .watchOS(.v9), .tvOS(.v16)],
    products: [
        .library(name: "SwiftEDHOC", targets: ["SwiftEDHOC"]),
    ],
    dependencies: [
        .package(url: "https://github.com/valpackett/SwiftCBOR.git", from: "0.4.7"),
        .package(url: "https://github.com/krzyzanowskim/CryptoSwift.git", from: "1.8.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
    ],
    targets: [
        .target(name: "SwiftEDHOC", dependencies: [
            "SwiftCBOR", "CryptoSwift",
            .product(name: "X509", package: "swift-certificates"),
        ]),
        .testTarget(name: "SwiftEDHOCTests", dependencies: ["SwiftEDHOC"]),
    ]
)
