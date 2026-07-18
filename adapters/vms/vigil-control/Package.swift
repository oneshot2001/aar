// swift-tools-version:6.2
import PackageDescription

// vigil-control — AAR D3 VMS-leg mediator. A small loopback HTTP service that
// wraps VigilCore.AxisEngine.VAPIXClient so the AAR TS VmsAdapter can dispatch
// abstract commands through the transport witness to a mediator. Depends on
// the Vigil repo by path (demo-env assumption, documented in DEMO-CONTRACT);
// Vigil source is unmodified.
let package = Package(
  name: "vigil-control",
  platforms: [.macOS(.v26)],
  dependencies: [
    .package(path: "../../../../vigil/VigilCore"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
  ],
  targets: [
    .executableTarget(
      name: "vigil-control",
      dependencies: [
        .product(name: "AxisEngine", package: "VigilCore"),
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
        .product(name: "NIOHTTP1", package: "swift-nio"),
      ]
    )
  ]
)
