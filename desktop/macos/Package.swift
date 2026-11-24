// swift-tools-version: 5.10
import PackageDescription
let package = Package(
    name: "MSM5xxx Emulator",
    defaultLocalization: "en",
    platforms: [.macOS("15.0")],
    products: [.executable(name: "MSM5xxx Emulator", targets: ["MSM5xxxEmulator"])],
    dependencies: [.package(url: "https://github.com/sparkle-project/Sparkle", exact: "2.10.1")],
    targets: [.executableTarget(name: "MSM5xxxEmulator", dependencies: [.product(name: "Sparkle", package: "Sparkle")], path: "Sources/PhoneEmulator", resources: [.process("Resources")])]
)
