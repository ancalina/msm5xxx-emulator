// swift-tools-version: 5.10
import PackageDescription
let package = Package(
    name: "MSM5xxx Emulator",
    defaultLocalization: "en",
    platforms: [.macOS("15.0")],
    products: [.executable(name: "MSM5xxx Emulator", targets: ["MSM5xxxEmulator"])],
    targets: [.executableTarget(name: "MSM5xxxEmulator", path: "Sources/PhoneEmulator", resources: [.process("Resources")])]
)
