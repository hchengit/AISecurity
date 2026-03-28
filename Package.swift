// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AISecurity",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "AISecurity",
            path: "Sources/AISecurity",
            exclude: ["Info.plist", "AppIcon.icns"]
        )
    ]
)
