// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "AISecurity",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/LebJe/TOMLKit.git", exact: "0.6.0"),
    ],
    targets: [
        .systemLibrary(
            name: "CSecurityCore",
            path: "CSecurityCore"
        ),
        .executableTarget(
            name: "AISecurity",
            dependencies: ["TOMLKit", "CSecurityCore"],
            path: "Sources/AISecurity",
            exclude: ["Info.plist", "AppIcon.icns"],
            linkerSettings: [
                .unsafeFlags(["-L\(Context.packageDirectory)/CSecurityCore/lib"]),
            ]
        )
    ]
)
