import Foundation

/// Unencrypted sidecar that stores only the information needed to monitor vault files.
/// Contains NO secrets — just paths and protection levels.
/// Read on startup so VaultFileTracker can begin monitoring immediately without passphrase.
struct VaultTrackingManifest: Codable {

    struct Entry: Codable {
        var originalPath: String
        var watchPath: String
        var protection: String  // "locked", "readOnly", "localOnly", "readOnlyLocal", "lockedLocal"
        let addedAt: String
    }

    var version: Int = 1
    var updatedAt: String
    var entries: [Entry]
}

/// Thread-safe store for the tracking sidecar file.
final class VaultTrackingStore {

    static let shared = VaultTrackingStore()

    private let filePath: String
    private let queue = DispatchQueue(label: "com.aisecurity.vault.tracking-store", qos: .utility)

    private init() {
        let secDir = SecurityConfig.shared.securityDir
        filePath = (secDir as NSString).appendingPathComponent("vault-tracking-manifest.json")
    }

    // MARK: - Load

    /// Load the tracking manifest from disk. Returns empty manifest if file doesn't exist or is corrupt.
    func load() -> VaultTrackingManifest {
        queue.sync {
            guard FileManager.default.fileExists(atPath: filePath),
                  let data = FileManager.default.contents(atPath: filePath),
                  let manifest = try? JSONDecoder().decode(VaultTrackingManifest.self, from: data) else {
                return VaultTrackingManifest(
                    updatedAt: ISO8601DateFormatter().string(from: Date()),
                    entries: []
                )
            }
            return manifest
        }
    }

    // MARK: - Save

    /// Atomically write the manifest to disk with 0600 permissions.
    func save(_ manifest: VaultTrackingManifest) {
        queue.async { [weak self] in
            guard let self else { return }

            var m = manifest
            m.updatedAt = ISO8601DateFormatter().string(from: Date())

            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            guard let data = try? encoder.encode(m) else { return }

            // Atomic write: write to temp, then rename
            let tempPath = self.filePath + ".tmp"
            let tempURL = URL(fileURLWithPath: tempPath)
            let targetURL = URL(fileURLWithPath: self.filePath)

            do {
                try data.write(to: tempURL, options: .atomic)
                // Set 0600 before moving into place
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o600],
                    ofItemAtPath: tempPath
                )
                // Move into place (atomic on same filesystem)
                if FileManager.default.fileExists(atPath: self.filePath) {
                    _ = try FileManager.default.replaceItemAt(targetURL, withItemAt: tempURL)
                } else {
                    try FileManager.default.moveItem(at: tempURL, to: targetURL)
                }
            } catch {
                // Clean up temp on failure
                try? FileManager.default.removeItem(atPath: tempPath)
            }
        }
    }

    // MARK: - Mutations

    /// Add new entries to the sidecar.
    func addEntries(_ paths: [String], watchPaths: [String], protection: SecurityCoreBridge.ProtectionLevel) {
        var manifest = load()
        let now = ISO8601DateFormatter().string(from: Date())
        let protStr = protection.sidecarKey

        for (i, path) in paths.enumerated() {
            // Skip if already tracked
            if manifest.entries.contains(where: { $0.originalPath == path }) { continue }

            let wp = i < watchPaths.count ? watchPaths[i] : ""
            manifest.entries.append(VaultTrackingManifest.Entry(
                originalPath: path,
                watchPath: wp,
                protection: protStr,
                addedAt: now
            ))
        }

        save(manifest)
    }

    /// Remove entries by original path.
    func removeEntries(_ paths: [String]) {
        var manifest = load()
        let pathSet = Set(paths)
        manifest.entries.removeAll { pathSet.contains($0.originalPath) }
        save(manifest)
    }

    /// Update a path after a file move.
    func updatePath(oldPath: String, newPath: String) {
        var manifest = load()
        if let idx = manifest.entries.firstIndex(where: { $0.originalPath == oldPath }) {
            manifest.entries[idx].originalPath = newPath
            // Update watch path: if it was based on old path, update the prefix
            let oldWatch = manifest.entries[idx].watchPath
            if oldWatch == oldPath {
                manifest.entries[idx].watchPath = newPath
            } else if oldWatch == oldPath + ".vault" {
                manifest.entries[idx].watchPath = newPath + ".vault"
            }
        }
        save(manifest)
    }

    /// Update the watch path (e.g., after lock/unlock changes which file to watch).
    func updateWatchPath(originalPath: String, newWatchPath: String) {
        var manifest = load()
        if let idx = manifest.entries.firstIndex(where: { $0.originalPath == originalPath }) {
            manifest.entries[idx].watchPath = newWatchPath
        }
        save(manifest)
    }

    /// Update protection level for an entry.
    func updateProtection(originalPath: String, protection: SecurityCoreBridge.ProtectionLevel) {
        var manifest = load()
        if let idx = manifest.entries.firstIndex(where: { $0.originalPath == originalPath }) {
            manifest.entries[idx].protection = protection.sidecarKey
        }
        save(manifest)
    }

    /// Rebuild the sidecar entirely from vault entries (source of truth reconciliation).
    func rebuild(from entries: [SecurityCoreBridge.VaultEntry]) {
        let now = ISO8601DateFormatter().string(from: Date())
        let newEntries = entries.map { entry in
            VaultTrackingManifest.Entry(
                originalPath: entry.originalPath,
                watchPath: entry.protection.isLocked ? entry.vaultPath : entry.originalPath,
                protection: entry.protection.sidecarKey,
                addedAt: now
            )
        }
        let manifest = VaultTrackingManifest(
            version: 1,
            updatedAt: now,
            entries: newEntries
        )
        save(manifest)
    }
}

// MARK: - ProtectionLevel Sidecar Key

extension SecurityCoreBridge.ProtectionLevel {

    /// Stable string key for the unencrypted sidecar (not for display — use `label` for UI).
    var sidecarKey: String {
        switch self {
        case .locked: return "locked"
        case .readOnly: return "readOnly"
        case .localOnly: return "localOnly"
        case .readOnlyLocal: return "readOnlyLocal"
        case .lockedLocal: return "lockedLocal"
        }
    }

    /// Parse a sidecar key back to a ProtectionLevel.
    static func from(sidecarKey: String) -> SecurityCoreBridge.ProtectionLevel {
        switch sidecarKey {
        case "locked": return .locked
        case "readOnly": return .readOnly
        case "localOnly": return .localOnly
        case "readOnlyLocal": return .readOnlyLocal
        case "lockedLocal": return .lockedLocal
        default: return .locked
        }
    }
}
