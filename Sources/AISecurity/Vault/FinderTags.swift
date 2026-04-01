import Foundation

/// Manages Finder tags for vault-protected files and folders.
/// Tags provide visual indication in Finder that items are protected.
enum FinderTags {

    static let vaultTag = "AISecurity Vault"
    static let readOnlyTag = "AISecurity Read-Only"
    static let localOnlyTag = "AISecurity Local-Only"

    /// Add vault tag(s) to a file or folder based on protection level.
    static func addTag(_ path: String, protection: SecurityCoreBridge.ProtectionLevel) {
        let url = URL(fileURLWithPath: path)

        // Determine which tags to apply based on protection components
        if protection.isLocked {
            addFinderTag(url: url, tag: vaultTag)
        }
        if protection.isReadOnly {
            addFinderTag(url: url, tag: readOnlyTag)
        }
        if protection.isLocalOnly {
            addFinderTag(url: url, tag: localOnlyTag)
        }

        // For locked files, also tag the .vault file
        if protection.isLocked {
            let vaultURL = URL(fileURLWithPath: path + ".vault")
            if FileManager.default.fileExists(atPath: vaultURL.path) {
                addFinderTag(url: vaultURL, tag: vaultTag)
                if protection.isLocalOnly {
                    addFinderTag(url: vaultURL, tag: localOnlyTag)
                }
            }
        }

        // If it's a directory, tag the folder itself
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue {
            addFinderTag(url: url, tag: vaultTag)
        }
    }

    /// Remove vault tags from a file or folder.
    static func removeTag(_ path: String) {
        let url = URL(fileURLWithPath: path)
        removeFinderTags(url: url, tags: [vaultTag, readOnlyTag, localOnlyTag])

        // Also remove from .vault file if it exists
        let vaultURL = URL(fileURLWithPath: path + ".vault")
        if FileManager.default.fileExists(atPath: vaultURL.path) {
            removeFinderTags(url: vaultURL, tags: [vaultTag, readOnlyTag, localOnlyTag])
        }
    }

    // MARK: - Deletion Protection (macOS immutable flag)

    /// Set the macOS user-immutable flag (uchg) to prevent accidental deletion/rename/move.
    static func lockFile(_ path: String) {
        guard FileManager.default.fileExists(atPath: path) else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/chflags")
        process.arguments = ["uchg", path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }

    /// Remove the macOS user-immutable flag so the file can be modified/deleted.
    static func unlockFile(_ path: String) {
        guard FileManager.default.fileExists(atPath: path) else { return }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/chflags")
        process.arguments = ["nouchg", path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try? process.run()
        process.waitUntilExit()
    }

    /// Lock a vault-protected file and its .vault counterpart.
    static func protectFromDeletion(_ path: String, protection: SecurityCoreBridge.ProtectionLevel) {
        // Lock the .vault file for encrypted protections
        if protection.isLocked {
            let vaultFile = path + ".vault"
            lockFile(vaultFile)
        }
        // Lock the original for read-only and local-only
        if protection.isReadOnly || protection == .localOnly {
            lockFile(path)
        }
    }

    /// Unlock a vault-protected file and its .vault counterpart for vault operations.
    static func unprotectFromDeletion(_ path: String) {
        unlockFile(path)
        unlockFile(path + ".vault")
    }

    // MARK: - Private

    private static func addFinderTag(url: URL, tag: String) {
        do {
            var tags = try existingTags(for: url)
            if !tags.contains(tag) {
                tags.append(tag)
                try (url as NSURL).setResourceValue(tags, forKey: .tagNamesKey)
            }
        } catch {
            // Silently fail — tagging is best-effort
        }
    }

    private static func removeFinderTags(url: URL, tags tagsToRemove: [String]) {
        do {
            var tags = try existingTags(for: url)
            tags.removeAll { tagsToRemove.contains($0) }
            try (url as NSURL).setResourceValue(tags, forKey: .tagNamesKey)
        } catch {
            // Silently fail
        }
    }

    private static func existingTags(for url: URL) throws -> [String] {
        let values = try url.resourceValues(forKeys: [.tagNamesKey])
        return values.tagNames ?? []
    }
}
