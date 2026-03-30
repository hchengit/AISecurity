import Foundation

/// Manages Finder tags for vault-protected files and folders.
/// Tags provide visual indication in Finder that items are protected.
enum FinderTags {

    static let vaultTag = "AISecurity Vault"
    static let readOnlyTag = "AISecurity Read-Only"
    static let localOnlyTag = "AISecurity Local-Only"

    /// Add a vault tag to a file or folder.
    static func addTag(_ path: String, protection: SecurityCoreBridge.ProtectionLevel) {
        let tag: String
        switch protection {
        case .locked: tag = vaultTag
        case .readOnly: tag = readOnlyTag
        case .localOnly: tag = localOnlyTag
        }

        let url = URL(fileURLWithPath: path)
        addFinderTag(url: url, tag: tag)

        // For locked files, also tag the .vault file
        if protection == .locked {
            let vaultURL = URL(fileURLWithPath: path + ".vault")
            if FileManager.default.fileExists(atPath: vaultURL.path) {
                addFinderTag(url: vaultURL, tag: tag)
            }
        }

        // If it's a directory, tag the folder itself
        var isDir: ObjCBool = false
        if FileManager.default.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue {
            addFinderTag(url: url, tag: tag)
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
