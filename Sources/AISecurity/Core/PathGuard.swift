import Foundation

/// Validates file paths supplied by Finder Services before AISecurity
/// operates on them. Guards against two classes of attack:
///
/// 1. Symlink redirection. An attacker drops a symlink in a world-writable
///    location (e.g. ~/Downloads/cute.gguf → /etc/hosts) and tricks the user
///    into right-click → Services. Without this guard the app would follow
///    the link and hash / encrypt the target.
///
/// 2. Sensitive-path operation. Even without a symlink, a user mis-selecting
///    their own SSH key or the system Keychain should get a hard stop rather
///    than proceed.
///
/// Policy: reject symlinks outright (the user can operate on the target
/// directly if they meant to). Reject operations against a fixed deny-list
/// of sensitive paths. Return a canonical absolute path for everything else.
enum PathGuard {

    /// Outcome of validating a single path.
    enum ValidationResult {
        case ok(String)            // canonical path
        case rejectedSymlink(String)
        case rejectedSensitive(String, reason: String)
        case rejectedMissing(String)
    }

    /// Deny-list of absolute path prefixes. Anything under these roots is
    /// refused regardless of the requested operation. The match is
    /// prefix-based with a trailing `/` check to avoid accidentally blocking
    /// e.g. `/etcd-data` when we meant `/etc/`.
    private static let sensitiveRoots: [(prefix: String, reason: String)] = {
        let home = NSHomeDirectory()
        return [
            ("/System",                       reason: "system files"),
            ("/usr",                          reason: "system binaries"),
            ("/bin",                          reason: "system binaries"),
            ("/sbin",                         reason: "system binaries"),
            ("/private/etc",                  reason: "system config (/etc)"),
            ("/etc",                          reason: "system config"),
            ("/private/var/db",               reason: "system databases"),
            ("/Library/Keychains",            reason: "system keychain"),
            ("\(home)/Library/Keychains",     reason: "user keychain"),
            ("\(home)/.ssh",                  reason: "SSH keys"),
            ("\(home)/.gnupg",                reason: "GPG keys"),
            ("\(home)/.aws",                  reason: "AWS credentials"),
            ("\(home)/.config/gcloud",        reason: "GCP credentials"),
            ("\(home)/.kube",                 reason: "Kubernetes credentials"),
            ("\(home)/.mac-security",         reason: "AISecurity internal data"),
        ]
    }()

    /// Validate a single path supplied by Finder Services.
    static func validate(_ rawPath: String) -> ValidationResult {
        // Use lstat via FileManager so we detect the link itself — stat would
        // transparently follow it and hide the attack.
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: rawPath, isDirectory: &isDir) else {
            return .rejectedMissing(rawPath)
        }

        // Detect symlinks via file attributes. `.typeSymbolicLink` is set iff
        // the last component is itself a link.
        if let attrs = try? fm.attributesOfItem(atPath: rawPath),
           let ftype = attrs[.type] as? FileAttributeType,
           ftype == .typeSymbolicLink {
            return .rejectedSymlink(rawPath)
        }

        // Canonicalize: strip `..`, resolve any intermediate links, and make
        // absolute. We've already checked the final component isn't a link
        // above; resolvingSymlinksInPath handles intermediate dirs that
        // *might* be symlinked on macOS (e.g. /var → /private/var).
        let canonical = (rawPath as NSString).standardizingPath
        let url = URL(fileURLWithPath: canonical)
        let resolved = url.resolvingSymlinksInPath().path

        // Enforce sensitive-root deny-list against the resolved path, so an
        // attacker can't bypass it by stacking symlinks upstream of a dir.
        for (prefix, reason) in sensitiveRoots {
            if resolved == prefix || resolved.hasPrefix(prefix + "/") {
                return .rejectedSensitive(resolved, reason: reason)
            }
        }

        return .ok(resolved)
    }

    /// Validate a batch. Returns (accepted, rejected) where `rejected`
    /// includes a short human-readable explanation suitable for display.
    static func validateBatch(_ paths: [String]) -> (accepted: [String], rejected: [(String, String)]) {
        var accepted: [String] = []
        var rejected: [(String, String)] = []
        for p in paths {
            switch validate(p) {
            case .ok(let canonical):
                accepted.append(canonical)
            case .rejectedSymlink(let path):
                rejected.append((path, "symlink — operate on the target directly"))
            case .rejectedSensitive(let path, let reason):
                rejected.append((path, "refused (\(reason))"))
            case .rejectedMissing(let path):
                rejected.append((path, "file not found"))
            }
        }
        return (accepted, rejected)
    }
}
