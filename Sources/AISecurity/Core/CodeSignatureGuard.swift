import AppKit
import Foundation
import Security

/// Self-verification of the running app bundle's code signature on startup.
///
/// Purpose: detect post-install tampering. Someone with user-level write
/// access to `/Applications/AISecurity.app` could patch the main binary,
/// swap a Swift stdlib for a trojaned copy, or inject resources. Re-checking
/// the seal at every launch catches that — but only if the signature exists
/// and covers what we expect.
///
/// What this buys you under each signing mode:
///   • Developer ID / notarized build → full protection. Any resource or
///     binary change invalidates the seal; the app refuses to start.
///   • Ad-hoc signed build (current dev flow) → partial protection. Detects
///     accidental or clumsy tampering (editing files in place), but does
///     NOT prove origin — an attacker can re-sign ad-hoc. Still worth doing
///     because it turns a silent compromise into a loud one, and the check
///     becomes authoritative the moment you switch to Developer ID signing.
///   • Unsigned build → no protection. `SecStaticCodeCheckValidity` returns
///     an error for unsigned bundles. We treat that as non-fatal in dev so
///     `swift build` flows still work.
///
/// Policy:
///   - Production (running from /Applications): invalid signature = fail hard.
///   - Development (any other bundle location): log the result but continue.
///     Avoids blocking `swift run` and similar dev flows.
enum CodeSignatureGuard {

    enum CheckResult {
        case valid                     // signed and seal verifies
        case invalid(String)           // signed but tampered / wrong flags
        case unsigned                  // no signature (dev build)
        case unableToCheck(String)     // API call failed for an unrelated reason
    }

    /// Returns true if startup should proceed. In production an invalid
    /// signature causes this to return false after showing an alert.
    @discardableResult
    static func verifyOrRefuseStartup() -> Bool {
        let bundlePath = Bundle.main.bundlePath
        let result = check(bundlePath: bundlePath)
        let isProduction = bundlePath.hasPrefix("/Applications/")

        switch result {
        case .valid:
            log("Code signature valid: \(bundlePath)")
            return true

        case .unsigned:
            log("Bundle is unsigned — skipping integrity check (dev build)")
            return true   // dev flow: swift run, etc.

        case .invalid(let msg):
            log("CODE SIGNATURE INVALID: \(msg)")
            if isProduction {
                let alert = NSAlertCompat(
                    title: "AISecurity integrity check failed",
                    body: "The application bundle at \(bundlePath) has been tampered with or its signature is invalid.\n\n\(msg)\n\nReinstall AISecurity from a trusted source."
                )
                alert.runAndExit()
                return false
            }
            // Dev: warn in log, allow startup.
            return true

        case .unableToCheck(let msg):
            log("WARNING: could not verify code signature (\(msg)) — proceeding")
            return true
        }
    }

    // MARK: - Internals

    private static func check(bundlePath: String) -> CheckResult {
        let url = URL(fileURLWithPath: bundlePath)
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard createStatus == errSecSuccess, let code = staticCode else {
            return .unableToCheck("SecStaticCodeCreateWithPath failed: OSStatus \(createStatus)")
        }

        // Default flags are fine for our use: verify the seal matches the
        // on-disk contents. We don't require revocation checks (would need
        // network at startup) and don't specify multi-arch-only validation
        // (the default already covers the primary architecture).
        var errors: Unmanaged<CFError>?
        let status = SecStaticCodeCheckValidityWithErrors(code, [], nil, &errors)

        if status == errSecSuccess {
            return .valid
        }

        // errSecCSUnsigned (-67062) means the bundle has no signature at all.
        if status == -67062 {
            return .unsigned
        }

        // Any other non-success status means signed but failed validation.
        let errMsg: String
        if let err = errors?.takeRetainedValue() {
            errMsg = CFErrorCopyDescription(err) as String? ?? "OSStatus \(status)"
        } else {
            errMsg = "OSStatus \(status)"
        }
        return .invalid(errMsg)
    }

    private static func log(_ msg: String) {
        let home = NSHomeDirectory()
        let path = "\(home)/.mac-security/logs/code-signature.log"
        let line = "[\(Date())] \(msg)\n"
        // Best-effort append; ignore failures (logs dir may not exist yet in
        // very early startup paths).
        if let handle = FileHandle(forWritingAtPath: path) {
            handle.seekToEndOfFile()
            handle.write(line.data(using: .utf8) ?? Data())
            handle.closeFile()
        } else {
            try? line.write(toFile: path, atomically: true, encoding: .utf8)
        }
    }
}

/// Tiny helper that displays a blocking alert using NSAlert and then exits.
private struct NSAlertCompat {
    let title: String
    let body: String

    func runAndExit() {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = body
        alert.alertStyle = .critical
        alert.addButton(withTitle: "Quit")
        alert.runModal()
        NSApp.terminate(nil)
    }
}
