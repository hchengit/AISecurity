import AppKit
import Foundation

/// "Export Portable Vault" — bundles one or more `.vault` files together
/// with the Python decryptor and a README into a destination folder (typically
/// a USB drive). The goal: a user can hand-carry the folder to any computer
/// with Python 3 and decrypt the file using their passphrase.
///
/// Security properties (intentional):
///   - The bundle contains NO passphrase hint, key material, or salt files.
///     Only ciphertext + a public tool. Losing the USB drive = the attacker
///     needs the passphrase to decrypt, exactly like the in-app case.
///   - The decryptor script is the signed copy from the app bundle. Its
///     bytes are covered by the app's code signature, so the running app
///     would refuse to start if the script were tampered with post-install.
///   - No telemetry, no network calls — the decryptor runs purely offline.
enum PortableVaultExport {

    /// User-facing entry point. Runs on the main thread; shows Open/Save
    /// panels and an alert on completion. Pass `initialVaultFiles` to skip
    /// the Open panel (used by the right-click Services flow).
    @MainActor
    static func run(initialVaultFiles: [URL]? = nil) {
        // 1. Pick source .vault files if not already provided.
        let vaultFiles: [URL]
        if let urls = initialVaultFiles, !urls.isEmpty {
            vaultFiles = urls
        } else {
            guard let picked = pickVaultFiles() else { return }   // user cancelled
            vaultFiles = picked
        }

        // 2. Pick a destination folder.
        guard let destRoot = pickDestinationFolder() else { return }

        // 3. Locate the bundled decryptor. We only ship one canonical copy;
        //    if it's missing something is badly wrong and we refuse.
        guard let toolURL = Bundle.main.url(
            forResource: "vault-decrypt",
            withExtension: "py"
        ) else {
            showError(
                "Decryptor script missing from app bundle",
                detail: "Reinstall AISecurity — the Portable Vault decryptor is not where it should be."
            )
            return
        }

        // 4. Produce a uniquely-named subfolder at the destination so we
        //    don't clobber existing files. USB drives often have mixed
        //    content and we can't assume the user picked an empty one.
        let stamp = timestampString()
        let exportDir = destRoot.appendingPathComponent("AISecurity-Portable-Vault-\(stamp)")

        do {
            try FileManager.default.createDirectory(
                at: exportDir,
                withIntermediateDirectories: true,
                attributes: nil
            )
        } catch {
            showError("Could not create export folder", detail: error.localizedDescription)
            return
        }

        // 5. Copy each vault file with its original name (e.g. secret.pdf.vault).
        //    Collision within the export folder is impossible (we just made it).
        var copied: [String] = []
        var failures: [(String, String)] = []
        for src in vaultFiles {
            let dst = exportDir.appendingPathComponent(src.lastPathComponent)
            do {
                try FileManager.default.copyItem(at: src, to: dst)
                copied.append(src.lastPathComponent)
            } catch {
                failures.append((src.lastPathComponent, error.localizedDescription))
            }
        }

        // 6. Copy the decryptor script. chmod +x so Unix users can invoke
        //    it directly if they prefer (`./vault-decrypt.py foo.vault`).
        do {
            let dst = exportDir.appendingPathComponent("vault-decrypt.py")
            try FileManager.default.copyItem(at: toolURL, to: dst)
            try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dst.path)
        } catch {
            showError("Could not copy decryptor script", detail: error.localizedDescription)
            return
        }

        // 7. Write requirements.txt for pip.
        let requirementsPath = exportDir.appendingPathComponent("requirements.txt")
        try? "cryptography>=42\n".write(to: requirementsPath, atomically: true, encoding: .utf8)

        // 8. Write README.txt with instructions. Deliberately minimal — no
        //    hints that could help an attacker who got hold of the drive.
        let readmeText = buildReadme(copiedVaultFiles: copied)
        let readmePath = exportDir.appendingPathComponent("README.txt")
        try? readmeText.write(to: readmePath, atomically: true, encoding: .utf8)

        // 9. Show result.
        showResult(exportDir: exportDir, copied: copied, failures: failures)
    }

    // MARK: - UI helpers

    @MainActor
    private static func pickVaultFiles() -> [URL]? {
        let panel = NSOpenPanel()
        panel.title = "Choose .vault file(s) to export"
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.allowedContentTypes = []   // filter by extension in the validator below
        panel.message = "Select encrypted files to include in the portable vault bundle. The files stay encrypted — anyone on the destination machine will need your passphrase to decrypt them."
        guard panel.runModal() == .OK else { return nil }
        let urls = panel.urls.filter { $0.pathExtension.lowercased() == "vault" }
        guard !urls.isEmpty else {
            showError("No .vault files selected", detail: "Pick at least one file ending in .vault.")
            return nil
        }
        return urls
    }

    @MainActor
    private static func pickDestinationFolder() -> URL? {
        let panel = NSOpenPanel()
        panel.title = "Choose destination folder (e.g. USB drive)"
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.prompt = "Choose"
        panel.message = "Pick the folder or USB drive where the portable vault bundle should be written."
        guard panel.runModal() == .OK else { return nil }
        return panel.url
    }

    @MainActor
    private static func showResult(exportDir: URL, copied: [String], failures: [(String, String)]) {
        let alert = NSAlert()
        if failures.isEmpty {
            alert.messageText = "Portable vault exported"
            alert.informativeText = """
            \(copied.count) file(s) copied with the decryptor and instructions to:

            \(exportDir.path)

            On any computer, open README.txt inside that folder and follow the 3-step decryption instructions.
            """
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Reveal in Finder")
            alert.addButton(withTitle: "Done")
            if alert.runModal() == .alertFirstButtonReturn {
                NSWorkspace.shared.activateFileViewerSelecting([exportDir])
            }
        } else {
            let list = failures.map { "• \($0.0): \($0.1)" }.joined(separator: "\n")
            alert.messageText = "Export completed with \(failures.count) error(s)"
            alert.informativeText = """
            Succeeded: \(copied.count) file(s). Failed:

            \(list)

            Folder: \(exportDir.path)
            """
            alert.alertStyle = .warning
            alert.runModal()
        }
    }

    @MainActor
    private static func showError(_ title: String, detail: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = detail
        alert.alertStyle = .warning
        alert.runModal()
    }

    // MARK: - Content builders

    /// Build the README text. Kept deliberately free of any hints about
    /// vault passphrases — the security of the exported bundle depends on
    /// the adversary NOT finding anything useful if they get the drive
    /// without the passphrase.
    private static func buildReadme(copiedVaultFiles: [String]) -> String {
        let fileList = copiedVaultFiles.map { "    \($0)" }.joined(separator: "\n")
        return """
        AISecurity Portable Vault Bundle
        ================================

        This folder contains one or more encrypted files and a standalone
        tool that can decrypt them on any computer with Python 3.

        Files in this bundle:
        \(fileList)
            vault-decrypt.py     — the decryption tool
            requirements.txt     — Python dependency
            README.txt           — this file

        To decrypt a file
        -----------------

        1. Install Python 3 if you don't have it:
             macOS:   already installed
             Linux:   usually already installed; otherwise `sudo apt install python3 python3-pip`
             Windows: download from https://www.python.org/downloads/

        2. Install the one dependency (in a terminal, inside this folder):
             pip install -r requirements.txt
           or directly:
             pip install cryptography

        3. Decrypt a file:
             python3 vault-decrypt.py <file.vault>

           Example:
             python3 vault-decrypt.py secret.pdf.vault

           You'll be prompted for the passphrase you set when the file was
           encrypted in AISecurity. The decrypted file is written next to
           the .vault file with the .vault extension removed.

        Security notes
        --------------

        • The encrypted files cannot be decrypted without the passphrase.
          Losing this folder is not a security incident — losing the
          passphrase is.

        • Do NOT write your passphrase in this README or anywhere on the
          drive. Keep it in your head or in a separate secure location.

        • The decryption tool (vault-decrypt.py) is a plain Python script.
          You can read it yourself before running it.

        • This tool does not phone home, log anything, or make network
          connections. Everything happens locally on your machine.

        For questions or to verify the tool, see the AISecurity project.
        """
    }

    /// Filesystem-safe local timestamp, no colons.
    private static func timestampString() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f.string(from: Date())
    }
}
