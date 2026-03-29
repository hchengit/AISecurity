# AISecurity — Cross-Platform Assessment & Implementation Plan

**Date:** 2026-03-28
**Status:** Phase 3 in progress (macOS FFI integration) — all 6 modules migrated to Rust FFI
**Last Updated:** 2026-03-28

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
| Remote repo (GitHub) | ⬜ Not started | — |

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
| install.sh updated with Rust build step | ⬜ Not started | `install.sh` |
| Performance benchmark (NSRegularExpression vs regex crate) | ⬜ Not started | — |

### Phase 4: Linux Daemon

| Component | Status | Location |
|-----------|--------|----------|
| Linux daemon crate | ⬜ Not started | `crates/security-linux/` |
| File watcher (inotify) | ⬜ Not started | `file_watcher_linux.rs` |
| Email scanner (Thunderbird mbox/maildir) | ⬜ Not started | `email_scanner_linux.rs` |
| Messages scanner (Signal Desktop SQLite) | ⬜ Not started | `message_scanner_linux.rs` |
| Clipboard monitor (arboard/xclip/wl-paste) | ⬜ Not started | `clipboard_linux.rs` |
| Desktop notifications (notify-rust/D-Bus) | ⬜ Not started | `notifications_linux.rs` |
| System tray (ksni) | ⬜ Not started | `tray.rs` |
| systemd user service | ⬜ Not started | `deploy/linux/security-core.service` |
| Linux install script | ⬜ Not started | `deploy/linux/install.sh` |
| Verification: Ubuntu 22.04+ / Fedora 38+ | ⬜ Not started | �� |

### Phase 5: ElizaOS-Inspired Features

| Component | Status | Location |
|-----------|--------|----------|
| AES-256-GCM encryption (config + whitelist + logs) | ⬜ Not started | `encryption.rs` |
| Sensitive key filtering (log/display redaction) | ⬜ Not started | `key_filter.rs` |
| WASM sandbox for custom detection rules | ⬜ Not started | `wasm_sandbox.rs` |
| rustls TLS transport (future remote logging) | ⬜ Not started | `tls_transport.rs` |
| Process lifecycle manager (cancellation tokens) | ⬜ Not started | `process_manager.rs` |

### Phase 6: Feature Parity & Polish

| Component | Status | Location |
|-----------|--------|----------|
| Shared JSON test suite (both platforms) | ⬜ Not started | `tests/integration/` |
| Linux TUI threat viewer (ratatui) | ⬜ Not started | `security-linux/src/tui.rs` |
| Documentation (README, PORTING, CUSTOM_RULES, CONFIG) | ⬜ Not started | — |
| Feature parity matrix verified | ⬜ Not started | See §6.3 below |

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
```

## Key Architectural Decisions

1. **Rust core = static library (.a)** — self-contained, no .dylib to ship
2. **C ABI via cbindgen** — most stable FFI for Swift interop
3. **Same config.toml both platforms** — one format, one parser, one doc set
4. **Pattern modules = pure functions, zero I/O** — trivially testable
5. **Incremental migration** — each Swift module switches independently
6. **MacSec = reference only** — not modified, used for Linux path/service mapping
