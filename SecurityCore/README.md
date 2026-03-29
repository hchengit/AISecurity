# SecurityCore — Cross-Platform Security Detection Engine

Rust-based security detection core powering AISecurity on macOS and Linux. All pattern matching, scoring, and analysis runs through this shared library.

## Architecture

```
SecurityCore/
  crates/
    security-core/          # Platform-agnostic detection library (rlib)
      src/
        severity.rs         # SeverityLevel enum (CRITICAL/HIGH/MEDIUM/LOW)
        alert.rs            # SecurityAlert, ThreatDetail, FindingDetail
        threat_intent_parser.rs  # 7-layer scoring engine
        sensitive_data.rs   # 40+ regex patterns (financial, PII, crypto, API keys)
        prompt_injection.rs # 8 categories + sanitization + heuristics
        file_sanitizer.rs   # 9 malware pattern groups + suspicious filenames
        email_patterns.rs   # 9 email threat groups + trusted domains
        message_patterns.rs # 9 SMS/iMessage threat groups + phishing domains
        sender_whitelist.rs # Policy engine + freemail blocklist
        config.rs           # TOML config parser + MACSEC_* env overrides
        path_resolver.rs    # Platform-aware defaults (macOS vs Linux)
        encryption.rs       # AES-256-GCM + SHA-256 key derivation
        key_filter.rs       # Sensitive key/value redaction
        wasm_sandbox.rs     # wasmtime plugin loader (memory-isolated)
        tls_transport.rs    # rustls TLS for remote log shipping
        process_manager.rs  # CancellationToken + worker lifecycle
    security-core-ffi/      # C ABI FFI for Swift interop (staticlib/cdylib)
    security-linux/         # Linux daemon binary
```

## Quick Start (Linux)

```bash
# Build
cd SecurityCore
cargo build --release -p security-linux

# Run daemon
./target/release/security-linux

# View threats (TUI)
./target/release/security-linux --tui

# Install as systemd service
../deploy/linux/install.sh
```

## Quick Start (macOS)

```bash
# Build Rust core
cd SecurityCore
./build-rust.sh

# Build Swift app
swift build
swift run AISecurity
```

## Configuration

Config file: `~/.mac-security/config.toml`

```toml
[general]
mode = "PRODUCTION"  # PRODUCTION | TESTING | DEVELOPMENT

[paths]
security_dir = "~/.mac-security"
log_dir = "~/.mac-security/logs"
quarantine_dir = "~/.mac-security/quarantine"
# Linux:
mail_dir = "~/.thunderbird"
messages_db = "~/.config/Signal/sql/db.sqlite"
# macOS:
# mail_dir = "~/Library/Mail"
# messages_db = "~/Library/Messages/chat.db"

[file_watcher]
enabled = true
monitored_directories = ["~/Downloads", "~/Desktop", "~/Documents"]

[notifications]
enabled = true
critical_only = true
```

Environment variable overrides (highest priority):

| Variable | Overrides |
|----------|-----------|
| `MACSEC_MODE` | `[general].mode` |
| `MACSEC_SECURITY_DIR` | `[paths].security_dir` |
| `MACSEC_MAIL_DIR` | `[paths].mail_dir` |
| `MACSEC_MESSAGES_DB` | `[paths].messages_db` |
| `MACSEC_LOG_DIR` | `[paths].log_dir` |
| `MACSEC_QUARANTINE_DIR` | `[paths].quarantine_dir` |
| `MACSEC_SCAN_DIRS` | `[file_watcher].monitored_directories` (colon-separated) |

## Encryption

Set `SECURITYCORE_PASSPHRASE` for at-rest encryption of whitelist and config secrets. In PRODUCTION mode, the default passphrase is rejected.

## Custom WASM Rules

Place `.wasm` plugins in `~/.mac-security/rules/`. Each plugin exports:

- `name() -> (ptr, len)` — plugin name
- `analyze(text_ptr, text_len) -> (ptr, len)` — JSON result
- `alloc(size) -> ptr` — memory allocation

Plugins run in a sandboxed wasmtime environment with no filesystem or network access.

## Tests

```bash
# Unit tests (122 tests)
cargo test -p security-core

# Cross-validation integration tests (shared JSON test suite)
cargo test --test cross_validation

# Full workspace
cargo test --workspace
```

## Detection Capabilities

| Module | Patterns | Severity |
|--------|----------|----------|
| Intent Parser | 7-layer scoring (entity, directed, authority, action, urgency, fear) | Adaptive |
| Sensitive Data | 40+ (credit cards, SSN, crypto keys, API keys, PEM, env vars) | CRITICAL-HIGH |
| Prompt Injection | 8 categories (system prompt, role hijack, jailbreak, delimiter) | CRITICAL-MEDIUM |
| File Sanitizer | 9 groups (reverse shell, fork bomb, RCE, exfiltration, mining) | CRITICAL-HIGH |
| Email Threats | 9 groups (phishing, social engineering, IRS, crypto scam, malware) | CRITICAL-MEDIUM |
| Message Threats | 9 groups (bank smishing, Apple, delivery, IRS, OTP theft, prize) | CRITICAL-MEDIUM |
