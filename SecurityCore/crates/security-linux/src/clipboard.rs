use arboard::Clipboard;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::thread;

use security_core::alert::SecurityAlert;
use security_core::prompt_injection;
use security_core::sensitive_data;
use security_core::severity::SeverityLevel;

use crate::logger::SecurityLogger;
use crate::notifications;

/// Monitor clipboard for sensitive data and prompt injection attempts.
/// Polls every 2 seconds (matching macOS clipboardMonitorIntervalMs).
pub fn start(
    logger: Arc<SecurityLogger>,
    running: Arc<AtomicBool>,
    critical_only: bool,
) {
    let mut clipboard = match Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            logger.warn(&format!("📋 Clipboard init failed: {} — clipboard monitoring skipped", e));
            return;
        }
    };

    logger.info("📋 Clipboard monitor started");

    let mut last_content = String::new();
    let poll_interval = Duration::from_secs(2);

    while running.load(Ordering::Relaxed) {
        if let Ok(text) = clipboard.get_text() {
            if !text.is_empty() && text != last_content {
                last_content = text.clone();
                check_clipboard(&text, &logger, critical_only);
            }
        }

        thread::sleep(poll_interval);
    }

    logger.info("📋 Clipboard monitor stopped");
}

fn check_clipboard(text: &str, logger: &SecurityLogger, critical_only: bool) {
    // Check for sensitive data
    let findings = sensitive_data::scan_text(text, "clipboard");
    if !findings.is_empty() {
        let max_sev = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(SeverityLevel::Low);

        let categories: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();
        let unique_cats: Vec<&str> = {
            let mut v = categories;
            v.sort();
            v.dedup();
            v
        };

        let alert = SecurityAlert::new(
            "CLIPBOARD_SENSITIVE_DATA",
            max_sev,
            &format!(
                "📋 Sensitive data detected in clipboard: {} finding(s) [{}]",
                findings.len(),
                unique_cats.join(", ")
            ),
        );
        logger.alert(&alert);
        if notifications::should_notify(max_sev, critical_only) {
            notifications::notify(&alert);
        }
    }

    // Check for prompt injection
    let validation = prompt_injection::validate(text, "clipboard");
    if !validation.safe {
        let sev = validation.severity.unwrap_or(SeverityLevel::Medium);
        let alert = SecurityAlert::new(
            "CLIPBOARD_PROMPT_INJECTION",
            sev,
            &format!(
                "📋 Prompt injection detected in clipboard: {}",
                validation.reason.unwrap_or_default()
            ),
        );
        logger.alert(&alert);
        if notifications::should_notify(sev, critical_only) {
            notifications::notify(&alert);
        }
    }
}
