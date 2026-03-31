//! Telegram Bot API integration — sends formatted alerts via sendMessage.

use super::config::TelegramConfig;
use security_core::alert::SecurityAlert;
use security_core::severity::SeverityLevel;

/// Send a security alert to Telegram.
pub fn send(alert: &SecurityAlert, config: &TelegramConfig) -> Result<(), String> {
    let text = format_message(alert);
    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        urlencoded(&config.bot_token)
    );

    let body = serde_json::json!({
        "chat_id": config.chat_id,
        "text": text,
        "parse_mode": "MarkdownV2"
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("HTTP: {}", e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

/// Send a test message.
pub fn send_test(config: &TelegramConfig) -> Result<(), String> {
    let text = esc("\u{1F6E1} AISecurity Test\n\nThis is a test from the Linux daemon.\nTelegram is configured correctly!");
    let url = format!(
        "https://api.telegram.org/bot{}/sendMessage",
        urlencoded(&config.bot_token)
    );

    let body = serde_json::json!({
        "chat_id": config.chat_id,
        "text": text,
        "parse_mode": "MarkdownV2"
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("HTTP: {}", e))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("HTTP {}", resp.status()))
    }
}

fn format_message(alert: &SecurityAlert) -> String {
    let mut lines = Vec::new();

    lines.push("\u{1F6E1} *AISecurity Alert*".to_string());
    lines.push(format!(
        "{} *{}*",
        severity_emoji(alert.severity),
        esc(&format!("{}", alert.severity).to_uppercase())
    ));
    lines.push(String::new());
    lines.push("\u{2501}".repeat(18));
    lines.push(String::new());
    lines.push("\u{1F4CB} *What Happened:*".to_string());
    lines.push(esc(&alert.message));

    if let Some(ref file_path) = alert.file_path {
        lines.push(String::new());
        lines.push(format!("\u{1F4C1} *File:* `{}`", esc(file_path)));
    }

    let ts = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    lines.push(format!("\u{23F0} *Time:* {}", esc(&ts)));

    lines.join("\n")
}

fn severity_emoji(sev: SeverityLevel) -> &'static str {
    match sev {
        SeverityLevel::Critical => "\u{1F6A8}",
        SeverityLevel::High => "\u{26A0}\u{FE0F}",
        SeverityLevel::Medium => "\u{2139}\u{FE0F}",
        SeverityLevel::Low => "\u{2705}",
    }
}

/// Escape MarkdownV2 special characters.
fn esc(text: &str) -> String {
    let specials = r#"_*[]()~`>#+-=|{}.!\"#;
    let mut result = String::with_capacity(text.len());
    for ch in text.chars() {
        if specials.contains(ch) {
            result.push('\\');
        }
        result.push(ch);
    }
    result
}

/// Percent-encode for URL path safety.
fn urlencoded(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}
