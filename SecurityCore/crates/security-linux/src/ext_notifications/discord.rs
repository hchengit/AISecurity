//! Discord webhook integration — sends rich embeds for security alerts.

use super::config::DiscordConfig;
use security_core::alert::SecurityAlert;
use security_core::severity::SeverityLevel;

/// Send a security alert to Discord via webhook.
pub fn send(alert: &SecurityAlert, config: &DiscordConfig) -> Result<(), String> {
    validate_webhook_url(&config.webhook_url)?;

    let embed = build_embed(alert);
    let body = serde_json::json!({
        "username": "AISecurity",
        "embeds": [embed]
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&config.webhook_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("HTTP: {}", e))?;

    let status = resp.status().as_u16();
    if status == 204 || status == 200 {
        Ok(())
    } else {
        Err(format!("HTTP {}", status))
    }
}

/// Send a test message.
#[allow(dead_code)] // public API; not yet wired into a test-notification command
pub fn send_test(config: &DiscordConfig) -> Result<(), String> {
    validate_webhook_url(&config.webhook_url)?;

    let embed = serde_json::json!({
        "title": "\u{1F6E1} AISecurity Test",
        "description": "This is a test from the Linux daemon.\nDiscord is configured correctly!",
        "color": 3066993,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    let body = serde_json::json!({
        "username": "AISecurity",
        "embeds": [embed]
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&config.webhook_url)
        .json(&body)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .map_err(|e| format!("HTTP: {}", e))?;

    let status = resp.status().as_u16();
    if status == 204 || status == 200 {
        Ok(())
    } else {
        Err(format!("HTTP {}", status))
    }
}

fn build_embed(alert: &SecurityAlert) -> serde_json::Value {
    let mut fields = Vec::new();

    if let Some(ref file_path) = alert.file_path {
        let name = file_path.rsplit('/').next().unwrap_or(file_path);
        fields.push(serde_json::json!({
            "name": "\u{1F4C1} File",
            "value": format!("`{}`", name),
            "inline": true
        }));
    }

    fields.push(serde_json::json!({
        "name": "\u{1F534} Severity",
        "value": format!("{}", alert.severity).to_uppercase(),
        "inline": true
    }));

    let mut embed = serde_json::json!({
        "title": format!("{} {}", severity_emoji(alert.severity), alert.alert_type),
        "description": alert.message,
        "color": severity_color(alert.severity),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "footer": { "text": format!("AISecurity \u{2022} {}", alert.alert_type) }
    });

    if !fields.is_empty() {
        embed["fields"] = serde_json::Value::Array(fields);
    }

    embed
}

fn severity_emoji(sev: SeverityLevel) -> &'static str {
    match sev {
        SeverityLevel::Critical => "\u{1F6A8}",
        SeverityLevel::High => "\u{26A0}\u{FE0F}",
        SeverityLevel::Medium => "\u{2139}\u{FE0F}",
        SeverityLevel::Low => "\u{2705}",
    }
}

fn severity_color(sev: SeverityLevel) -> u32 {
    match sev {
        SeverityLevel::Critical => 0xFF0000,
        SeverityLevel::High => 0xFFA500,
        SeverityLevel::Medium => 0xFFFF00,
        SeverityLevel::Low => 0x00FF00,
    }
}

/// Validate webhook URL — HTTPS only, no localhost/internal.
fn validate_webhook_url(url: &str) -> Result<(), String> {
    if !url.starts_with("https://") {
        return Err("Only HTTPS webhook URLs are allowed".into());
    }
    let host_part = url
        .strip_prefix("https://")
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");
    let host = host_part.split(':').next().unwrap_or("");
    if host == "localhost"
        || host.starts_with("127.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host == "0.0.0.0"
        || host == "::1"
    {
        return Err("Local/internal webhook URLs are not allowed".into());
    }
    Ok(())
}
