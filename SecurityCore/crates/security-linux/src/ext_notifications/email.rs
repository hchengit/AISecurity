//! Email notification channel — sends alerts via Gmail SMTP using lettre.

use super::config::EmailConfig;
use security_core::alert::SecurityAlert;
use security_core::severity::SeverityLevel;

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};

/// Send a security alert email.
pub fn send(alert: &SecurityAlert, config: &EmailConfig) -> Result<(), String> {
    let subject = format!(
        "{} AISecurity: {}",
        severity_emoji(alert.severity),
        sanitize_header(&alert.alert_type)
    );
    let body = build_plain_text(alert);

    send_mail(
        &config.user_email,
        &config.app_password,
        &subject,
        &body,
    )
}

/// Send a test email.
#[allow(dead_code)] // public API; not yet wired into a test-notification command
pub fn send_test(config: &EmailConfig) -> Result<(), String> {
    send_mail(
        &config.user_email,
        &config.app_password,
        "\u{1F6E1} AISecurity Test Notification",
        "AISecurity Test\n\nThis is a test from the Linux daemon.\nEmail is configured correctly!",
    )
}

fn send_mail(
    user_email: &str,
    app_password: &str,
    subject: &str,
    body: &str,
) -> Result<(), String> {
    let email = Message::builder()
        .from(
            format!("AISecurity <{}>", user_email)
                .parse()
                .map_err(|e| format!("From address: {}", e))?,
        )
        .to(user_email
            .parse()
            .map_err(|e| format!("To address: {}", e))?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body.to_string())
        .map_err(|e| format!("Build email: {}", e))?;

    let creds = Credentials::new(user_email.to_string(), app_password.to_string());

    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .map_err(|e| format!("SMTP relay: {}", e))?
        .credentials(creds)
        .build();

    mailer
        .send(&email)
        .map_err(|e| format!("SMTP send: {}", e))?;

    Ok(())
}

fn build_plain_text(alert: &SecurityAlert) -> String {
    let mut lines = vec![
        format!(
            "AISecurity Alert - {}",
            format!("{}", alert.severity).to_uppercase()
        ),
        "\u{2501}".repeat(40),
        alert.alert_type.clone(),
        String::new(),
        alert.message.clone(),
    ];

    if let Some(ref file_path) = alert.file_path {
        lines.push(String::new());
        lines.push(format!("File: {}", file_path));
    }

    lines.push(String::new());
    lines.push("\u{2501}".repeat(40));
    lines.push(format!(
        "Sent at {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

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

/// Strip CR/LF from header values to prevent email header injection.
fn sanitize_header(value: &str) -> String {
    value.replace('\r', "").replace('\n', " ")
}
