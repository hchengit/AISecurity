use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, thread};
use walkdir::WalkDir;

use security_core::alert::{SecurityAlert, ThreatDetail};
use security_core::email_patterns;
use security_core::severity::SeverityLevel;
use security_core::threat_intent_parser::{self, Channel};

use crate::logger::SecurityLogger;
use crate::notifications;

/// Scan Thunderbird maildir/mbox for new emails.
/// Thunderbird stores mail in: ~/.thunderbird/<profile>/ImapMail/<server>/
/// Each folder is a file (mbox) + .msf index. New mail in "Inbox", "INBOX", etc.
pub fn start(
    thunderbird_dir: &str,
    logger: Arc<SecurityLogger>,
    running: Arc<AtomicBool>,
    critical_only: bool,
) {
    let tb_path = Path::new(thunderbird_dir);
    if !tb_path.exists() {
        logger.info(&format!(
            "📧 Thunderbird directory not found: {} — email scanning skipped",
            thunderbird_dir
        ));
        return;
    }

    logger.info(&format!("📧 Email scanner started — monitoring {}", thunderbird_dir));

    let mut scanned_files: HashMap<PathBuf, u64> = HashMap::new(); // path → size at last scan
    let scan_interval = Duration::from_secs(60);

    while running.load(Ordering::Relaxed) {
        scan_thunderbird(tb_path, &logger, &mut scanned_files, critical_only);
        // Sleep in small increments so we can check the running flag
        for _ in 0..(scan_interval.as_millis() / 500) {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    logger.info("📧 Email scanner stopped");
}

fn scan_thunderbird(
    tb_path: &Path,
    logger: &SecurityLogger,
    scanned: &mut HashMap<PathBuf, u64>,
    critical_only: bool,
) {
    // Find mbox files (Inbox, Sent, etc.) — Thunderbird mbox files have no extension
    // and sit alongside .msf index files
    let mail_files = find_mail_files(tb_path);

    for mail_path in mail_files {
        let metadata = match fs::metadata(&mail_path) {
            Ok(m) => m,
            Err(_) => continue,
        };

        let size = metadata.len();
        let prev_size = scanned.get(&mail_path).copied().unwrap_or(0);

        if size <= prev_size {
            continue; // no new data
        }

        // Read only the new portion
        let content = match fs::read(&mail_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // For the first scan, only look at the last 64KB to avoid scanning entire history
        let start_offset = if prev_size == 0 {
            content.len().saturating_sub(65536)
        } else {
            prev_size as usize
        };

        if start_offset >= content.len() {
            scanned.insert(mail_path, size);
            continue;
        }

        let new_bytes = &content[start_offset..];
        let text = String::from_utf8_lossy(new_bytes);

        // Split into individual messages by "From " line (mbox format)
        let messages = split_mbox(&text);

        let mut threats_found = 0;
        for msg in &messages {
            let parsed = parse_email_text(msg);
            let full_text = format!(
                "{}\n{}\n{}",
                parsed.from, parsed.subject, parsed.body
            );

            let threats = email_patterns::analyze_email(&full_text);
            let intent = threat_intent_parser::parse(&full_text, Channel::Email);

            let is_trusted = parsed
                .from_domain
                .as_ref()
                .map(|d| email_patterns::is_trusted_domain(d))
                .unwrap_or(false);

            let layer_threshold: u8 = if is_trusted { 5 } else { 3 };

            // Filter: bypass categories always fire, others need intent layers
            let confirmed: Vec<_> = threats
                .iter()
                .filter(|t| {
                    email_patterns::is_bypass_category(&t.category)
                        || intent.layers_fired >= layer_threshold
                })
                .collect();

            // If intent alone is threat and no patterns matched
            if intent.is_threat && confirmed.is_empty() && intent.layers_fired >= layer_threshold {
                let alert = SecurityAlert::new(
                    "EMAIL_THREAT_DETECTED",
                    intent.severity.unwrap_or(SeverityLevel::Medium),
                    &format!(
                        "📧 {} — Intent: {} [{}]",
                        parsed.from, intent.label, intent.confidence
                    ),
                );
                logger.alert(&alert);
                if notifications::should_notify(
                    intent.severity.unwrap_or(SeverityLevel::Medium),
                    critical_only,
                ) {
                    notifications::notify(&alert);
                }
                threats_found += 1;
                continue;
            }

            if !confirmed.is_empty() {
                let max_sev = confirmed
                    .iter()
                    .map(|t| t.severity)
                    .max()
                    .unwrap_or(SeverityLevel::Medium);
                let final_sev = std::cmp::max(
                    intent.severity.unwrap_or(SeverityLevel::Low),
                    max_sev,
                );

                let labels: Vec<&str> = confirmed.iter().map(|t| t.label.as_str()).collect();

                let mut alert = SecurityAlert::new(
                    "EMAIL_THREAT_DETECTED",
                    final_sev,
                    &format!(
                        "📧 {} — {} [{}]",
                        parsed.from,
                        labels.join(", "),
                        intent.confidence
                    ),
                );
                alert.from = Some(parsed.from.clone());
                alert.subject = Some(parsed.subject.clone());
                alert.threats = Some(
                    confirmed
                        .iter()
                        .map(|t| ThreatDetail {
                            label: t.label.clone(),
                            category: t.category.clone(),
                            severity: t.severity,
                        })
                        .collect(),
                );

                logger.alert(&alert);
                if notifications::should_notify(final_sev, critical_only) {
                    notifications::notify(&alert);
                }
                threats_found += 1;
            }
        }

        if threats_found > 0 {
            logger.info(&format!(
                "📧 Scanned {} new message(s) in {}, {} threat(s) found",
                messages.len(),
                mail_path.display(),
                threats_found
            ));
        }

        scanned.insert(mail_path, size);
    }
}

fn find_mail_files(tb_path: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in WalkDir::new(tb_path)
        .max_depth(6)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // Thunderbird mbox files: no extension, alongside .msf files
        // Common names: Inbox, Sent, Drafts, Trash, INBOX, etc.
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        if ext.is_empty() && !name.starts_with('.') {
            // Check if there's a corresponding .msf file (confirms it's mbox)
            let msf = path.with_extension("msf");
            if msf.exists() {
                files.push(path.to_path_buf());
            }
        }
    }
    files
}

struct ParsedEmail {
    from: String,
    subject: String,
    body: String,
    from_domain: Option<String>,
}

fn parse_email_text(raw: &str) -> ParsedEmail {
    // Try mailparse first, fall back to simple header extraction
    match mailparse::parse_mail(raw.as_bytes()) {
        Ok(parsed) => {
            let from = parsed
                .headers
                .iter()
                .find(|h| h.get_key().eq_ignore_ascii_case("from"))
                .map(|h| h.get_value())
                .unwrap_or_default();
            let subject = parsed
                .headers
                .iter()
                .find(|h| h.get_key().eq_ignore_ascii_case("subject"))
                .map(|h| h.get_value())
                .unwrap_or_default();
            let body = parsed.get_body().unwrap_or_default();
            let from_domain = extract_domain(&from);

            ParsedEmail {
                from,
                subject,
                body,
                from_domain,
            }
        }
        Err(_) => simple_parse(raw),
    }
}

fn simple_parse(raw: &str) -> ParsedEmail {
    let mut from = String::new();
    let mut subject = String::new();
    let mut in_headers = true;
    let mut body = String::new();

    for line in raw.lines() {
        if in_headers {
            if line.is_empty() {
                in_headers = false;
                continue;
            }
            let lower = line.to_lowercase();
            if lower.starts_with("from:") {
                from = line[5..].trim().to_string();
            } else if lower.starts_with("subject:") {
                subject = line[8..].trim().to_string();
            }
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }

    let from_domain = extract_domain(&from);
    ParsedEmail {
        from,
        subject,
        body,
        from_domain,
    }
}

fn split_mbox(text: &str) -> Vec<String> {
    let mut messages = Vec::new();
    let mut current = String::new();

    for line in text.lines() {
        if line.starts_with("From ") && !current.is_empty() {
            messages.push(std::mem::take(&mut current));
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.trim().is_empty() {
        messages.push(current);
    }

    // Limit to most recent 50 messages per scan
    if messages.len() > 50 {
        messages.split_off(messages.len() - 50)
    } else {
        messages
    }
}

fn extract_domain(from: &str) -> Option<String> {
    // Extract domain from "Name <user@domain.com>" or "user@domain.com"
    let s = from.to_lowercase();
    if let Some(at) = s.rfind('@') {
        let rest = &s[at + 1..];
        let domain = rest
            .trim_end_matches('>')
            .trim()
            .to_string();
        if !domain.is_empty() {
            return Some(domain);
        }
    }
    None
}
