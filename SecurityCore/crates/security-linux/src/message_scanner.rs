use rusqlite::Connection;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::thread;

use security_core::alert::{SecurityAlert, ThreatDetail};
use security_core::message_patterns;
use security_core::severity::SeverityLevel;
use security_core::threat_intent_parser::{self, Channel};

use crate::logger::SecurityLogger;
use crate::notifications;

/// Poll Signal Desktop SQLite database for new messages and scan them.
/// Signal stores messages in: ~/.config/Signal/sql/db.sqlite
pub fn start(
    db_path: &str,
    logger: Arc<SecurityLogger>,
    running: Arc<AtomicBool>,
    critical_only: bool,
) {
    let path = Path::new(db_path);
    if !path.exists() {
        logger.info(&format!(
            "📱 Signal Desktop database not found: {} — message scanning skipped",
            db_path
        ));
        return;
    }

    logger.info(&format!("📱 Message scanner started — monitoring {}", db_path));

    let mut last_timestamp: i64 = current_timestamp_ms() - 7 * 24 * 60 * 60 * 1000; // last 7 days
    let scan_interval = Duration::from_secs(60);

    while running.load(Ordering::Relaxed) {
        match scan_signal_db(path, last_timestamp, &logger, critical_only) {
            Ok(new_ts) => {
                if new_ts > last_timestamp {
                    last_timestamp = new_ts;
                }
            }
            Err(e) => {
                // Signal locks the DB when in use — silently retry
                if !e.contains("locked") && !e.contains("busy") {
                    logger.warn(&format!("📱 Signal DB error: {}", e));
                }
            }
        }

        for _ in 0..(scan_interval.as_millis() / 500) {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    logger.info("📱 Message scanner stopped");
}

fn scan_signal_db(
    db_path: &Path,
    since_timestamp: i64,
    logger: &SecurityLogger,
    critical_only: bool,
) -> Result<i64, String> {
    let conn = Connection::open_with_flags(
        db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;

    // Signal Desktop schema: messages table with body, sent_at, source, type
    // type = 'incoming' for received messages
    let mut stmt = conn
        .prepare(
            "SELECT body, sent_at, source, conversationId \
             FROM messages \
             WHERE type = 'incoming' \
             AND body IS NOT NULL AND body != '' \
             AND sent_at > ?1 \
             ORDER BY sent_at ASC \
             LIMIT 200",
        )
        .map_err(|e| e.to_string())?;

    let mut max_ts = since_timestamp;
    let mut threats_found = 0;
    let mut messages_scanned = 0;

    let rows = stmt
        .query_map([since_timestamp], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;

    for row in rows {
        let (body, sent_at, source, _conv_id) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };

        if sent_at > max_ts {
            max_ts = sent_at;
        }

        let text = body.trim();
        if text.is_empty() {
            continue;
        }

        messages_scanned += 1;
        let sender = source.unwrap_or_else(|| "Unknown".to_string());

        // Analyze with message patterns
        let raw_threats = message_patterns::analyze_message(text);
        let intent = threat_intent_parser::parse(text, Channel::Sms);

        // Filter: always-fire categories + intent threshold
        let threats: Vec<_> = raw_threats
            .iter()
            .filter(|t| {
                t.category == "malicious_url" || t.category == "crypto_scam" || intent.layers_fired >= 2
            })
            .collect();

        // Intent-only threat
        if intent.is_threat && threats.is_empty() {
            let sev = intent.severity.unwrap_or(SeverityLevel::Medium);
            let alert = SecurityAlert::new(
                "MESSAGE_THREAT_DETECTED",
                sev,
                &format!("📱 Suspicious message from {}: Intent: {}", sender, intent.label),
            );
            logger.alert(&alert);
            if notifications::should_notify(sev, critical_only) {
                notifications::notify(&alert);
            }
            threats_found += 1;
            continue;
        }

        if !threats.is_empty() {
            let top_sev = threats
                .iter()
                .map(|t| t.severity)
                .max()
                .unwrap_or(SeverityLevel::Medium);
            let final_sev = std::cmp::max(
                intent.severity.unwrap_or(SeverityLevel::Low),
                top_sev,
            );

            let preview = if text.len() > 100 {
                format!("{}...", &text[..100])
            } else {
                text.to_string()
            }
            .replace('\n', " ");

            let mut alert = SecurityAlert::new(
                "MESSAGE_THREAT_DETECTED",
                final_sev,
                &format!(
                    "📱 Suspicious message from {}: {}",
                    sender,
                    threats.iter().map(|t| t.label.as_str()).collect::<Vec<_>>().join(", ")
                ),
            );
            alert.sender = Some(sender.clone());
            alert.preview = Some(preview);
            alert.threats = Some(
                threats
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

    if messages_scanned > 0 {
        logger.info(&format!(
            "📱 Scanned {} new message(s), {} threat(s) found",
            messages_scanned, threats_found
        ));
    }

    Ok(max_ts)
}

fn current_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
