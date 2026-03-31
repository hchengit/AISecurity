use inotify::{EventMask, Inotify, WatchMask};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{fs, thread};

use security_core::alert::SecurityAlert;
use security_core::file_sanitizer;
use security_core::sensitive_data;
use security_core::severity::SeverityLevel;

use crate::ext_notifications::NotificationManager;
use crate::logger::SecurityLogger;
use crate::notifications;

const MAX_SCAN_SIZE: u64 = 10 * 1024 * 1024; // 10 MB

/// Watch directories for new/modified files via inotify and scan them.
pub fn start(
    dirs: &[String],
    logger: Arc<SecurityLogger>,
    running: Arc<AtomicBool>,
    critical_only: bool,
    ext_notif: Option<Arc<NotificationManager>>,
) {
    let mut inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            logger.warn(&format!("Failed to init inotify: {}", e));
            return;
        }
    };

    let mut watched = Vec::new();
    for dir in dirs {
        let path = Path::new(dir);
        if !path.exists() {
            logger.info(&format!("Skipping non-existent watch dir: {}", dir));
            continue;
        }
        match inotify.watches().add(path, WatchMask::CREATE | WatchMask::CLOSE_WRITE | WatchMask::MOVED_TO) {
            Ok(wd) => {
                watched.push((wd, dir.clone()));
                logger.info(&format!("📁 Watching: {}", dir));
            }
            Err(e) => {
                logger.warn(&format!("Failed to watch {}: {}", dir, e));
            }
        }
    }

    if watched.is_empty() {
        logger.warn("No directories being watched — file watcher idle");
        return;
    }

    let mut hash_cache: HashMap<PathBuf, String> = HashMap::new();
    let mut buf = [0u8; 4096];

    logger.info(&format!(
        "📁 File watcher started — monitoring {} directories",
        watched.len()
    ));

    while running.load(Ordering::Relaxed) {
        let events = match inotify.read_events(&mut buf) {
            Ok(evts) => evts.collect::<Vec<_>>(),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(500));
                continue;
            }
            Err(e) => {
                logger.warn(&format!("inotify read error: {}", e));
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };

        for event in events {
            if event.mask.contains(EventMask::ISDIR) {
                continue;
            }
            let name = match event.name {
                Some(n) => n,
                None => continue,
            };

            // Find which directory this event belongs to
            let dir = match watched.iter().find(|(wd, _)| *wd == event.wd) {
                Some((_, d)) => d,
                None => continue,
            };

            let file_path = Path::new(dir).join(name);
            scan_file(&file_path, &logger, &mut hash_cache, critical_only, &ext_notif);
        }
    }

    logger.info("📁 File watcher stopped");
}

fn scan_file(
    path: &Path,
    logger: &SecurityLogger,
    cache: &mut HashMap<PathBuf, String>,
    critical_only: bool,
    ext_notif: &Option<Arc<NotificationManager>>,
) {
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };

    if !metadata.is_file() || metadata.len() > MAX_SCAN_SIZE {
        return;
    }

    let content = match fs::read(path) {
        Ok(c) => c,
        Err(_) => return,
    };

    // SHA256 cache check
    let hash = format!("{:x}", Sha256::digest(&content));
    let path_buf = path.to_path_buf();
    if cache.get(&path_buf).map(|h| h == &hash).unwrap_or(false) {
        return; // already scanned this version
    }
    cache.insert(path_buf, hash);

    let text = match String::from_utf8(content) {
        Ok(t) => t,
        Err(_) => return, // binary file
    };

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // Scan for malicious patterns
    let file_result = file_sanitizer::scan(&text, filename);

    if !file_result.safe {
        for threat in &file_result.threats {
            let alert = SecurityAlert::new(
                "EXTERNAL_FILE_THREAT",
                threat.severity,
                &format!("🚨 Malicious content in: {} — {}", filename, threat.label),
            );
            logger.alert(&alert);
            if notifications::should_notify(threat.severity, critical_only) {
                notifications::notify(&alert);
            }
            if let Some(ref nm) = ext_notif { nm.send(&alert); }
        }
    }

    for warning in &file_result.warnings {
        logger.warn(&format!("\u{26A0}\u{FE0F} Suspicious file: {} \u{2014} {}", filename, warning.detail));
    }

    // Scan for sensitive data
    let findings = sensitive_data::scan_text(&text, &format!("file:{}", filename));
    if !findings.is_empty() {
        let max_sev = findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(SeverityLevel::Low);

        let alert = SecurityAlert::new(
            "SENSITIVE_DATA_IN_FILE",
            max_sev,
            &format!(
                "\u{1F511} {} sensitive data finding(s) in: {}",
                findings.len(),
                filename
            ),
        );
        logger.alert(&alert);
        if notifications::should_notify(max_sev, critical_only) {
            notifications::notify(&alert);
        }
        if let Some(ref nm) = ext_notif { nm.send(&alert); }
    }
}
