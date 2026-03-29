mod clipboard;
mod email_scanner;
mod file_watcher;
mod logger;
mod message_scanner;
mod notifications;
mod tui;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use security_core::config::SecurityConfig;

fn main() {
    // Check for --tui flag before anything else
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tui") {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let config_path = format!("{}/.mac-security/config.toml", home);
        let config = SecurityConfig::load_or_default(&config_path);
        let alerts_path = format!("{}/alerts.log", config.paths.log_dir);
        if let Err(e) = tui::run(&alerts_path) {
            eprintln!("TUI error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    // Load config: try ~/.mac-security/config.toml, fall back to defaults + env overrides
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let config_path = format!("{}/.mac-security/config.toml", home);
    let config = SecurityConfig::load_or_default(&config_path);

    let sec_logger = Arc::new(logger::SecurityLogger::new(&config.paths.log_dir));

    eprintln!("╔══════════════════════════════════════════════════╗");
    eprintln!("║       SecurityCore — Linux Security Daemon       ║");
    eprintln!("╠══════════════════════════════════════════════════╣");
    eprintln!("║  Mode: {:<41} ║", config.general.mode);
    eprintln!("║  Logs: {:<41} ║", config.paths.log_dir);
    eprintln!("╚══════════════════════════════════════════════════╝");

    sec_logger.info(&format!(
        "SecurityCore Linux daemon starting — mode={}",
        config.general.mode
    ));

    // Graceful shutdown via Ctrl+C / SIGTERM
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            eprintln!("\n🛑 Shutdown signal received — stopping all monitors...");
            r.store(false, Ordering::Relaxed);
        })
        .expect("Failed to set Ctrl+C handler");
    }

    let critical_only = config.notifications.critical_only;
    let mut handles = Vec::new();

    // 1. File Watcher (inotify)
    if config.file_watcher.enabled {
        let dirs = config.file_watcher.monitored_directories.clone();
        let log = sec_logger.clone();
        let run = running.clone();
        handles.push(thread::Builder::new()
            .name("file-watcher".into())
            .spawn(move || file_watcher::start(&dirs, log, run, critical_only))
            .expect("Failed to spawn file watcher"));
    }

    // 2. Email Scanner (Thunderbird)
    if config.email_scanner.enabled {
        let mail_dir = config.paths.mail_dir.clone();
        let log = sec_logger.clone();
        let run = running.clone();
        handles.push(thread::Builder::new()
            .name("email-scanner".into())
            .spawn(move || email_scanner::start(&mail_dir, log, run, critical_only))
            .expect("Failed to spawn email scanner"));
    }

    // 3. Messages Scanner (Signal Desktop)
    if config.messages_scanner.enabled {
        let db_path = config.paths.messages_db.clone();
        let log = sec_logger.clone();
        let run = running.clone();
        handles.push(thread::Builder::new()
            .name("message-scanner".into())
            .spawn(move || message_scanner::start(&db_path, log, run, critical_only))
            .expect("Failed to spawn message scanner"));
    }

    // 4. Clipboard Monitor
    {
        let log = sec_logger.clone();
        let run = running.clone();
        handles.push(thread::Builder::new()
            .name("clipboard-monitor".into())
            .spawn(move || clipboard::start(log, run, critical_only))
            .expect("Failed to spawn clipboard monitor"));
    }

    sec_logger.info("All monitors started — daemon running");

    // Wait for all threads
    for h in handles {
        let _ = h.join();
    }

    sec_logger.info("SecurityCore Linux daemon stopped cleanly");
    eprintln!("✅ SecurityCore stopped.");
}
