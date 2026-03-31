mod auth;
mod clipboard;
mod email_scanner;
mod ext_notifications;
mod file_watcher;
mod logger;
mod message_scanner;
mod notifications;
mod tui;
mod tui_file_browser;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use security_core::config::SecurityConfig;

fn main() {
    // Load config early — needed by all modes
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let config_path = format!("{}/.mac-security/config.toml", home);
    let config = SecurityConfig::load_or_default(&config_path);

    // Check for --tui flag
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--tui") {
        let alerts_path = format!("{}/alerts.log", config.paths.log_dir);
        let security_dir = config.paths.security_dir.clone();
        if let Err(e) = tui::run(&alerts_path, &security_dir) {
            eprintln!("TUI error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let sec_logger = Arc::new(logger::SecurityLogger::new(&config.paths.log_dir));

    // Initialize external notification manager
    let notif_manager = Arc::new(ext_notifications::NotificationManager::new(
        &config.paths.security_dir,
    ));

    eprintln!("\u{2554}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2557}");
    eprintln!("\u{2551}       SecurityCore \u{2014} Linux Security Daemon       \u{2551}");
    eprintln!("\u{2560}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2563}");
    eprintln!("\u{2551}  Mode: {:<41} \u{2551}", config.general.mode);
    eprintln!("\u{2551}  Logs: {:<41} \u{2551}", config.paths.log_dir);
    eprintln!("\u{255A}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{255D}");

    sec_logger.info(&format!(
        "SecurityCore Linux daemon starting \u{2014} mode={}",
        config.general.mode
    ));

    // Graceful shutdown via Ctrl+C / SIGTERM
    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            eprintln!("\n\u{1F6D1} Shutdown signal received \u{2014} stopping all monitors...");
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
        let nm = notif_manager.clone();
        handles.push(
            thread::Builder::new()
                .name("file-watcher".into())
                .spawn(move || file_watcher::start(&dirs, log, run, critical_only, Some(nm)))
                .expect("Failed to spawn file watcher"),
        );
    }

    // 2. Email Scanner (Thunderbird)
    if config.email_scanner.enabled {
        let mail_dir = config.paths.mail_dir.clone();
        let log = sec_logger.clone();
        let run = running.clone();
        handles.push(
            thread::Builder::new()
                .name("email-scanner".into())
                .spawn(move || email_scanner::start(&mail_dir, log, run, critical_only))
                .expect("Failed to spawn email scanner"),
        );
    }

    // 3. Messages Scanner (Signal Desktop)
    if config.messages_scanner.enabled {
        let db_path = config.paths.messages_db.clone();
        let log = sec_logger.clone();
        let run = running.clone();
        handles.push(
            thread::Builder::new()
                .name("message-scanner".into())
                .spawn(move || message_scanner::start(&db_path, log, run, critical_only))
                .expect("Failed to spawn message scanner"),
        );
    }

    // 4. Clipboard Monitor
    {
        let log = sec_logger.clone();
        let run = running.clone();
        handles.push(
            thread::Builder::new()
                .name("clipboard-monitor".into())
                .spawn(move || clipboard::start(log, run, critical_only))
                .expect("Failed to spawn clipboard monitor"),
        );
    }

    sec_logger.info("All monitors started \u{2014} daemon running");

    // Wait for all threads
    for h in handles {
        let _ = h.join();
    }

    sec_logger.info("SecurityCore Linux daemon stopped cleanly");
    eprintln!("\u{2705} SecurityCore stopped.");
}
