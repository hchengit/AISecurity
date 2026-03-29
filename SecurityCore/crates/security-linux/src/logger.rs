use security_core::alert::SecurityAlert;
use security_core::severity::SeverityLevel;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// JSON structured logger — identical output format to macOS SecurityLogger.
pub struct SecurityLogger {
    log_dir: PathBuf,
    alerts_file: Mutex<Option<fs::File>>,
}

impl SecurityLogger {
    pub fn new(log_dir: &str) -> Self {
        let path = PathBuf::from(log_dir);
        let _ = fs::create_dir_all(&path);

        let alerts_path = path.join("alerts.log");
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&alerts_path)
            .ok();

        Self {
            log_dir: path,
            alerts_file: Mutex::new(file),
        }
    }

    pub fn alert(&self, alert: &SecurityAlert) {
        let json = match serde_json::to_string(alert) {
            Ok(j) => j,
            Err(_) => return,
        };

        // Write to alerts.log
        if let Ok(mut guard) = self.alerts_file.lock() {
            if let Some(ref mut f) = *guard {
                let _ = writeln!(f, "{}", json);
                let _ = f.flush();
            }
        }

        // Also print to stderr for systemd journal capture
        let icon = match alert.severity {
            SeverityLevel::Critical => "🚨",
            SeverityLevel::High => "⚠️",
            SeverityLevel::Medium => "⚡",
            SeverityLevel::Low => "ℹ️",
        };
        eprintln!("{} [{}] {}", icon, alert.severity, alert.message);
    }

    pub fn info(&self, msg: &str) {
        log::info!("{}", msg);
        self.write_general(msg, "INFO");
    }

    pub fn warn(&self, msg: &str) {
        log::warn!("{}", msg);
        self.write_general(msg, "WARN");
    }

    fn write_general(&self, msg: &str, level: &str) {
        let path = self.log_dir.join("daemon.log");
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
            let ts = chrono::Utc::now().to_rfc3339();
            let _ = writeln!(f, "{} [{}] {}", ts, level, msg);
        }
    }

    pub fn log_dir(&self) -> &str {
        self.log_dir.to_str().unwrap_or("")
    }
}
