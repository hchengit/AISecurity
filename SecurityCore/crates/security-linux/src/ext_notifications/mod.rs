//! External notification channels — Telegram, Discord, Email.
//! Mirrors the macOS Swift implementation with identical message formats.

pub mod config;
pub mod discord;
pub mod email;
pub mod telegram;

use config::NotificationConfig;
use security_core::alert::SecurityAlert;
use security_core::severity::SeverityLevel;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

/// Rate-limiting notification manager.
/// Routes alerts to configured channels based on severity.
pub struct NotificationManager {
    config: NotificationConfig,
    state: Mutex<RateLimitState>,
}

struct RateLimitState {
    /// Per-alert-type cooldown (60s).
    last_send_by_type: HashMap<String, Instant>,
    /// Per-file cooldown (1 hour).
    last_send_by_file: HashMap<String, Instant>,
    /// Global window: max 10 per 5 minutes.
    global_window: Vec<Instant>,
    /// Count of suppressed notifications.
    suppressed: u64,
}

const TYPE_COOLDOWN_SECS: u64 = 60;
const FILE_COOLDOWN_SECS: u64 = 3600;
const GLOBAL_MAX: usize = 10;
const GLOBAL_WINDOW_SECS: u64 = 300;

impl NotificationManager {
    pub fn new(config_dir: &str) -> Self {
        Self {
            config: NotificationConfig::load(config_dir),
            state: Mutex::new(RateLimitState {
                last_send_by_type: HashMap::new(),
                last_send_by_file: HashMap::new(),
                global_window: Vec::new(),
                suppressed: 0,
            }),
        }
    }

    /// Reload config from disk.
    pub fn reload_config(&mut self, config_dir: &str) {
        self.config = NotificationConfig::load(config_dir);
    }

    /// Send an alert to all configured channels (if not rate-limited).
    pub fn send(&self, alert: &SecurityAlert) {
        // Only send external notifications for HIGH and CRITICAL
        if !should_send_external(alert.severity) {
            return;
        }

        // Rate limiting
        if !self.check_rate_limit(alert) {
            return;
        }

        // Send to each enabled channel
        if self.config.telegram.enabled
            && !self.config.telegram.bot_token.is_empty()
            && !self.config.telegram.chat_id.is_empty()
        {
            if let Err(e) = telegram::send(alert, &self.config.telegram) {
                log::warn!("Telegram send failed: {}", e);
            }
        }

        if self.config.discord.enabled && !self.config.discord.webhook_url.is_empty() {
            if let Err(e) = discord::send(alert, &self.config.discord) {
                log::warn!("Discord send failed: {}", e);
            }
        }

        if self.config.email.enabled
            && !self.config.email.user_email.is_empty()
            && !self.config.email.app_password.is_empty()
        {
            if let Err(e) = email::send(alert, &self.config.email) {
                log::warn!("Email send failed: {}", e);
            }
        }
    }

    fn check_rate_limit(&self, alert: &SecurityAlert) -> bool {
        let mut state = self.state.lock().unwrap();
        let now = Instant::now();

        // Per-type cooldown
        if let Some(last) = state.last_send_by_type.get(&alert.alert_type) {
            if now.duration_since(*last).as_secs() < TYPE_COOLDOWN_SECS {
                state.suppressed += 1;
                return false;
            }
        }

        // Per-file cooldown
        if let Some(ref fp) = alert.file_path {
            if let Some(last) = state.last_send_by_file.get(fp) {
                if now.duration_since(*last).as_secs() < FILE_COOLDOWN_SECS {
                    state.suppressed += 1;
                    return false;
                }
            }
        }

        // Global window
        state
            .global_window
            .retain(|t| now.duration_since(*t).as_secs() < GLOBAL_WINDOW_SECS);
        if state.global_window.len() >= GLOBAL_MAX {
            state.suppressed += 1;
            return false;
        }

        // Record this send
        state
            .last_send_by_type
            .insert(alert.alert_type.clone(), now);
        if let Some(ref fp) = alert.file_path {
            state.last_send_by_file.insert(fp.clone(), now);
        }
        state.global_window.push(now);

        // Prune old entries
        if state.last_send_by_file.len() > 200 {
            let cutoff_secs = FILE_COOLDOWN_SECS;
            state
                .last_send_by_file
                .retain(|_, t| now.duration_since(*t).as_secs() < cutoff_secs);
        }

        true
    }
}

fn should_send_external(severity: SeverityLevel) -> bool {
    matches!(
        severity,
        SeverityLevel::Critical | SeverityLevel::High
    )
}
