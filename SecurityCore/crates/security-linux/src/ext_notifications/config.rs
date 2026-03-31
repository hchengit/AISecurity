//! Notification channel configuration — JSON persistence.
//! Shares the same format as the macOS notification-config.json.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelegramConfig {
    #[serde(default)]
    pub bot_token: String,
    #[serde(default)]
    pub chat_id: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordConfig {
    #[serde(default)]
    pub webhook_url: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    #[serde(default)]
    pub user_email: String,
    #[serde(default)]
    pub app_password: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub telegram: TelegramConfig,
    pub discord: DiscordConfig,
    pub email: EmailConfig,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            telegram: TelegramConfig {
                bot_token: String::new(),
                chat_id: String::new(),
                enabled: false,
                updated_at: None,
            },
            discord: DiscordConfig {
                webhook_url: String::new(),
                enabled: false,
                updated_at: None,
            },
            email: EmailConfig {
                user_email: String::new(),
                app_password: String::new(),
                enabled: false,
                updated_at: None,
            },
        }
    }
}

impl NotificationConfig {
    /// Load from `{config_dir}/notification-config.json`, or return defaults.
    pub fn load(config_dir: &str) -> Self {
        let path = PathBuf::from(config_dir).join("notification-config.json");
        match fs::read_to_string(&path) {
            Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    /// Save to `{config_dir}/notification-config.json`.
    pub fn save(&self, config_dir: &str) -> Result<(), String> {
        let path = PathBuf::from(config_dir).join("notification-config.json");
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("JSON serialize: {}", e))?;
        fs::write(&path, json).map_err(|e| format!("Write: {}", e))?;

        // Harden permissions (owner-only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }

        Ok(())
    }
}
