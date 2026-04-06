/// Platform-aware path resolver.
/// Uses cfg!(target_os) to provide sensible defaults per OS.
pub struct PathResolver {
    home: String,
}

impl PathResolver {
    pub fn new() -> Self {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_else(|_| "/tmp".to_string());
        Self { home }
    }

    /// Expand ~ to $HOME.
    pub fn resolve(&self, path: &str) -> String {
        if path.starts_with("~/") {
            format!("{}{}", self.home, &path[1..])
        } else if path == "~" {
            self.home.clone()
        } else {
            path.to_string()
        }
    }

    pub fn home(&self) -> &str {
        &self.home
    }

    pub fn security_dir(&self) -> String {
        format!("{}/.mac-security", self.home)
    }

    pub fn quarantine_dir(&self) -> String {
        format!("{}/.mac-security/quarantine", self.home)
    }

    pub fn log_dir(&self) -> String {
        format!("{}/.mac-security/logs", self.home)
    }

    /// Mail directory — platform-specific default.
    pub fn mail_dir(&self) -> String {
        if cfg!(target_os = "macos") {
            format!("{}/Library/Mail", self.home)
        } else {
            // Linux: Thunderbird default
            format!("{}/.thunderbird", self.home)
        }
    }

    /// Messages database — platform-specific default.
    pub fn messages_db(&self) -> String {
        if cfg!(target_os = "macos") {
            format!("{}/Library/Messages/chat.db", self.home)
        } else {
            // Linux: Signal Desktop
            format!("{}/.config/Signal/sql/db.sqlite", self.home)
        }
    }

    pub fn downloads_dir(&self) -> String {
        format!("{}/Downloads", self.home)
    }

    pub fn desktop_dir(&self) -> String {
        format!("{}/Desktop", self.home)
    }

    pub fn documents_dir(&self) -> String {
        format!("{}/Documents", self.home)
    }

    /// Default directories to monitor for new files.
    pub fn default_monitored_dirs(&self) -> Vec<String> {
        vec![
            format!("{}/Downloads", self.home),
            format!("{}/Desktop", self.home),
            format!("{}/Documents", self.home),
        ]
    }

    /// Default protected paths — platform-specific.
    pub fn default_protected_paths(&self) -> Vec<String> {
        let mut paths = vec![
            format!("{}/.ssh", self.home),
            format!("{}/.gnupg", self.home),
            format!("{}/.bitcoin", self.home),
            format!("{}/.lnd", self.home),
            format!("{}/.sparrow", self.home),
        ];

        if cfg!(target_os = "macos") {
            paths.extend([
                format!("{}/Library/Keychains", self.home),
                format!("{}/Library/Messages", self.home),
                format!("{}/Library/Mail", self.home),
                format!("{}/Library/Saved Application State", self.home),
                format!("{}/Library/Application Support/Sparrow", self.home),
                format!("{}/Library/Application Support/Bitwarden", self.home),
                format!("{}/Library/Safari", self.home),
                format!("{}/Library/Calendars", self.home),
                format!("{}/Library/Group Containers/group.com.apple.notes", self.home),
                format!("{}/Pictures/Photos Library.photoslibrary", self.home),
                format!("{}/Documents/Tax Returns", self.home),
                format!("{}/Documents/TurboTax", self.home),
            ]);
        } else {
            // Linux equivalents
            paths.extend([
                format!("{}/.local/share/keyrings", self.home),
                format!("{}/.config/Signal", self.home),
                format!("{}/.thunderbird", self.home),
                format!("{}/.config/Bitwarden", self.home),
                format!("{}/Pictures", self.home),
                format!("{}/Documents/Tax Returns", self.home),
            ]);
        }

        paths
    }

    /// Linux-specific path mapping.
    pub fn keychain_dir(&self) -> String {
        if cfg!(target_os = "macos") {
            format!("{}/Library/Keychains", self.home)
        } else {
            format!("{}/.local/share/keyrings", self.home)
        }
    }

    pub fn photos_dir(&self) -> String {
        if cfg!(target_os = "macos") {
            format!("{}/Pictures/Photos Library.photoslibrary", self.home)
        } else {
            format!("{}/Pictures", self.home)
        }
    }

    pub fn bitwarden_dir(&self) -> String {
        if cfg!(target_os = "macos") {
            format!("{}/Library/Application Support/Bitwarden", self.home)
        } else {
            format!("{}/.config/Bitwarden", self.home)
        }
    }

    pub fn sparrow_dir(&self) -> String {
        if cfg!(target_os = "macos") {
            format!("{}/Library/Application Support/Sparrow", self.home)
        } else {
            format!("{}/.sparrow", self.home)
        }
    }
}

impl Default for PathResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_tilde() {
        let resolver = PathResolver::new();
        let resolved = resolver.resolve("~/Documents/test.txt");
        assert!(!resolved.starts_with("~/"));
        assert!(resolved.ends_with("/Documents/test.txt"));
    }

    #[test]
    fn resolve_absolute_unchanged() {
        let resolver = PathResolver::new();
        assert_eq!(resolver.resolve("/tmp/test"), "/tmp/test");
    }

    #[test]
    fn security_dir_under_home() {
        let resolver = PathResolver::new();
        assert!(resolver.security_dir().ends_with(".mac-security"));
    }

    #[test]
    fn default_monitored_dirs() {
        let resolver = PathResolver::new();
        let dirs = resolver.default_monitored_dirs();
        assert_eq!(dirs.len(), 3);
        assert!(dirs.iter().any(|d| d.ends_with("/Downloads")));
        assert!(dirs.iter().any(|d| d.ends_with("/Desktop")));
        assert!(dirs.iter().any(|d| d.ends_with("/Documents")));
    }

    #[test]
    fn protected_paths_include_ssh() {
        let resolver = PathResolver::new();
        let paths = resolver.default_protected_paths();
        assert!(paths.iter().any(|p| p.ends_with(".ssh")));
        assert!(paths.iter().any(|p| p.ends_with(".gnupg")));
        assert!(paths.iter().any(|p| p.ends_with(".bitcoin")));
    }
}
