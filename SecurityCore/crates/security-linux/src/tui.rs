//! TUI — multi-screen terminal interface.
//! Screens: Alerts (threat viewer), Vault (file protection manager).
//! Launch with: security-linux --tui

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::*;
use security_core::alert::SecurityAlert;
use security_core::severity::SeverityLevel;
use security_core::vault::{ProtectionLevel, Vault, VaultEntry};
use std::collections::BTreeMap;
use std::io::{self, stdout, BufRead};
use std::path::Path;
use std::time::Duration;

use crate::auth::AuthGate;
use crate::tui_file_browser::FileBrowser;

// ─── Screen Enum ───────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Screen {
    Alerts,
    Vault,
    FileBrowser,
    ProtectionPicker,
    AuthPrompt,
}

// ─── App State ─────────────────────────────────────────────────────────────

struct App {
    screen: Screen,
    should_quit: bool,

    // Alerts screen
    alerts: Vec<SecurityAlert>,
    alert_cursor: usize,

    // Vault screen
    vault_entries: Vec<VaultEntry>,
    vault_cursor: usize,
    vault_folders: Vec<FolderGroup>,
    vault_flat_index: Vec<(usize, usize)>, // (folder_idx, entry_idx_within_folder)

    // File browser
    file_browser: Option<FileBrowser>,

    // Protection picker
    picker_locked: bool,
    picker_read_only: bool,
    picker_local_only: bool,
    picker_cursor: usize,

    // Auth prompt
    auth_password: String,
    auth_message: String,
    auth_error: Option<String>,
    auth_callback: AuthAction,

    // Vault passphrase (cached for session)
    vault_passphrase: Option<String>,

    // Paths
    alerts_log_path: String,
    security_dir: String,

    // Auth gate
    auth_gate: AuthGate,

    // Status message
    status_msg: Option<String>,
}

#[derive(Clone)]
enum AuthAction {
    None,
    UnlockFiles(Vec<String>),
    LockFiles(Vec<String>),
    ToggleLocalOnly(Vec<String>),
    ProtectFiles(Vec<String>, ProtectionLevel),
    ViewVault,
}

struct FolderGroup {
    folder: String,
    entries: Vec<VaultEntry>,
    expanded: bool,
}

impl App {
    fn new(alerts_log_path: &str, security_dir: &str) -> Self {
        let alerts = load_alerts(Path::new(alerts_log_path));
        Self {
            screen: Screen::Alerts,
            should_quit: false,
            alerts,
            alert_cursor: 0,
            vault_entries: Vec::new(),
            vault_cursor: 0,
            vault_folders: Vec::new(),
            vault_flat_index: Vec::new(),
            file_browser: None,
            picker_locked: true,
            picker_read_only: false,
            picker_local_only: false,
            picker_cursor: 0,
            auth_password: String::new(),
            auth_message: String::new(),
            auth_error: None,
            auth_callback: AuthAction::None,
            vault_passphrase: None,
            alerts_log_path: alerts_log_path.to_string(),
            security_dir: security_dir.to_string(),
            auth_gate: AuthGate::new(),
            status_msg: None,
        }
    }

    fn reload_alerts(&mut self) {
        self.alerts = load_alerts(Path::new(&self.alerts_log_path));
        self.alert_cursor = 0;
    }

    fn load_vault(&mut self) {
        if let Some(ref pass) = self.vault_passphrase {
            let vault = Vault::new(&self.security_dir);
            match vault.list(pass) {
                Ok(entries) => {
                    self.vault_entries = entries;
                    self.build_folder_groups();
                    self.status_msg = Some(format!("{} vault entries loaded", self.vault_entries.len()));
                }
                Err(e) => {
                    self.status_msg = Some(format!("Vault error: {}", e));
                }
            }
        }
    }

    fn build_folder_groups(&mut self) {
        let mut by_folder: BTreeMap<String, Vec<VaultEntry>> = BTreeMap::new();
        for entry in &self.vault_entries {
            let folder = Path::new(&entry.original_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "/".to_string());
            by_folder.entry(folder).or_default().push(entry.clone());
        }

        self.vault_folders = by_folder
            .into_iter()
            .map(|(folder, entries)| FolderGroup {
                folder,
                entries,
                expanded: true,
            })
            .collect();

        self.rebuild_flat_index();
    }

    fn rebuild_flat_index(&mut self) {
        self.vault_flat_index.clear();
        for (fi, group) in self.vault_folders.iter().enumerate() {
            // Folder header itself
            self.vault_flat_index.push((fi, usize::MAX));
            if group.expanded {
                for ei in 0..group.entries.len() {
                    self.vault_flat_index.push((fi, ei));
                }
            }
        }
    }

    fn vault_next(&mut self) {
        if !self.vault_flat_index.is_empty() {
            self.vault_cursor = (self.vault_cursor + 1).min(self.vault_flat_index.len() - 1);
        }
    }

    fn vault_prev(&mut self) {
        self.vault_cursor = self.vault_cursor.saturating_sub(1);
    }

    fn vault_toggle_folder(&mut self) {
        if let Some(&(fi, ei)) = self.vault_flat_index.get(self.vault_cursor) {
            if ei == usize::MAX {
                // It's a folder header — toggle expand/collapse
                self.vault_folders[fi].expanded = !self.vault_folders[fi].expanded;
                self.rebuild_flat_index();
            }
        }
    }

    fn selected_vault_entry(&self) -> Option<&VaultEntry> {
        if let Some(&(fi, ei)) = self.vault_flat_index.get(self.vault_cursor) {
            if ei != usize::MAX {
                return self.vault_folders.get(fi)?.entries.get(ei);
            }
        }
        None
    }

    fn require_auth(&mut self, message: &str, action: AuthAction) {
        if self.auth_gate.has_valid_session() && self.vault_passphrase.is_some() {
            // Already authenticated — execute directly
            self.execute_auth_action(action);
        } else if self.auth_gate.is_locked_out() {
            let secs = self.auth_gate.lockout_remaining_secs();
            self.status_msg = Some(format!("Locked out. Try again in {}s", secs));
        } else {
            self.auth_message = message.to_string();
            self.auth_password.clear();
            self.auth_error = None;
            self.auth_callback = action;
            self.screen = Screen::AuthPrompt;
        }
    }

    fn submit_auth(&mut self) {
        let password = self.auth_password.clone();

        match self.auth_gate.authenticate(&password) {
            Ok(()) => {
                // If we don't have vault passphrase yet, this password IS the vault passphrase
                // (or prompt separately — for now we use the same password)
                if self.vault_passphrase.is_none() {
                    // Try using the system password as vault passphrase
                    let vault = Vault::new(&self.security_dir);
                    if vault.verify_passphrase(&password).unwrap_or(false) {
                        self.vault_passphrase = Some(password.clone());
                    }
                    // If vault passphrase is different from system password,
                    // the user will need to enter it separately via the vault prompt
                }

                let action = self.auth_callback.clone();
                self.auth_password.clear();
                self.screen = Screen::Vault;
                self.execute_auth_action(action);
            }
            Err(e) => {
                self.auth_error = Some(format!("{} ({} attempts remaining)",
                    e, self.auth_gate.attempts_remaining()));
                self.auth_password.clear();
            }
        }
    }

    fn execute_auth_action(&mut self, action: AuthAction) {
        let pass = match &self.vault_passphrase {
            Some(p) => p.clone(),
            None => {
                self.status_msg = Some("Vault passphrase required".to_string());
                return;
            }
        };

        let vault = Vault::new(&self.security_dir);

        match action {
            AuthAction::ViewVault => {
                self.load_vault();
            }
            AuthAction::UnlockFiles(paths) => {
                let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                match vault.unlock(&path_refs, &pass) {
                    Ok(r) => self.status_msg = Some(r.message),
                    Err(e) => self.status_msg = Some(format!("Unlock error: {}", e)),
                }
                self.load_vault();
            }
            AuthAction::LockFiles(paths) => {
                let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                match vault.lock(&path_refs, &pass) {
                    Ok(r) => self.status_msg = Some(r.message),
                    Err(e) => self.status_msg = Some(format!("Lock error: {}", e)),
                }
                self.load_vault();
            }
            AuthAction::ToggleLocalOnly(paths) => {
                let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                match vault.toggle_local_only(&path_refs, &pass) {
                    Ok(r) => self.status_msg = Some(r.message),
                    Err(e) => self.status_msg = Some(format!("Toggle error: {}", e)),
                }
                self.load_vault();
            }
            AuthAction::ProtectFiles(paths, protection) => {
                let path_refs: Vec<&str> = paths.iter().map(|s| s.as_str()).collect();
                match vault.add(&path_refs, protection, &pass) {
                    Ok(r) => self.status_msg = Some(r.message),
                    Err(e) => self.status_msg = Some(format!("Protect error: {}", e)),
                }
                self.load_vault();
            }
            AuthAction::None => {}
        }
    }

    fn get_picked_protection(&self) -> Option<ProtectionLevel> {
        match (self.picker_locked, self.picker_read_only, self.picker_local_only) {
            (true, _, true) => Some(ProtectionLevel::LockedLocal),
            (true, _, false) => Some(ProtectionLevel::Locked),
            (false, true, true) => Some(ProtectionLevel::ReadOnlyLocal),
            (false, true, false) => Some(ProtectionLevel::ReadOnly),
            (false, false, true) => Some(ProtectionLevel::LocalOnly),
            _ => None,
        }
    }
}

// ─── Alert Loading ─────────────────────────────────────────────────────────

fn load_alerts(log_path: &Path) -> Vec<SecurityAlert> {
    let file = match std::fs::File::open(log_path) {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let reader = io::BufReader::new(file);
    let mut alerts = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        if let Ok(alert) = serde_json::from_str::<SecurityAlert>(&line) {
            alerts.push(alert);
        }
    }
    alerts.reverse();
    alerts
}

// ─── Rendering Helpers ─────────────────────────────────────────────────────

fn severity_color(sev: SeverityLevel) -> Color {
    match sev {
        SeverityLevel::Critical => Color::Red,
        SeverityLevel::High => Color::Yellow,
        SeverityLevel::Medium => Color::Cyan,
        SeverityLevel::Low => Color::Green,
    }
}

fn severity_badge(sev: SeverityLevel) -> &'static str {
    match sev {
        SeverityLevel::Critical => " CRITICAL ",
        SeverityLevel::High => "   HIGH   ",
        SeverityLevel::Medium => "  MEDIUM  ",
        SeverityLevel::Low => "   LOW    ",
    }
}

fn protection_badge(prot: ProtectionLevel) -> (&'static str, Color) {
    match prot {
        ProtectionLevel::Locked => ("LOCKED", Color::Red),
        ProtectionLevel::ReadOnly => ("READ-ONLY", Color::Yellow),
        ProtectionLevel::LocalOnly => ("LOCAL-ONLY", Color::Cyan),
        ProtectionLevel::ReadOnlyLocal => ("RO+LOCAL", Color::Magenta),
        ProtectionLevel::LockedLocal => ("LOCK+LOCAL", Color::LightRed),
    }
}

// ─── Screen Renderers ──────────────────────────────────────────────────────

fn render(frame: &mut Frame, app: &App) {
    match app.screen {
        Screen::Alerts => render_alerts(frame, app),
        Screen::Vault => render_vault(frame, app),
        Screen::FileBrowser => render_file_browser(frame, app),
        Screen::ProtectionPicker => render_protection_picker(frame, app),
        Screen::AuthPrompt => render_auth_prompt(frame, app),
    }
}

fn render_alerts(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(5),
            Constraint::Length(1),
        ])
        .split(frame.area());

    // Title
    let title = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" SecurityCore \u{2014} Threat Viewer ");
    let title_text = Paragraph::new(format!(" {} alert(s) loaded", app.alerts.len()))
        .block(title);
    frame.render_widget(title_text, chunks[0]);

    // Alert list
    let items: Vec<ListItem> = app
        .alerts
        .iter()
        .enumerate()
        .map(|(i, alert)| {
            let badge = severity_badge(alert.severity);
            let color = severity_color(alert.severity);
            let prefix = if i == app.alert_cursor { "\u{25B6} " } else { "  " };
            let ts = &alert.timestamp[..19.min(alert.timestamp.len())];
            ListItem::new(Line::from(vec![
                Span::raw(prefix),
                Span::styled(badge, Style::default().fg(Color::Black).bg(color).bold()),
                Span::raw(" "),
                Span::styled(ts, Style::default().fg(Color::DarkGray)),
                Span::raw(" "),
                Span::raw(&alert.message),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Alerts "),
    );
    frame.render_widget(list, chunks[1]);

    // Detail panel
    let detail = if let Some(alert) = app.alerts.get(app.alert_cursor) {
        let mut lines = vec![Line::from(vec![
            Span::styled("Type: ", Style::default().bold()),
            Span::raw(&alert.alert_type),
            Span::raw("  "),
            Span::styled("Severity: ", Style::default().bold()),
            Span::styled(
                format!("{}", alert.severity),
                Style::default().fg(severity_color(alert.severity)).bold(),
            ),
        ])];
        if let Some(ref from) = alert.from {
            lines.push(Line::from(vec![
                Span::styled("From: ", Style::default().bold()),
                Span::raw(from.as_str()),
            ]));
        }
        if let Some(ref preview) = alert.preview {
            lines.push(Line::from(vec![
                Span::styled("Preview: ", Style::default().bold()),
                Span::styled(preview.as_str(), Style::default().fg(Color::DarkGray)),
            ]));
        }
        Paragraph::new(lines)
    } else {
        Paragraph::new("No alerts")
    };
    frame.render_widget(
        detail.block(Block::default().borders(Borders::ALL).title(" Details ")),
        chunks[2],
    );

    // Status bar
    let status_text = app.status_msg.as_deref().unwrap_or("");
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" \u{2191}\u{2193} ", Style::default().bold()),
        Span::raw("Navigate  "),
        Span::styled(" d ", Style::default().bold()),
        Span::raw("Dismiss  "),
        Span::styled(" r ", Style::default().bold()),
        Span::raw("Reload  "),
        Span::styled(" v ", Style::default().bold()),
        Span::raw("Vault  "),
        Span::styled(" q ", Style::default().bold()),
        Span::raw("Quit  "),
        Span::styled(status_text, Style::default().fg(Color::Yellow)),
    ]))
    .style(Style::default().bg(Color::DarkGray));
    frame.render_widget(status, chunks[3]);
}

fn render_vault(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(5),
            Constraint::Length(1),
        ])
        .split(frame.area());

    // Title
    let title = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Magenta))
        .title(" SecurityCore \u{2014} Vault Manager ");
    let title_text = Paragraph::new(format!(
        " {} protected file(s) in {} folder(s)",
        app.vault_entries.len(),
        app.vault_folders.len()
    ))
    .block(title);
    frame.render_widget(title_text, chunks[0]);

    // Vault entry list with folder grouping
    let mut items: Vec<ListItem> = Vec::new();
    for (idx, &(fi, ei)) in app.vault_flat_index.iter().enumerate() {
        let prefix = if idx == app.vault_cursor { "\u{25B6} " } else { "  " };

        if ei == usize::MAX {
            // Folder header
            let group = &app.vault_folders[fi];
            let arrow = if group.expanded { "\u{25BC}" } else { "\u{25B6}" };
            items.push(ListItem::new(Line::from(vec![
                Span::raw(prefix),
                Span::styled(
                    format!("{} \u{1F4C1} {} ({} files)", arrow, group.folder, group.entries.len()),
                    Style::default().fg(Color::Cyan).bold(),
                ),
            ])));
        } else {
            // File entry
            let entry = &app.vault_folders[fi].entries[ei];
            let (badge, color) = protection_badge(entry.protection);
            let name = Path::new(&entry.original_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| entry.original_path.clone());
            let unlock_status = if entry.is_unlocked { " [DECRYPTED]" } else { "" };

            items.push(ListItem::new(Line::from(vec![
                Span::raw(prefix),
                Span::raw("    "),
                Span::styled(
                    format!(" {} ", badge),
                    Style::default().fg(Color::Black).bg(color).bold(),
                ),
                Span::raw(" "),
                Span::raw(name),
                Span::styled(unlock_status, Style::default().fg(Color::Green)),
            ])));
        }
    }

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Protected Files "),
    );
    frame.render_widget(list, chunks[1]);

    // Detail panel
    let detail = if let Some(entry) = app.selected_vault_entry() {
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled("Path: ", Style::default().bold()),
                Span::raw(&entry.original_path),
            ]),
            Line::from(vec![
                Span::styled("Protection: ", Style::default().bold()),
                Span::raw(format!("{}", entry.protection)),
                Span::raw("  "),
                Span::styled("Size: ", Style::default().bold()),
                Span::raw(format_size(entry.size_bytes)),
            ]),
            Line::from(vec![
                Span::styled("Protected at: ", Style::default().bold()),
                Span::raw(&entry.encrypted_at),
            ]),
        ])
    } else {
        Paragraph::new("Select an entry to view details")
    };
    frame.render_widget(
        detail.block(Block::default().borders(Borders::ALL).title(" Details ")),
        chunks[2],
    );

    // Status bar
    let status_text = app.status_msg.as_deref().unwrap_or("");
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" \u{2191}\u{2193} ", Style::default().bold()),
        Span::raw("Navigate  "),
        Span::styled(" Enter ", Style::default().bold()),
        Span::raw("Expand  "),
        Span::styled(" u ", Style::default().bold()),
        Span::raw("Unlock  "),
        Span::styled(" l ", Style::default().bold()),
        Span::raw("Lock  "),
        Span::styled(" t ", Style::default().bold()),
        Span::raw("Toggle  "),
        Span::styled(" a ", Style::default().bold()),
        Span::raw("Add  "),
        Span::styled(" Esc ", Style::default().bold()),
        Span::raw("Back  "),
        Span::styled(status_text, Style::default().fg(Color::Yellow)),
    ]))
    .style(Style::default().bg(Color::DarkGray));
    frame.render_widget(status, chunks[3]);
}

fn render_file_browser(frame: &mut Frame, app: &App) {
    let browser = match &app.file_browser {
        Some(b) => b,
        None => return,
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(frame.area());

    // Title with current directory
    let title = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(" Select Files to Protect ");
    let title_text = Paragraph::new(format!(
        " {} \u{2014} {} selected",
        browser.current_dir_str(),
        browser.selection_count()
    ))
    .block(title);
    frame.render_widget(title_text, chunks[0]);

    // File list
    let items: Vec<ListItem> = browser
        .entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let prefix = if i == browser.cursor { "\u{25B6} " } else { "  " };
            let check = if entry.selected {
                "[\u{2713}] "
            } else if entry.is_dir {
                "    "
            } else {
                "[ ] "
            };
            let icon = if entry.name == ".." {
                "\u{2B06}"
            } else if entry.is_dir {
                "\u{1F4C1}"
            } else {
                "\u{1F4C4}"
            };
            let style = if entry.selected {
                Style::default().fg(Color::Green)
            } else if entry.is_dir {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default()
            };

            ListItem::new(Line::from(vec![
                Span::raw(prefix),
                Span::raw(check),
                Span::raw(format!("{} ", icon)),
                Span::styled(&entry.name, style),
            ]))
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Files "),
    );
    frame.render_widget(list, chunks[1]);

    // Status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" \u{2191}\u{2193} ", Style::default().bold()),
        Span::raw("Navigate  "),
        Span::styled(" Space ", Style::default().bold()),
        Span::raw("Select  "),
        Span::styled(" Enter ", Style::default().bold()),
        Span::raw("Open dir  "),
        Span::styled(" p ", Style::default().bold()),
        Span::raw("Protect  "),
        Span::styled(" Esc ", Style::default().bold()),
        Span::raw("Cancel"),
    ]))
    .style(Style::default().bg(Color::DarkGray));
    frame.render_widget(status, chunks[2]);
}

fn render_protection_picker(frame: &mut Frame, app: &App) {
    let area = centered_rect(50, 40, frame.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Choose Protection Level ");

    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);

    let options = vec![
        (
            app.picker_locked,
            "Locked (Encrypt)",
            "Original securely deleted, passphrase to decrypt",
        ),
        (
            app.picker_read_only,
            "Read-only",
            "Apps can open but not modify, alert on writes",
        ),
        (
            app.picker_local_only,
            "Local-only",
            "Alert on network exfiltration (can combine)",
        ),
    ];

    let mut lines = Vec::new();
    for (i, (checked, label, desc)) in options.iter().enumerate() {
        let prefix = if i == app.picker_cursor { "\u{25B6} " } else { "  " };
        let check = if *checked { "[\u{2713}]" } else { "[ ]" };
        lines.push(Line::from(vec![
            Span::raw(prefix),
            Span::styled(
                format!("{} {}", check, label),
                Style::default().bold(),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::raw("      "),
            Span::styled(*desc, Style::default().fg(Color::DarkGray)),
        ]));
        lines.push(Line::default());
    }

    lines.push(Line::from(vec![
        Span::styled(" Space ", Style::default().bold().fg(Color::Yellow)),
        Span::raw("Toggle  "),
        Span::styled(" Enter ", Style::default().bold().fg(Color::Yellow)),
        Span::raw("Confirm  "),
        Span::styled(" Esc ", Style::default().bold().fg(Color::Yellow)),
        Span::raw("Cancel"),
    ]));

    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_auth_prompt(frame: &mut Frame, app: &App) {
    let area = centered_rect(50, 30, frame.area());

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .title(" Authentication Required ");

    let inner = block.inner(area);
    frame.render_widget(Clear, area);
    frame.render_widget(block, area);

    let mask = "\u{2022}".repeat(app.auth_password.len());
    let attempts = app.auth_gate.attempts_remaining();

    let mut lines = vec![
        Line::from(Span::raw(&app.auth_message)),
        Line::default(),
        Line::from(vec![
            Span::styled("Password: ", Style::default().bold()),
            Span::raw(&mask),
            Span::styled("_", Style::default().fg(Color::White).add_modifier(Modifier::SLOW_BLINK)),
        ]),
        Line::default(),
        Line::from(Span::styled(
            format!("{} attempt(s) remaining", attempts),
            Style::default().fg(Color::DarkGray),
        )),
    ];

    if let Some(ref err) = app.auth_error {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            err.as_str(),
            Style::default().fg(Color::Red).bold(),
        )));
    }

    lines.push(Line::default());
    lines.push(Line::from(vec![
        Span::styled(" Enter ", Style::default().bold()),
        Span::raw("Submit  "),
        Span::styled(" Esc ", Style::default().bold()),
        Span::raw("Cancel"),
    ]));

    frame.render_widget(Paragraph::new(lines), inner);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

// ─── Event Loop ────────────────────────────────────────────────────────────

pub fn run(alerts_log_path: &str, security_dir: &str) -> io::Result<()> {
    terminal::enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut app = App::new(alerts_log_path, security_dir);

    loop {
        terminal.draw(|f| render(f, &app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match app.screen {
                        Screen::Alerts => match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                            KeyCode::Down | KeyCode::Char('j') => {
                                if !app.alerts.is_empty() {
                                    app.alert_cursor = (app.alert_cursor + 1).min(app.alerts.len() - 1);
                                }
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.alert_cursor = app.alert_cursor.saturating_sub(1);
                            }
                            KeyCode::Char('d') => {
                                if !app.alerts.is_empty() {
                                    app.alerts.remove(app.alert_cursor);
                                    if app.alert_cursor >= app.alerts.len() && app.alert_cursor > 0 {
                                        app.alert_cursor -= 1;
                                    }
                                }
                            }
                            KeyCode::Char('r') => app.reload_alerts(),
                            KeyCode::Char('v') => {
                                app.require_auth("Authenticate to access vault", AuthAction::ViewVault);
                            }
                            _ => {}
                        },
                        Screen::Vault => match key.code {
                            KeyCode::Esc => {
                                app.screen = Screen::Alerts;
                                app.status_msg = None;
                            }
                            KeyCode::Down | KeyCode::Char('j') => app.vault_next(),
                            KeyCode::Up | KeyCode::Char('k') => app.vault_prev(),
                            KeyCode::Enter => app.vault_toggle_folder(),
                            KeyCode::Char('u') => {
                                // Unlock selected entry
                                if let Some(entry) = app.selected_vault_entry() {
                                    let path = entry.original_path.clone();
                                    app.require_auth("Authenticate to unlock", AuthAction::UnlockFiles(vec![path]));
                                }
                            }
                            KeyCode::Char('l') => {
                                // Lock selected entry
                                if let Some(entry) = app.selected_vault_entry() {
                                    let path = entry.original_path.clone();
                                    app.require_auth("Authenticate to lock", AuthAction::LockFiles(vec![path]));
                                }
                            }
                            KeyCode::Char('t') => {
                                // Toggle local-only
                                if let Some(entry) = app.selected_vault_entry() {
                                    let path = entry.original_path.clone();
                                    app.require_auth("Authenticate to toggle", AuthAction::ToggleLocalOnly(vec![path]));
                                }
                            }
                            KeyCode::Char('a') => {
                                // Add files — open file browser
                                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                                app.file_browser = Some(FileBrowser::new(Path::new(&home)));
                                app.screen = Screen::FileBrowser;
                            }
                            KeyCode::Char('r') => app.load_vault(),
                            _ => {}
                        },
                        Screen::FileBrowser => {
                            if let Some(ref mut browser) = app.file_browser {
                                match key.code {
                                    KeyCode::Esc => {
                                        app.screen = Screen::Vault;
                                        app.file_browser = None;
                                    }
                                    KeyCode::Down | KeyCode::Char('j') => browser.next(),
                                    KeyCode::Up | KeyCode::Char('k') => browser.prev(),
                                    KeyCode::Enter => browser.enter(),
                                    KeyCode::Char(' ') => browser.toggle_selected(),
                                    KeyCode::Char('p') => {
                                        let selected = browser.get_selected();
                                        if !selected.is_empty() {
                                            app.screen = Screen::ProtectionPicker;
                                        } else {
                                            app.status_msg = Some("Select files first (Space)".to_string());
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Screen::ProtectionPicker => match key.code {
                            KeyCode::Esc => app.screen = Screen::FileBrowser,
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.picker_cursor = (app.picker_cursor + 1).min(2);
                            }
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.picker_cursor = app.picker_cursor.saturating_sub(1);
                            }
                            KeyCode::Char(' ') => {
                                match app.picker_cursor {
                                    0 => {
                                        app.picker_locked = !app.picker_locked;
                                        if app.picker_locked { app.picker_read_only = false; }
                                    }
                                    1 => {
                                        app.picker_read_only = !app.picker_read_only;
                                        if app.picker_read_only { app.picker_locked = false; }
                                    }
                                    2 => app.picker_local_only = !app.picker_local_only,
                                    _ => {}
                                }
                            }
                            KeyCode::Enter => {
                                if let Some(protection) = app.get_picked_protection() {
                                    let paths = app.file_browser.as_ref()
                                        .map(|b| b.get_selected())
                                        .unwrap_or_default();
                                    if !paths.is_empty() {
                                        app.file_browser = None;
                                        app.require_auth(
                                            "Authenticate to protect files",
                                            AuthAction::ProtectFiles(paths, protection),
                                        );
                                    }
                                } else {
                                    app.status_msg = Some("Select at least one protection level".to_string());
                                }
                            }
                            _ => {}
                        },
                        Screen::AuthPrompt => match key.code {
                            KeyCode::Esc => {
                                app.screen = if app.vault_passphrase.is_some() {
                                    Screen::Vault
                                } else {
                                    Screen::Alerts
                                };
                                app.auth_password.clear();
                            }
                            KeyCode::Enter => app.submit_auth(),
                            KeyCode::Backspace => { app.auth_password.pop(); }
                            KeyCode::Char(c) => app.auth_password.push(c),
                            _ => {}
                        },
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    terminal::disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
