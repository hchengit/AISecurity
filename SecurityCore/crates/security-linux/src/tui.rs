//! TUI threat viewer — reads alerts.log, displays severity badges, allows dismiss.
//! Launch with: security-linux --tui

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::*;
use security_core::alert::SecurityAlert;
use security_core::severity::SeverityLevel;
use std::io::{self, stdout, BufRead};
use std::path::Path;
use std::time::Duration;

struct App {
    alerts: Vec<SecurityAlert>,
    selected: usize,
    should_quit: bool,
}

impl App {
    fn new(alerts: Vec<SecurityAlert>) -> Self {
        Self {
            alerts,
            selected: 0,
            should_quit: false,
        }
    }

    fn next(&mut self) {
        if !self.alerts.is_empty() {
            self.selected = (self.selected + 1).min(self.alerts.len() - 1);
        }
    }

    fn prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    fn dismiss_selected(&mut self) {
        if !self.alerts.is_empty() {
            self.alerts.remove(self.selected);
            if self.selected >= self.alerts.len() && self.selected > 0 {
                self.selected -= 1;
            }
        }
    }
}

/// Load alerts from the JSON log file.
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

    // Most recent first
    alerts.reverse();
    alerts
}

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

fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // title
            Constraint::Min(10),   // alert list
            Constraint::Length(5), // detail
            Constraint::Length(1), // status bar
        ])
        .split(frame.area());

    // Title
    let title = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" SecurityCore — Threat Viewer ");
    let title_text = Paragraph::new(format!(
        " {} alert(s) loaded",
        app.alerts.len()
    ))
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
            let prefix = if i == app.selected { "► " } else { "  " };

            let line = Line::from(vec![
                Span::raw(prefix),
                Span::styled(badge, Style::default().fg(Color::Black).bg(color).bold()),
                Span::raw(" "),
                Span::styled(
                    &alert.timestamp[..19.min(alert.timestamp.len())],
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(" "),
                Span::raw(&alert.message),
            ]);

            ListItem::new(line)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Alerts (↑/↓ navigate, d dismiss, q quit) "),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));
    frame.render_widget(list, chunks[1]);

    // Detail panel
    let detail = if let Some(alert) = app.alerts.get(app.selected) {
        let mut lines = vec![
            Line::from(vec![
                Span::styled("Type: ", Style::default().bold()),
                Span::raw(&alert.alert_type),
                Span::raw("  "),
                Span::styled("Severity: ", Style::default().bold()),
                Span::styled(
                    format!("{}", alert.severity),
                    Style::default().fg(severity_color(alert.severity)).bold(),
                ),
            ]),
        ];

        if let Some(ref from) = alert.from {
            lines.push(Line::from(vec![
                Span::styled("From: ", Style::default().bold()),
                Span::raw(from.as_str()),
            ]));
        }
        if let Some(ref subject) = alert.subject {
            lines.push(Line::from(vec![
                Span::styled("Subject: ", Style::default().bold()),
                Span::raw(subject.as_str()),
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

    let detail_block = detail.block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Details "),
    );
    frame.render_widget(detail_block, chunks[2]);

    // Status bar
    let status = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓ ", Style::default().bold()),
        Span::raw("Navigate  "),
        Span::styled(" d ", Style::default().bold()),
        Span::raw("Dismiss  "),
        Span::styled(" r ", Style::default().bold()),
        Span::raw("Reload  "),
        Span::styled(" q ", Style::default().bold()),
        Span::raw("Quit"),
    ]))
    .style(Style::default().bg(Color::DarkGray));
    frame.render_widget(status, chunks[3]);
}

/// Run the TUI threat viewer.
pub fn run(alerts_log_path: &str) -> io::Result<()> {
    let log_path = Path::new(alerts_log_path);
    let alerts = load_alerts(log_path);

    // Setup terminal
    terminal::enable_raw_mode()?;
    stdout().execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;

    let mut app = App::new(alerts);

    loop {
        terminal.draw(|f| render(f, &app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
                        KeyCode::Down | KeyCode::Char('j') => app.next(),
                        KeyCode::Up | KeyCode::Char('k') => app.prev(),
                        KeyCode::Char('d') => app.dismiss_selected(),
                        KeyCode::Char('r') => {
                            app.alerts = load_alerts(log_path);
                            app.selected = 0;
                        }
                        _ => {}
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    terminal::disable_raw_mode()?;
    stdout().execute(LeaveAlternateScreen)?;

    Ok(())
}
