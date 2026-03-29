use security_core::alert::SecurityAlert;
use security_core::severity::SeverityLevel;

/// Send desktop notification for security alerts via D-Bus.
pub fn notify(alert: &SecurityAlert) {
    let urgency = match alert.severity {
        SeverityLevel::Critical => notify_rust::Urgency::Critical,
        SeverityLevel::High => notify_rust::Urgency::Critical,
        SeverityLevel::Medium => notify_rust::Urgency::Normal,
        SeverityLevel::Low => notify_rust::Urgency::Low,
    };

    let icon = match alert.severity {
        SeverityLevel::Critical | SeverityLevel::High => "dialog-warning",
        SeverityLevel::Medium => "dialog-information",
        SeverityLevel::Low => "dialog-information",
    };

    let title = format!("SecurityCore — {}", alert.severity);

    let _ = notify_rust::Notification::new()
        .summary(&title)
        .body(&alert.message)
        .icon(icon)
        .urgency(urgency)
        .timeout(notify_rust::Timeout::Milliseconds(8000))
        .show();
}

/// Should we show a desktop notification for this severity?
pub fn should_notify(severity: SeverityLevel, critical_only: bool) -> bool {
    if critical_only {
        matches!(severity, SeverityLevel::Critical | SeverityLevel::High)
    } else {
        true
    }
}
