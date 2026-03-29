use serde::{Deserialize, Serialize};

use crate::severity::SeverityLevel;

/// A single security finding from any module.
/// JSON field names match the Swift SecurityAlert exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    #[serde(rename = "type")]
    pub alert_type: String,
    pub severity: SeverityLevel,
    pub message: String,
    pub timestamp: String,
    #[serde(rename = "filePath", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threats: Option<Vec<ThreatDetail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub findings: Option<Vec<FindingDetail>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatDetail {
    pub label: String,
    pub category: String,
    pub severity: SeverityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingDetail {
    pub label: String,
    pub category: String,
    pub severity: SeverityLevel,
}

impl SecurityAlert {
    pub fn new(alert_type: &str, severity: SeverityLevel, message: &str) -> Self {
        Self {
            alert_type: alert_type.to_string(),
            severity,
            message: message.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            file_path: None,
            from: None,
            to: None,
            subject: None,
            threats: None,
            findings: None,
            preview: None,
            sender: None,
            category: None,
        }
    }
}
