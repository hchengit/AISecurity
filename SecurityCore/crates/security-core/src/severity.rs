use serde::{Deserialize, Serialize};
use std::fmt;

/// Threat severity levels — matches the Swift CRITICAL/HIGH/MEDIUM/LOW system.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SeverityLevel {
    #[serde(rename = "CRITICAL")]
    Critical = 4,
    #[serde(rename = "HIGH")]
    High = 3,
    #[serde(rename = "MEDIUM")]
    Medium = 2,
    #[serde(rename = "LOW")]
    Low = 1,
}

impl SeverityLevel {
    pub fn rank(self) -> u8 {
        self as u8
    }
}

impl PartialOrd for SeverityLevel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SeverityLevel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rank().cmp(&other.rank())
    }
}

impl fmt::Display for SeverityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SeverityLevel::Critical => write!(f, "CRITICAL"),
            SeverityLevel::High => write!(f, "HIGH"),
            SeverityLevel::Medium => write!(f, "MEDIUM"),
            SeverityLevel::Low => write!(f, "LOW"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ordering() {
        assert!(SeverityLevel::Critical > SeverityLevel::High);
        assert!(SeverityLevel::High > SeverityLevel::Medium);
        assert!(SeverityLevel::Medium > SeverityLevel::Low);
    }

    #[test]
    fn severity_json_roundtrip() {
        let val = SeverityLevel::Critical;
        let json = serde_json::to_string(&val).unwrap();
        assert_eq!(json, "\"CRITICAL\"");
        let back: SeverityLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, val);
    }
}
