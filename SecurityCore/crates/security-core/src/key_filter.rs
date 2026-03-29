//! Sensitive key filtering — redacts values for keys containing secrets.
//!
//! Applied to: log output, status display, config dump.
//! Matches ElizaOS pattern: blocks keys/secrets/passwords/tokens from AI-visible settings.

use once_cell::sync::Lazy;
use regex::Regex;

/// Key name patterns that indicate a sensitive value.
static SENSITIVE_KEY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"(?i)api[_\-]?key",
        r"(?i)secret[_\-]?key",
        r"(?i)private[_\-]?key",
        r"(?i)access[_\-]?token",
        r"(?i)auth[_\-]?token",
        r"(?i)bearer[_\-]?token",
        r"(?i)jwt[_\-]?secret",
        r"(?i)client[_\-]?secret",
        r"(?i)password",
        r"(?i)passwd",
        r"(?i)passphrase",
        r"(?i)seed[_\-]?phrase",
        r"(?i)mnemonic",
        r"(?i)private[_\-]?key",
        r"(?i)signing[_\-]?key",
        r"(?i)encryption[_\-]?key",
        r"(?i)master[_\-]?key",
        r"(?i)db[_\-]?pass",
        r"(?i)database[_\-]?url",
        r"(?i)connection[_\-]?string",
        r"(?i)aws[_\-]?secret",
        r"(?i)xprv",
        r"(?i)zprv",
        r"(?i)wif[_\-]?key",
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
});

/// Value patterns that look sensitive regardless of key name.
static SENSITIVE_VALUE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"\bsk-(?:proj-)?[a-zA-Z0-9\-_]{20,}",   // OpenAI key
        r"\bsk-ant-[a-zA-Z0-9\-_]{32,}",          // Anthropic key
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}", // GitHub token
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}",           // AWS key
        r"\bBearer\s+[A-Za-z0-9\-_\.~\+/]+=*",   // Bearer token
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", // PEM key
        r"\bxprv[a-zA-Z0-9]{107}",                // Bitcoin xprv
        r"\bzprv[a-zA-Z0-9]{107}",                // Bitcoin zprv
    ]
    .iter()
    .filter_map(|p| Regex::new(p).ok())
    .collect()
});

const REDACTED: &str = "[REDACTED]";

/// Check if a key name indicates a sensitive value.
pub fn is_sensitive_key(key: &str) -> bool {
    SENSITIVE_KEY_PATTERNS.iter().any(|p| p.is_match(key))
}

/// Check if a value looks sensitive regardless of key name.
pub fn is_sensitive_value(value: &str) -> bool {
    SENSITIVE_VALUE_PATTERNS.iter().any(|p| p.is_match(value))
}

/// Redact a value if its key or content is sensitive.
pub fn filter_value(key: &str, value: &str) -> String {
    if is_sensitive_key(key) || is_sensitive_value(value) {
        REDACTED.to_string()
    } else {
        value.to_string()
    }
}

/// Filter a JSON object's values, redacting sensitive keys.
pub fn filter_json_object(
    obj: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut filtered = serde_json::Map::new();
    for (key, value) in obj {
        let new_value = match value {
            serde_json::Value::String(s) => {
                if is_sensitive_key(key) || is_sensitive_value(s) {
                    serde_json::Value::String(REDACTED.to_string())
                } else {
                    value.clone()
                }
            }
            serde_json::Value::Object(inner) => {
                serde_json::Value::Object(filter_json_object(inner))
            }
            _ => {
                if is_sensitive_key(key) {
                    serde_json::Value::String(REDACTED.to_string())
                } else {
                    value.clone()
                }
            }
        };
        filtered.insert(key.clone(), new_value);
    }
    filtered
}

/// Redact sensitive values in a flat key=value config string.
pub fn filter_config_line(line: &str) -> String {
    // Match lines like: KEY = "value" or KEY = value
    if let Some(eq_pos) = line.find('=') {
        let key = line[..eq_pos].trim();
        let value = line[eq_pos + 1..].trim();
        if is_sensitive_key(key) || is_sensitive_value(value) {
            return format!("{} = {}", key, REDACTED);
        }
    }
    line.to_string()
}

/// Filter all lines in a multi-line config/log string.
pub fn filter_config(text: &str) -> String {
    text.lines()
        .map(filter_config_line)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sensitive_keys() {
        assert!(is_sensitive_key("api_key"));
        assert!(is_sensitive_key("API_KEY"));
        assert!(is_sensitive_key("secret_key"));
        assert!(is_sensitive_key("password"));
        assert!(is_sensitive_key("PASSWD"));
        assert!(is_sensitive_key("access_token"));
        assert!(is_sensitive_key("jwt_secret"));
        assert!(is_sensitive_key("seed_phrase"));
        assert!(is_sensitive_key("mnemonic"));
        assert!(is_sensitive_key("private_key"));
        assert!(is_sensitive_key("db_pass"));
        assert!(is_sensitive_key("database_url"));
        assert!(is_sensitive_key("xprv"));
    }

    #[test]
    fn non_sensitive_keys_pass() {
        assert!(!is_sensitive_key("username"));
        assert!(!is_sensitive_key("email"));
        assert!(!is_sensitive_key("mode"));
        assert!(!is_sensitive_key("enabled"));
        assert!(!is_sensitive_key("log_dir"));
    }

    #[test]
    fn detects_sensitive_values() {
        assert!(is_sensitive_value("sk-proj-abc123def456ghi789"));
        assert!(is_sensitive_value("sk-ant-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(is_sensitive_value("ghp_abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(is_sensitive_value("AKIAIOSFODNN7EXAMPLE"));
        assert!(is_sensitive_value("Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"));
        assert!(is_sensitive_value("-----BEGIN RSA PRIVATE KEY-----"));
    }

    #[test]
    fn filter_value_redacts() {
        assert_eq!(filter_value("api_key", "sk-12345"), REDACTED);
        assert_eq!(filter_value("mode", "PRODUCTION"), "PRODUCTION");
        // Sensitive value regardless of key
        assert_eq!(
            filter_value("some_field", "sk-proj-abc123def456ghi789jklmno"),
            REDACTED
        );
    }

    #[test]
    fn filter_json() {
        let mut obj = serde_json::Map::new();
        obj.insert("api_key".to_string(), serde_json::Value::String("sk-secret".to_string()));
        obj.insert("mode".to_string(), serde_json::Value::String("PRODUCTION".to_string()));
        obj.insert("password".to_string(), serde_json::Value::String("hunter2".to_string()));

        let filtered = filter_json_object(&obj);
        assert_eq!(filtered["api_key"], REDACTED);
        assert_eq!(filtered["mode"], "PRODUCTION");
        assert_eq!(filtered["password"], REDACTED);
    }

    #[test]
    fn filter_nested_json() {
        let json: serde_json::Value = serde_json::from_str(r#"{
            "database": {
                "host": "localhost",
                "password": "secret123"
            },
            "api_key": "sk-test"
        }"#).unwrap();

        if let serde_json::Value::Object(obj) = json {
            let filtered = filter_json_object(&obj);
            assert_eq!(filtered["api_key"], REDACTED);
            let db = filtered["database"].as_object().unwrap();
            assert_eq!(db["host"], "localhost");
            assert_eq!(db["password"], REDACTED);
        }
    }

    #[test]
    fn filter_config_lines() {
        let config = "mode = PRODUCTION\napi_key = sk-secret\nlog_dir = /var/log\npassword = hunter2";
        let filtered = filter_config(config);
        assert!(filtered.contains("mode = PRODUCTION"));
        assert!(filtered.contains(&format!("api_key = {}", REDACTED)));
        assert!(filtered.contains("log_dir = /var/log"));
        assert!(filtered.contains(&format!("password = {}", REDACTED)));
    }
}
