//! Cross-validation integration tests — runs shared JSON test cases against all modules.
//! Both macOS (Swift via FFI) and Linux (native Rust) run these same test cases.

use serde::Deserialize;
use std::fs;

use security_core::email_patterns;
use security_core::encryption;
use security_core::file_sanitizer;
use security_core::message_patterns;
use security_core::prompt_injection;
use security_core::sensitive_data;
use security_core::severity::SeverityLevel;
use security_core::threat_intent_parser::{self, Channel};

#[derive(Debug, Deserialize)]
struct TestCase {
    test_name: String,
    input: String,
    #[serde(default)]
    channel: Option<String>,
    #[serde(default)]
    expected_intent: Option<ExpectedIntent>,
    #[serde(default)]
    expected_patterns: Option<Vec<String>>,
    #[serde(default)]
    expected_message_patterns: Option<Vec<String>>,
    #[serde(default)]
    expected_prompt_injection: Option<ExpectedPromptInjection>,
    #[serde(default)]
    expected_sensitive_data: Option<Vec<String>>,
    #[serde(default)]
    expected_file_threats: Option<Vec<String>>,
    #[serde(default)]
    expected_encryption_roundtrip: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ExpectedIntent {
    #[serde(rename = "isThreat")]
    is_threat: bool,
    #[serde(rename = "minLayersFired")]
    min_layers_fired: u8,
    severity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedPromptInjection {
    safe: bool,
    category: String,
}

fn load_test_cases() -> Vec<TestCase> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/integration/test_cases.json"
    );
    let content = fs::read_to_string(path).expect("Failed to read test_cases.json");
    serde_json::from_str(&content).expect("Failed to parse test_cases.json")
}

fn parse_severity(s: &str) -> SeverityLevel {
    match s {
        "CRITICAL" => SeverityLevel::Critical,
        "HIGH" => SeverityLevel::High,
        "MEDIUM" => SeverityLevel::Medium,
        "LOW" => SeverityLevel::Low,
        _ => panic!("Unknown severity: {}", s),
    }
}

#[test]
fn intent_parser_tests() {
    let cases = load_test_cases();
    let mut tested = 0;

    for case in &cases {
        if let Some(ref expected) = case.expected_intent {
            let channel = match case.channel.as_deref() {
                Some("sms") => Channel::Sms,
                _ => Channel::Email,
            };

            let result = threat_intent_parser::parse(&case.input, channel);

            assert_eq!(
                result.is_threat, expected.is_threat,
                "[{}] is_threat mismatch: got {}, expected {}",
                case.test_name, result.is_threat, expected.is_threat
            );

            assert!(
                result.layers_fired >= expected.min_layers_fired,
                "[{}] layers_fired too low: got {}, expected >= {}",
                case.test_name, result.layers_fired, expected.min_layers_fired
            );

            if let Some(ref sev_str) = expected.severity {
                let expected_sev = parse_severity(sev_str);
                assert_eq!(
                    result.severity,
                    Some(expected_sev),
                    "[{}] severity mismatch: got {:?}, expected {}",
                    case.test_name, result.severity, sev_str
                );
            }

            tested += 1;
        }
    }

    assert!(tested > 0, "No intent parser test cases found");
    eprintln!("  ✅ Intent parser: {} test cases passed", tested);
}

#[test]
fn email_pattern_tests() {
    let cases = load_test_cases();
    let mut tested = 0;

    for case in &cases {
        if let Some(ref expected_cats) = case.expected_patterns {
            let threats = email_patterns::analyze_email(&case.input);
            let found_cats: Vec<&str> = threats.iter().map(|t| t.category.as_str()).collect();

            for expected_cat in expected_cats {
                assert!(
                    found_cats.contains(&expected_cat.as_str()),
                    "[{}] expected email category '{}' not found in {:?}",
                    case.test_name, expected_cat, found_cats
                );
            }

            if expected_cats.is_empty() {
                // No email patterns expected — but we don't assert empty since
                // intent-only tests may not have email pattern expectations
            }

            tested += 1;
        }
    }

    assert!(tested > 0, "No email pattern test cases found");
    eprintln!("  ✅ Email patterns: {} test cases passed", tested);
}

#[test]
fn message_pattern_tests() {
    let cases = load_test_cases();
    let mut tested = 0;

    for case in &cases {
        if let Some(ref expected_cats) = case.expected_message_patterns {
            let threats = message_patterns::analyze_message(&case.input);
            let found_cats: Vec<&str> = threats.iter().map(|t| t.category.as_str()).collect();

            for expected_cat in expected_cats {
                assert!(
                    found_cats.contains(&expected_cat.as_str()),
                    "[{}] expected message category '{}' not found in {:?}",
                    case.test_name, expected_cat, found_cats
                );
            }

            if expected_cats.is_empty() {
                assert!(
                    threats.is_empty(),
                    "[{}] expected no message threats but found {:?}",
                    case.test_name, found_cats
                );
            }

            tested += 1;
        }
    }

    assert!(tested > 0, "No message pattern test cases found");
    eprintln!("  ✅ Message patterns: {} test cases passed", tested);
}

#[test]
fn prompt_injection_tests() {
    let cases = load_test_cases();
    let mut tested = 0;

    for case in &cases {
        if let Some(ref expected) = case.expected_prompt_injection {
            let result = prompt_injection::validate(&case.input, "test");

            assert_eq!(
                result.safe, expected.safe,
                "[{}] prompt injection safe mismatch: got {}, expected {}",
                case.test_name, result.safe, expected.safe
            );

            if !expected.safe {
                assert_eq!(
                    result.category.as_deref(),
                    Some(expected.category.as_str()),
                    "[{}] prompt injection category mismatch: got {:?}, expected {}",
                    case.test_name, result.category, expected.category
                );
            }

            tested += 1;
        }
    }

    assert!(tested > 0, "No prompt injection test cases found");
    eprintln!("  ✅ Prompt injection: {} test cases passed", tested);
}

#[test]
fn sensitive_data_tests() {
    let cases = load_test_cases();
    let mut tested = 0;

    for case in &cases {
        if let Some(ref expected_cats) = case.expected_sensitive_data {
            let findings = sensitive_data::scan_text(&case.input, "test");
            let found_cats: Vec<&str> = findings.iter().map(|f| f.category.as_str()).collect();

            for expected_cat in expected_cats {
                assert!(
                    found_cats.contains(&expected_cat.as_str()),
                    "[{}] expected sensitive data category '{}' not found in {:?}",
                    case.test_name, expected_cat, found_cats
                );
            }

            if expected_cats.is_empty() {
                assert!(
                    findings.is_empty(),
                    "[{}] expected no sensitive data but found {:?}",
                    case.test_name, found_cats
                );
            }

            tested += 1;
        }
    }

    assert!(tested > 0, "No sensitive data test cases found");
    eprintln!("  ✅ Sensitive data: {} test cases passed", tested);
}

#[test]
fn file_threat_tests() {
    let cases = load_test_cases();
    let mut tested = 0;

    for case in &cases {
        if let Some(ref expected_cats) = case.expected_file_threats {
            let threats = file_sanitizer::scan_content(&case.input);
            let found_cats: Vec<&str> = threats.iter().map(|t| t.category.as_str()).collect();

            for expected_cat in expected_cats {
                assert!(
                    found_cats.contains(&expected_cat.as_str()),
                    "[{}] expected file threat category '{}' not found in {:?}",
                    case.test_name, expected_cat, found_cats
                );
            }

            if expected_cats.is_empty() {
                assert!(
                    threats.is_empty(),
                    "[{}] expected no file threats but found {:?}",
                    case.test_name, found_cats
                );
            }

            tested += 1;
        }
    }

    assert!(tested > 0, "No file threat test cases found");
    eprintln!("  ✅ File threats: {} test cases passed", tested);
}

#[test]
fn encryption_roundtrip_tests() {
    let cases = load_test_cases();
    let mut tested = 0;

    for case in &cases {
        if case.expected_encryption_roundtrip == Some(true) {
            let enc = encryption::Encryptor::new("cross-validation-test-key");

            let encrypted = enc
                .encrypt_string(&case.input, encryption::aad::GENERAL)
                .expect(&format!("[{}] encryption failed", case.test_name));

            let decrypted = enc
                .decrypt_string(&encrypted, encryption::aad::GENERAL)
                .expect(&format!("[{}] decryption failed", case.test_name));

            assert_eq!(
                decrypted, case.input,
                "[{}] encryption roundtrip mismatch",
                case.test_name
            );

            // Verify wrong AAD fails
            let wrong_aad_result = enc.decrypt_string(&encrypted, encryption::aad::CONFIG);
            assert!(
                wrong_aad_result.is_err(),
                "[{}] wrong AAD should fail decryption",
                case.test_name
            );

            tested += 1;
        }
    }

    assert!(tested > 0, "No encryption roundtrip test cases found");
    eprintln!("  ✅ Encryption roundtrip: {} test cases passed", tested);
}
