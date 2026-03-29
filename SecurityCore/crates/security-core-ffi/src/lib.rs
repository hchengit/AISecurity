//! C ABI FFI layer for security-core.
//!
//! All functions use `#[no_mangle] pub extern "C"` for stable ABI.
//! Callers must free returned pointers via the corresponding `sec_free_*` function.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use security_core::email_patterns;
use security_core::file_sanitizer;
use security_core::message_patterns;
use security_core::prompt_injection;
use security_core::sensitive_data;
use security_core::severity::SeverityLevel;
use security_core::threat_intent_parser::{self, Channel};

// ---------------------------------------------------------------------------
// FFI result types
// ---------------------------------------------------------------------------

/// FFI-safe intent analysis result.
#[repr(C)]
pub struct IntentResultFFI {
    pub is_threat: bool,
    pub severity: i8, // -1 = none, 1..4 = Low..Critical
    pub layers_fired: u8,
    pub l1: bool,
    pub l2: bool,
    pub l3: bool,
    pub l4: bool,
    pub l5: bool,
    pub l6: bool,
    pub label: *mut c_char,
    pub confidence: *mut c_char,
}

/// FFI-safe findings array.
#[repr(C)]
pub struct FindingsArrayFFI {
    pub items: *mut FindingFFI,
    pub count: u32,
}

/// FFI-safe single finding.
#[repr(C)]
pub struct FindingFFI {
    pub finding_type: *mut c_char,
    pub label: *mut c_char,
    pub severity: i8,
    pub category: *mut c_char,
    pub source: *mut c_char,
    pub match_preview: *mut c_char,
    pub offset: u32,
}

/// FFI-safe validation result.
#[repr(C)]
pub struct ValidationResultFFI {
    pub safe: bool,
    pub reason: *mut c_char,   // null if safe
    pub severity: i8,          // -1 = none
    pub category: *mut c_char, // null if safe
}

/// FFI-safe sanitization result.
#[repr(C)]
pub struct SanitizationResultFFI {
    pub sanitized: *mut c_char,
    pub modified: bool,
    pub changes_json: *mut c_char, // JSON array of strings
}

/// FFI-safe threats array (for file/email/message scanning).
#[repr(C)]
pub struct ThreatsArrayFFI {
    pub items: *mut ThreatFFI,
    pub count: u32,
}

/// FFI-safe single threat.
#[repr(C)]
pub struct ThreatFFI {
    pub threat_type: *mut c_char,
    pub label: *mut c_char,
    pub severity: i8,
    pub category: *mut c_char,
}

/// FFI-safe whitelist scan policy.
#[repr(C)]
pub struct ScanPolicyFFI {
    pub is_whitelisted: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn severity_to_i8(s: Option<SeverityLevel>) -> i8 {
    match s {
        Some(SeverityLevel::Low) => 1,
        Some(SeverityLevel::Medium) => 2,
        Some(SeverityLevel::High) => 3,
        Some(SeverityLevel::Critical) => 4,
        None => -1,
    }
}

fn to_c_string(s: &str) -> *mut c_char {
    CString::new(s).map(|c| c.into_raw()).unwrap_or(ptr::null_mut())
}

unsafe fn from_c_str(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

/// Initialize with an optional config path. Returns true on success.
#[no_mangle]
pub extern "C" fn sec_init(config_path: *const c_char) -> bool {
    let _path = unsafe { from_c_str(config_path) };
    // Config loading is deferred to callers who need it.
    // This ensures the lazy statics get warmed up.
    let _ = threat_intent_parser::parse("warmup", Channel::Email);
    true
}

// ---------------------------------------------------------------------------
// Intent Parser
// ---------------------------------------------------------------------------

/// 7-layer intent analysis. Caller must free with sec_free_intent_result.
#[no_mangle]
pub extern "C" fn sec_parse_intent(text: *const c_char, channel: u8) -> *mut IntentResultFFI {
    let text = match unsafe { from_c_str(text) } {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let ch = if channel == 1 { Channel::Sms } else { Channel::Email };
    let r = threat_intent_parser::parse(&text, ch);

    Box::into_raw(Box::new(IntentResultFFI {
        is_threat: r.is_threat,
        severity: severity_to_i8(r.severity),
        layers_fired: r.layers_fired,
        l1: r.layers.l1,
        l2: r.layers.l2,
        l3: r.layers.l3,
        l4: r.layers.l4,
        l5: r.layers.l5,
        l6: r.layers.l6,
        label: to_c_string(&r.label),
        confidence: to_c_string(&r.confidence),
    }))
}

// ---------------------------------------------------------------------------
// Sensitive Data Scanner
// ---------------------------------------------------------------------------

/// Scan text for sensitive data. Caller must free with sec_free_findings.
#[no_mangle]
pub extern "C" fn sec_scan_sensitive_data(
    text: *const c_char,
    source: *const c_char,
) -> *mut FindingsArrayFFI {
    let text = match unsafe { from_c_str(text) } {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let source = unsafe { from_c_str(source) }.unwrap_or_else(|| "ffi".to_string());
    let findings = sensitive_data::scan_text(&text, &source);

    let items: Vec<FindingFFI> = findings
        .iter()
        .map(|f| FindingFFI {
            finding_type: to_c_string(&f.finding_type),
            label: to_c_string(&f.label),
            severity: severity_to_i8(Some(f.severity)),
            category: to_c_string(&f.category),
            source: to_c_string(&f.source),
            match_preview: to_c_string(&f.match_preview),
            offset: f.offset as u32,
        })
        .collect();

    let count = items.len() as u32;
    let items_ptr = if items.is_empty() {
        ptr::null_mut()
    } else {
        let mut boxed = items.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        std::mem::forget(boxed);
        ptr
    };

    Box::into_raw(Box::new(FindingsArrayFFI {
        items: items_ptr,
        count,
    }))
}

// ---------------------------------------------------------------------------
// Prompt Injection Validator
// ---------------------------------------------------------------------------

/// Validate text for prompt injection. Caller must free with sec_free_validation_result.
#[no_mangle]
pub extern "C" fn sec_validate_prompt(
    text: *const c_char,
    source: *const c_char,
) -> *mut ValidationResultFFI {
    let text = match unsafe { from_c_str(text) } {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let source = unsafe { from_c_str(source) }.unwrap_or_else(|| "ffi".to_string());
    let r = prompt_injection::validate(&text, &source);

    Box::into_raw(Box::new(ValidationResultFFI {
        safe: r.safe,
        reason: r.reason.as_deref().map(to_c_string).unwrap_or(ptr::null_mut()),
        severity: severity_to_i8(r.severity),
        category: r.category.as_deref().map(to_c_string).unwrap_or(ptr::null_mut()),
    }))
}

/// Sanitize text. Caller must free with sec_free_sanitization_result.
#[no_mangle]
pub extern "C" fn sec_sanitize_text(text: *const c_char) -> *mut SanitizationResultFFI {
    let text = match unsafe { from_c_str(text) } {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let r = prompt_injection::sanitize(&text);
    let changes_json = serde_json::to_string(&r.changes).unwrap_or_else(|_| "[]".to_string());

    Box::into_raw(Box::new(SanitizationResultFFI {
        sanitized: to_c_string(&r.sanitized),
        modified: r.modified,
        changes_json: to_c_string(&changes_json),
    }))
}

// ---------------------------------------------------------------------------
// File Sanitizer
// ---------------------------------------------------------------------------

/// Scan file content for threats. Caller must free with sec_free_threats.
#[no_mangle]
pub extern "C" fn sec_scan_file_content(text: *const c_char) -> *mut ThreatsArrayFFI {
    let text = match unsafe { from_c_str(text) } {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let threats = file_sanitizer::scan_content(&text);
    threats_to_ffi(threats.iter().map(|t| (&t.threat_type, &t.label, t.severity, &t.category)))
}

// ---------------------------------------------------------------------------
// Email Analyzer
// ---------------------------------------------------------------------------

/// Analyze email text for threats. Caller must free with sec_free_threats.
#[no_mangle]
pub extern "C" fn sec_analyze_email(text: *const c_char) -> *mut ThreatsArrayFFI {
    let text = match unsafe { from_c_str(text) } {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let threats = email_patterns::analyze_email(&text);
    threats_to_ffi(threats.iter().map(|t| (&t.threat_type, &t.label, t.severity, &t.category)))
}

// ---------------------------------------------------------------------------
// Message Analyzer
// ---------------------------------------------------------------------------

/// Analyze message text for threats. Caller must free with sec_free_threats.
#[no_mangle]
pub extern "C" fn sec_analyze_message(text: *const c_char) -> *mut ThreatsArrayFFI {
    let text = match unsafe { from_c_str(text) } {
        Some(t) => t,
        None => return ptr::null_mut(),
    };
    let threats = message_patterns::analyze_message(&text);
    threats_to_ffi(threats.iter().map(|t| (&t.threat_type, &t.label, t.severity, &t.category)))
}

// ---------------------------------------------------------------------------
// Whitelist (stateless policy check — state managed by caller)
// ---------------------------------------------------------------------------

/// Check scan policy. Always returns a valid pointer. Free with sec_free_scan_policy.
#[no_mangle]
pub extern "C" fn sec_whitelist_check(_sender: *const c_char) -> *mut ScanPolicyFFI {
    // Stateless — whitelist state is managed by the platform shell.
    // This just returns not-whitelisted so all categories fire.
    Box::into_raw(Box::new(ScanPolicyFFI {
        is_whitelisted: false,
    }))
}

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn sec_free_intent_result(ptr: *mut IntentResultFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let r = Box::from_raw(ptr);
        free_c_string(r.label);
        free_c_string(r.confidence);
    }
}

#[no_mangle]
pub extern "C" fn sec_free_findings(ptr: *mut FindingsArrayFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let arr = Box::from_raw(ptr);
        if !arr.items.is_null() && arr.count > 0 {
            let items = Vec::from_raw_parts(arr.items, arr.count as usize, arr.count as usize);
            for item in items {
                free_c_string(item.finding_type);
                free_c_string(item.label);
                free_c_string(item.category);
                free_c_string(item.source);
                free_c_string(item.match_preview);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn sec_free_validation_result(ptr: *mut ValidationResultFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let r = Box::from_raw(ptr);
        free_c_string(r.reason);
        free_c_string(r.category);
    }
}

#[no_mangle]
pub extern "C" fn sec_free_sanitization_result(ptr: *mut SanitizationResultFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let r = Box::from_raw(ptr);
        free_c_string(r.sanitized);
        free_c_string(r.changes_json);
    }
}

#[no_mangle]
pub extern "C" fn sec_free_threats(ptr: *mut ThreatsArrayFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let arr = Box::from_raw(ptr);
        if !arr.items.is_null() && arr.count > 0 {
            let items = Vec::from_raw_parts(arr.items, arr.count as usize, arr.count as usize);
            for item in items {
                free_c_string(item.threat_type);
                free_c_string(item.label);
                free_c_string(item.category);
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn sec_free_scan_policy(ptr: *mut ScanPolicyFFI) {
    if ptr.is_null() { return; }
    unsafe { drop(Box::from_raw(ptr)); }
}

unsafe fn free_c_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { CString::from_raw(ptr) });
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn threats_to_ffi<'a>(
    iter: impl Iterator<Item = (&'a String, &'a String, SeverityLevel, &'a String)>,
) -> *mut ThreatsArrayFFI {
    let items: Vec<ThreatFFI> = iter
        .map(|(t, l, s, c)| ThreatFFI {
            threat_type: to_c_string(t),
            label: to_c_string(l),
            severity: severity_to_i8(Some(s)),
            category: to_c_string(c),
        })
        .collect();

    let count = items.len() as u32;
    let items_ptr = if items.is_empty() {
        ptr::null_mut()
    } else {
        let mut boxed = items.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        std::mem::forget(boxed);
        ptr
    };

    Box::into_raw(Box::new(ThreatsArrayFFI {
        items: items_ptr,
        count,
    }))
}
