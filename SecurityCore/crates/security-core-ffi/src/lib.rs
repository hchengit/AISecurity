//! C ABI FFI layer for security-core.
//!
//! All functions use `#[no_mangle] pub extern "C"` for stable ABI.
//! Callers must free returned pointers via the corresponding `sec_free_*` function.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use security_core::command_policy;
use security_core::config::{self, ProtectionTier, SecurityConfig};
use security_core::threat_feeds;
use security_core::package_vulns;
use security_core::email_patterns;
use security_core::local_services::{self, ServiceOptions};
use security_core::model_verifier;
use security_core::policy_audit::PolicyAuditLog;
use security_core::vault;
use security_core::file_sanitizer;
use security_core::message_patterns;
use security_core::prompt_injection;
use security_core::sensitive_data;
use security_core::severity::SeverityLevel;
use security_core::threat_intent_parser::{self, Channel};

use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// FFI result types
// ---------------------------------------------------------------------------

/// FFI-safe intent analysis result.
#[repr(C)]
pub struct IntentResultFFI {
    pub is_threat: bool,
    pub severity: i8, // -1 = none, 1..4 = Low..Critical
    pub layers_fired: u8,
    pub score: u32, // weighted score out of 100
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
        score: r.score,
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

/// Analyze an attachment's leading bytes vs. its filename for a disguised executable (magic-byte
/// true-type check). `prefix`/`len` describe a byte buffer (a small prefix is sufficient). Caller
/// must free with sec_free_threats.
#[no_mangle]
pub extern "C" fn sec_analyze_attachment_structure(
    prefix: *const u8,
    len: usize,
    filename: *const c_char,
) -> *mut ThreatsArrayFFI {
    let filename = match unsafe { from_c_str(filename) } {
        Some(f) => f,
        None => return ptr::null_mut(),
    };
    let bytes: &[u8] = if prefix.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(prefix, len) }
    };
    let threats = file_sanitizer::analyze_attachment_structure(bytes, &filename);
    threats_to_ffi(threats.iter().map(|t| (&t.threat_type, &t.label, t.severity, &t.category)))
}

/// Inspect a container attachment (Office OOXML doc or ZIP archive) for a disguised macro document,
/// dangerous archive contents, or an encrypted archive — by reading ZIP entry metadata only (no
/// decompression). `prefix`/`len` describe a byte buffer (a bounded prefix is sufficient). Caller
/// must free with sec_free_threats.
#[no_mangle]
pub extern "C" fn sec_analyze_container(
    prefix: *const u8,
    len: usize,
    filename: *const c_char,
) -> *mut ThreatsArrayFFI {
    let filename = match unsafe { from_c_str(filename) } {
        Some(f) => f,
        None => return ptr::null_mut(),
    };
    let bytes: &[u8] = if prefix.is_null() || len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(prefix, len) }
    };
    let threats = file_sanitizer::analyze_container(bytes, &filename);
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
// Vault
// ---------------------------------------------------------------------------

/// FFI-safe vault operation result.
#[repr(C)]
pub struct VaultResultFFI {
    pub success: bool,
    pub message: *mut c_char,
    pub entries_affected: u32,
}

/// FFI-safe vault entry.
#[repr(C)]
pub struct VaultEntryFFI {
    pub original_path: *mut c_char,
    pub vault_path: *mut c_char,
    pub protection: u8, // 0=locked, 1=read_only, 2=local_only, 3=read_only_local, 4=locked_local
    pub encrypted_at: *mut c_char,
    pub size_bytes: u64,
    pub is_directory: bool,
    pub is_unlocked: bool,
}

/// FFI-safe vault entry array.
#[repr(C)]
pub struct VaultEntryArrayFFI {
    pub items: *mut VaultEntryFFI,
    pub count: u32,
}

fn protection_to_u8(p: vault::ProtectionLevel) -> u8 {
    match p {
        vault::ProtectionLevel::Locked => 0,
        vault::ProtectionLevel::ReadOnly => 1,
        vault::ProtectionLevel::LocalOnly => 2,
        vault::ProtectionLevel::ReadOnlyLocal => 3,
        vault::ProtectionLevel::LockedLocal => 4,
    }
}

fn u8_to_protection(v: u8) -> vault::ProtectionLevel {
    match v {
        1 => vault::ProtectionLevel::ReadOnly,
        2 => vault::ProtectionLevel::LocalOnly,
        3 => vault::ProtectionLevel::ReadOnlyLocal,
        4 => vault::ProtectionLevel::LockedLocal,
        _ => vault::ProtectionLevel::Locked,
    }
}

/// Check if vault has been set up.
#[no_mangle]
pub extern "C" fn sec_vault_is_setup(security_dir: *const c_char) -> bool {
    let dir = match unsafe { from_c_str(security_dir) } {
        Some(d) => d,
        None => return false,
    };
    vault::Vault::new(&dir).is_setup()
}

/// First-time vault setup — generates salt, creates manifest, writes recovery file.
#[no_mangle]
pub extern "C" fn sec_vault_setup(security_dir: *const c_char) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    let v = vault::Vault::new(&dir);
    match v.setup() {
        Ok(()) => Box::into_raw(Box::new(VaultResultFFI {
            success: true,
            message: to_c_string("Vault setup complete"),
            entries_affected: 0,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false,
            message: to_c_string(&format!("{}", e)),
            entries_affected: 0,
        })),
    }
}

/// Set the initial vault passphrase (first-time only).
#[no_mangle]
pub extern "C" fn sec_vault_set_passphrase(
    security_dir: *const c_char,
    passphrase: *const c_char,
) -> bool {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return false };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return false };
    vault::Vault::new(&dir).set_initial_passphrase(&pass).is_ok()
}

/// Verify vault passphrase.
#[no_mangle]
pub extern "C" fn sec_vault_verify_passphrase(
    security_dir: *const c_char,
    passphrase: *const c_char,
) -> bool {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return false };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return false };
    vault::Vault::new(&dir).verify_passphrase(&pass).unwrap_or(false)
}

/// Add files to vault. `paths` is a colon-separated list. `protection`: 0=locked, 1=read_only, 2=local_only, 3=read_only_local, 4=locked_local.
#[no_mangle]
pub extern "C" fn sec_vault_add(
    security_dir: *const c_char,
    paths: *const c_char,
    protection: u8,
    passphrase: *const c_char,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let paths_str = match unsafe { from_c_str(paths) } { Some(p) => p, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let path_list: Vec<&str> = paths_str.split('\n').collect();
    let prot = u8_to_protection(protection);
    let v = vault::Vault::new(&dir);

    match v.add(&path_list, prot, &pass) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success,
            message: to_c_string(&r.message),
            entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false,
            message: to_c_string(&format!("{}", e)),
            entries_affected: 0,
        })),
    }
}

/// Unlock (decrypt) vault entries. `paths` is colon-separated.
#[no_mangle]
pub extern "C" fn sec_vault_unlock(
    security_dir: *const c_char,
    paths: *const c_char,
    passphrase: *const c_char,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let paths_str = match unsafe { from_c_str(paths) } { Some(p) => p, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let path_list: Vec<&str> = paths_str.split('\n').collect();
    let v = vault::Vault::new(&dir);

    match v.unlock(&path_list, &pass) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success, message: to_c_string(&r.message), entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false, message: to_c_string(&format!("{}", e)), entries_affected: 0,
        })),
    }
}

/// Lock (re-encrypt) previously unlocked entries. `paths` is colon-separated.
#[no_mangle]
pub extern "C" fn sec_vault_lock(
    security_dir: *const c_char,
    paths: *const c_char,
    passphrase: *const c_char,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let paths_str = match unsafe { from_c_str(paths) } { Some(p) => p, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let path_list: Vec<&str> = paths_str.split('\n').collect();
    let v = vault::Vault::new(&dir);

    match v.lock(&path_list, &pass) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success, message: to_c_string(&r.message), entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false, message: to_c_string(&format!("{}", e)), entries_affected: 0,
        })),
    }
}

/// Remove entries from vault (decrypt and restore). `paths` is colon-separated.
#[no_mangle]
pub extern "C" fn sec_vault_remove(
    security_dir: *const c_char,
    paths: *const c_char,
    passphrase: *const c_char,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let paths_str = match unsafe { from_c_str(paths) } { Some(p) => p, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let path_list: Vec<&str> = paths_str.split('\n').collect();
    let v = vault::Vault::new(&dir);

    match v.remove(&path_list, &pass) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success, message: to_c_string(&r.message), entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false, message: to_c_string(&format!("{}", e)), entries_affected: 0,
        })),
    }
}

/// List all vault entries.
#[no_mangle]
pub extern "C" fn sec_vault_list(
    security_dir: *const c_char,
    passphrase: *const c_char,
) -> *mut VaultEntryArrayFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let v = vault::Vault::new(&dir);
    let entries = match v.list(&pass) {
        Ok(e) => e,
        Err(_) => return ptr::null_mut(),
    };

    let items: Vec<VaultEntryFFI> = entries.iter().map(|e| VaultEntryFFI {
        original_path: to_c_string(&e.original_path),
        vault_path: to_c_string(&e.vault_path),
        protection: protection_to_u8(e.protection),
        encrypted_at: to_c_string(&e.encrypted_at),
        size_bytes: e.size_bytes,
        is_directory: e.is_directory,
        is_unlocked: e.is_unlocked,
    }).collect();

    let count = items.len() as u32;
    let items_ptr = if items.is_empty() {
        ptr::null_mut()
    } else {
        let mut boxed = items.into_boxed_slice();
        let p = boxed.as_mut_ptr();
        std::mem::forget(boxed);
        p
    };

    Box::into_raw(Box::new(VaultEntryArrayFFI { items: items_ptr, count }))
}

/// Change vault passphrase.
#[no_mangle]
pub extern "C" fn sec_vault_change_passphrase(
    security_dir: *const c_char,
    old_passphrase: *const c_char,
    new_passphrase: *const c_char,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let old_pass = match unsafe { from_c_str(old_passphrase) } { Some(p) => p, None => return ptr::null_mut() };
    let new_pass = match unsafe { from_c_str(new_passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let v = vault::Vault::new(&dir);
    match v.change_passphrase(&old_pass, &new_pass) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success, message: to_c_string(&r.message), entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false, message: to_c_string(&format!("{}", e)), entries_affected: 0,
        })),
    }
}

/// Change protection level of vault entries. `paths` is newline-separated.
/// `new_protection`: 0=locked, 1=read_only, 2=local_only, 3=read_only_local, 4=locked_local.
#[no_mangle]
pub extern "C" fn sec_vault_change_protection(
    security_dir: *const c_char,
    paths: *const c_char,
    new_protection: u8,
    passphrase: *const c_char,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let paths_str = match unsafe { from_c_str(paths) } { Some(p) => p, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let path_list: Vec<&str> = paths_str.split('\n').collect();
    let prot = u8_to_protection(new_protection);
    let v = vault::Vault::new(&dir);

    match v.change_protection(&path_list, prot, &pass) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success, message: to_c_string(&r.message), entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false, message: to_c_string(&format!("{}", e)), entries_affected: 0,
        })),
    }
}

/// Toggle local-only monitoring on vault entries. `paths` is newline-separated.
#[no_mangle]
pub extern "C" fn sec_vault_toggle_local_only(
    security_dir: *const c_char,
    paths: *const c_char,
    passphrase: *const c_char,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let paths_str = match unsafe { from_c_str(paths) } { Some(p) => p, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let path_list: Vec<&str> = paths_str.split('\n').collect();
    let v = vault::Vault::new(&dir);

    match v.toggle_local_only(&path_list, &pass) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success, message: to_c_string(&r.message), entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false, message: to_c_string(&format!("{}", e)), entries_affected: 0,
        })),
    }
}

/// Progress callback type for batch vault operations.
/// Returns true to continue, false to cancel.
pub type VaultProgressCallback = extern "C" fn(
    current: u32,
    total: u32,
    current_path: *const c_char,
    user_data: *mut std::ffi::c_void,
) -> bool;

/// Add files to vault with progress callback and cancellation support.
/// `paths` is newline-separated.
#[no_mangle]
pub extern "C" fn sec_vault_add_with_progress(
    security_dir: *const c_char,
    paths: *const c_char,
    protection: u8,
    passphrase: *const c_char,
    callback: VaultProgressCallback,
    user_data: *mut std::ffi::c_void,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let paths_str = match unsafe { from_c_str(paths) } { Some(p) => p, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let path_list: Vec<&str> = paths_str.split('\n').collect();
    let prot = u8_to_protection(protection);
    let v = vault::Vault::new(&dir);

    match v.add_with_progress(&path_list, prot, &pass, |current, total, path| {
        let c_path = to_c_string(path);
        let cont = callback(current, total, c_path, user_data);
        unsafe { free_c_string(c_path); }
        cont
    }) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success, message: to_c_string(&r.message), entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false, message: to_c_string(&format!("{}", e)), entries_affected: 0,
        })),
    }
}

/// Update a vault entry's path after a file move.
#[no_mangle]
pub extern "C" fn sec_vault_update_path(
    security_dir: *const c_char,
    old_path: *const c_char,
    new_path: *const c_char,
    passphrase: *const c_char,
) -> *mut VaultResultFFI {
    let dir = match unsafe { from_c_str(security_dir) } { Some(d) => d, None => return ptr::null_mut() };
    let old = match unsafe { from_c_str(old_path) } { Some(p) => p, None => return ptr::null_mut() };
    let new = match unsafe { from_c_str(new_path) } { Some(p) => p, None => return ptr::null_mut() };
    let pass = match unsafe { from_c_str(passphrase) } { Some(p) => p, None => return ptr::null_mut() };

    let v = vault::Vault::new(&dir);

    match v.update_entry_path(&old, &new, &pass) {
        Ok(r) => Box::into_raw(Box::new(VaultResultFFI {
            success: r.success, message: to_c_string(&r.message), entries_affected: r.entries_affected as u32,
        })),
        Err(e) => Box::into_raw(Box::new(VaultResultFFI {
            success: false, message: to_c_string(&format!("{}", e)), entries_affected: 0,
        })),
    }
}

/// Free a VaultResultFFI.
#[no_mangle]
pub extern "C" fn sec_free_vault_result(ptr: *mut VaultResultFFI) {
    if ptr.is_null() { return; }
    unsafe { let r = Box::from_raw(ptr); free_c_string(r.message); }
}

/// Free a VaultEntryArrayFFI.
#[no_mangle]
pub extern "C" fn sec_free_vault_entries(ptr: *mut VaultEntryArrayFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let arr = Box::from_raw(ptr);
        if !arr.items.is_null() && arr.count > 0 {
            let items = Vec::from_raw_parts(arr.items, arr.count as usize, arr.count as usize);
            for item in items {
                free_c_string(item.original_path);
                free_c_string(item.vault_path);
                free_c_string(item.encrypted_at);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Encryption helpers (for Swift-side encrypted storage)
// ---------------------------------------------------------------------------

/// Install the process-global master key. `hex` must be the hex encoding of
/// exactly 32 random bytes sourced from the macOS Keychain.
/// Returns true on success. Once set, subsequent calls are no-ops (idempotent).
#[no_mangle]
pub extern "C" fn sec_set_master_key(hex: *const c_char) -> bool {
    let hex = match unsafe { from_c_str(hex) } {
        Some(h) => h,
        None => return false,
    };
    // Decode hex to bytes.
    if !hex.len().is_multiple_of(2) || hex.len() != 64 {
        return false;
    }
    let mut bytes = Vec::with_capacity(32);
    for i in (0..hex.len()).step_by(2) {
        match u8::from_str_radix(&hex[i..i + 2], 16) {
            Ok(b) => bytes.push(b),
            Err(_) => return false,
        }
    }
    security_core::encryption::set_master_key(&bytes)
}

/// True iff the master key has already been installed.
#[no_mangle]
pub extern "C" fn sec_has_master_key() -> bool {
    security_core::encryption::has_master_key()
}

/// Encrypt a JSON string with the WHITELIST AAD tag. Returns hex string.
/// Caller must free with sec_free_string.
/// Returns null if the master key has not been installed — callers must NOT
/// fall back to plaintext storage.
#[no_mangle]
pub extern "C" fn sec_encrypt_whitelist(json: *const c_char) -> *mut c_char {
    let json = match unsafe { from_c_str(json) } {
        Some(j) => j,
        None => return ptr::null_mut(),
    };
    let enc = match security_core::encryption::Encryptor::from_master_key() {
        Ok(e) => e,
        Err(_) => return ptr::null_mut(),
    };
    match enc.encrypt_string(&json, security_core::encryption::aad::WHITELIST) {
        Ok(hex) => to_c_string(&hex),
        Err(_) => ptr::null_mut(),
    }
}

/// Decrypt a hex string with the WHITELIST AAD tag. Returns JSON string.
/// Caller must free with sec_free_string.
#[no_mangle]
pub extern "C" fn sec_decrypt_whitelist(hex: *const c_char) -> *mut c_char {
    let hex = match unsafe { from_c_str(hex) } {
        Some(h) => h,
        None => return ptr::null_mut(),
    };
    let enc = match security_core::encryption::Encryptor::from_master_key() {
        Ok(e) => e,
        Err(_) => return ptr::null_mut(),
    };
    match enc.decrypt_string(&hex, security_core::encryption::aad::WHITELIST) {
        Ok(json) => to_c_string(&json),
        Err(_) => ptr::null_mut(),
    }
}

/// ONE-SHOT MIGRATION ONLY: decrypt a whitelist blob that was encrypted with
/// the legacy default-passphrase key (pre-master-key versions of the app).
/// Swift calls this when normal decryption fails, then re-encrypts with the
/// new master key. Will be removed in a future version.
#[no_mangle]
pub extern "C" fn sec_decrypt_whitelist_legacy(hex: *const c_char) -> *mut c_char {
    let hex = match unsafe { from_c_str(hex) } {
        Some(h) => h,
        None => return ptr::null_mut(),
    };
    let enc = security_core::encryption::Encryptor::legacy_default();
    match enc.decrypt_string(&hex, security_core::encryption::aad::WHITELIST) {
        Ok(json) => to_c_string(&json),
        Err(_) => ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Command Policy Engine
// ---------------------------------------------------------------------------

/// FFI-safe command check result.
#[repr(C)]
pub struct CommandCheckResultFFI {
    pub decision: i8,          // 0=allow, 1=deny, 2=ask
    pub reason: *mut c_char,
    pub matched_rule: *mut c_char,
}

/// Check a command against the policy. Caller must free with sec_free_command_check.
#[no_mangle]
pub extern "C" fn sec_command_check(
    command: *const c_char,
    config_path: *const c_char,
) -> *mut CommandCheckResultFFI {
    let command = match unsafe { from_c_str(command) } {
        Some(c) => c,
        None => return ptr::null_mut(),
    };
    let config = match unsafe { from_c_str(config_path) } {
        Some(p) => SecurityConfig::load_or_default(&p),
        None => SecurityConfig::default(),
    };

    let result = command_policy::check_command(&command, &config.command_policy);
    let decision = match result.decision {
        command_policy::Decision::Allow => 0i8,
        command_policy::Decision::Deny => 1i8,
        command_policy::Decision::Ask => 2i8,
    };

    Box::into_raw(Box::new(CommandCheckResultFFI {
        decision,
        reason: to_c_string(&result.reason),
        matched_rule: to_c_string(&result.matched_rule),
    }))
}

/// Free a CommandCheckResultFFI.
#[no_mangle]
pub extern "C" fn sec_free_command_check(ptr: *mut CommandCheckResultFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let r = Box::from_raw(ptr);
        free_c_string(r.reason);
        free_c_string(r.matched_rule);
    }
}

// ---------------------------------------------------------------------------
// Model Weight Verifier
// ---------------------------------------------------------------------------

/// Verify all tracked model files. Returns JSON array of results.
/// Uses effective paths: discovered + default + user-configured.
/// Caller must free with sec_free_string.
#[no_mangle]
pub extern "C" fn sec_model_verify(security_dir: *const c_char) -> *mut c_char {
    let dir = match unsafe { from_c_str(security_dir) } {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    let config = SecurityConfig::load_or_default(
        &format!("{}/config.toml", dir),
    );
    let paths = model_verifier::effective_model_paths(&dir, &config.model_verification.paths);
    let results = model_verifier::verify_models(&dir, &paths);
    serde_json::to_string(&results)
        .map(|s| to_c_string(&s))
        .unwrap_or(ptr::null_mut())
}

/// Discover model directories by scanning home + /Volumes/.
/// Returns JSON array of directory paths. Caller must free with sec_free_string.
#[no_mangle]
pub extern "C" fn sec_model_discover_dirs(security_dir: *const c_char) -> *mut c_char {
    let dir = match unsafe { from_c_str(security_dir) } {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    let dirs = model_verifier::discover_model_directories();
    let _ = model_verifier::save_discovered_dirs(&dir, &dirs);
    serde_json::to_string(&dirs)
        .map(|s| to_c_string(&s))
        .unwrap_or(ptr::null_mut())
}

/// Scan for model files and return JSON array of discovered paths.
/// Caller must free with sec_free_string.
#[no_mangle]
pub extern "C" fn sec_model_scan(security_dir: *const c_char) -> *mut c_char {
    let dir = match unsafe { from_c_str(security_dir) } {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    let config = SecurityConfig::load_or_default(
        &format!("{}/config.toml", dir),
    );
    let paths = if config.model_verification.paths.is_empty() {
        model_verifier::default_model_paths()
    } else {
        config.model_verification.paths.clone()
    };
    let found = model_verifier::scan_model_directories(&paths);
    serde_json::to_string(&found)
        .map(|s| to_c_string(&s))
        .unwrap_or(ptr::null_mut())
}

// ---------------------------------------------------------------------------
// Policy Audit Log
// ---------------------------------------------------------------------------

/// Log a policy decision. entry_json is a JSON string of PolicyDecision.
/// Returns true on success.
#[no_mangle]
pub extern "C" fn sec_audit_log(
    security_dir: *const c_char,
    entry_json: *const c_char,
) -> bool {
    let dir = match unsafe { from_c_str(security_dir) } {
        Some(d) => d,
        None => return false,
    };
    let json = match unsafe { from_c_str(entry_json) } {
        Some(j) => j,
        None => return false,
    };
    let entry: PolicyAuditLog = PolicyAuditLog::new(&dir);
    if let Ok(decision) = serde_json::from_str::<security_core::policy_audit::PolicyDecision>(&json) {
        entry.log(&decision).is_ok()
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Threat Intelligence Feeds
// ---------------------------------------------------------------------------

/// FFI-safe feed check result.
#[repr(C)]
pub struct FeedCheckResultFFI {
    pub threat_level: i8, // -1 = no match, 1-4 = Low..Critical
    pub feed_name: *mut c_char,  // null if no match
    pub indicator: *mut c_char,  // null if no match
}

/// Initialize threat feeds database. Call once at startup.
#[no_mangle]
pub extern "C" fn sec_feed_init(security_dir: *const c_char) -> bool {
    let dir = match unsafe { from_c_str(security_dir) } {
        Some(d) => d,
        None => return threat_feeds::init_default().is_ok(),
    };
    threat_feeds::init(&dir).is_ok()
}

/// Check a URL against threat feeds. Caller must free with sec_free_feed_check.
#[no_mangle]
pub extern "C" fn sec_feed_check_url(url: *const c_char) -> *mut FeedCheckResultFFI {
    let url = match unsafe { from_c_str(url) } {
        Some(u) => u,
        None => return ptr::null_mut(),
    };
    let result = threat_feeds::check_url(&url);
    Box::into_raw(Box::new(FeedCheckResultFFI {
        threat_level: result.threat_level,
        feed_name: result.feed_name.as_deref().map(to_c_string).unwrap_or(ptr::null_mut()),
        indicator: result.indicator.as_deref().map(to_c_string).unwrap_or(ptr::null_mut()),
    }))
}

/// Check a domain against threat feeds. Caller must free with sec_free_feed_check.
#[no_mangle]
pub extern "C" fn sec_feed_check_domain(domain: *const c_char) -> *mut FeedCheckResultFFI {
    let domain = match unsafe { from_c_str(domain) } {
        Some(d) => d,
        None => return ptr::null_mut(),
    };
    let result = threat_feeds::check_domain(&domain);
    Box::into_raw(Box::new(FeedCheckResultFFI {
        threat_level: result.threat_level,
        feed_name: result.feed_name.as_deref().map(to_c_string).unwrap_or(ptr::null_mut()),
        indicator: result.indicator.as_deref().map(to_c_string).unwrap_or(ptr::null_mut()),
    }))
}

/// Refresh all threat feeds. Returns count of entries refreshed, -1 on error.
/// BLOCKING — call from a background thread.
#[no_mangle]
pub extern "C" fn sec_feed_refresh() -> i32 {
    match threat_feeds::refresh_all() {
        Ok(count) => count as i32,
        Err(_) => -1,
    }
}

/// Get feed stats as JSON string. Caller must free with sec_free_string.
#[no_mangle]
pub extern "C" fn sec_feed_stats() -> *mut c_char {
    let stats = threat_feeds::get_stats();
    serde_json::to_string(&stats)
        .map(|s| to_c_string(&s))
        .unwrap_or(ptr::null_mut())
}

/// Get total entries count across all feeds.
#[no_mangle]
pub extern "C" fn sec_feed_total_entries() -> u32 {
    threat_feeds::total_entries()
}

/// Free a FeedCheckResultFFI.
#[no_mangle]
pub extern "C" fn sec_free_feed_check(ptr: *mut FeedCheckResultFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let r = Box::from_raw(ptr);
        free_c_string(r.feed_name);
        free_c_string(r.indicator);
    }
}

// ---------------------------------------------------------------------------
// Package Vulnerability Feed (OSV) — Phase 16
// ---------------------------------------------------------------------------

/// FFI-safe package check result.
#[repr(C)]
pub struct PackageCheckResultFFI {
    pub vulnerable: bool,
    pub severity: i8,          // -1 = clean, 1..4 = Low..Critical
    pub cve: *mut c_char,      // null if clean
    pub source: *mut c_char,   // "osv", "cache:osv", "error:..."
}

/// Initialize the package-vulns SQLite cache. Call once at startup.
#[no_mangle]
pub extern "C" fn sec_package_vulns_init(security_dir: *const c_char) -> bool {
    let dir = match unsafe { from_c_str(security_dir) } {
        Some(d) => d,
        None => return false,
    };
    package_vulns::init(&dir).is_ok()
}

/// Check a single package against OSV (cache-first). BLOCKING — on cache
/// miss makes an HTTP call up to 30 s. Call from a background thread.
#[no_mangle]
pub extern "C" fn sec_check_package(
    ecosystem: *const c_char,
    name: *const c_char,
    version: *const c_char,
) -> *mut PackageCheckResultFFI {
    let eco = match unsafe { from_c_str(ecosystem) } {
        Some(e) => e,
        None => return ptr::null_mut(),
    };
    let name = match unsafe { from_c_str(name) } {
        Some(n) => n,
        None => return ptr::null_mut(),
    };
    let version = match unsafe { from_c_str(version) } {
        Some(v) => v,
        None => return ptr::null_mut(),
    };

    let r = package_vulns::check_package(&eco, &name, &version);
    Box::into_raw(Box::new(PackageCheckResultFFI {
        vulnerable: r.vulnerable,
        severity: r.severity,
        cve: r.cve.as_deref().map(to_c_string).unwrap_or(ptr::null_mut()),
        source: to_c_string(&r.source),
    }))
}

/// Batch-check N packages. `queries_json` is a JSON array:
/// `[{"ecosystem":"PyPI","name":"litellm","version":"1.82.8"}, ...]`
/// Returns JSON array of results. Caller frees with `sec_free_string`.
/// BLOCKING — makes one OSV /querybatch call on cache miss.
#[no_mangle]
pub extern "C" fn sec_check_package_batch(queries_json: *const c_char) -> *mut c_char {
    let json = match unsafe { from_c_str(queries_json) } {
        Some(j) => j,
        None => return ptr::null_mut(),
    };

    let value: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };
    let arr = match value.as_array() {
        Some(a) => a,
        None => return ptr::null_mut(),
    };

    let tuples: Vec<(String, String, String)> = arr.iter()
        .filter_map(|v| {
            let eco = v.get("ecosystem")?.as_str()?.to_string();
            let name = v.get("name")?.as_str()?.to_string();
            let ver = v.get("version")?.as_str()?.to_string();
            Some((eco, name, ver))
        })
        .collect();
    let results = package_vulns::check_package_batch(&tuples);

    serde_json::to_string(&results)
        .map(|s| to_c_string(&s))
        .unwrap_or(ptr::null_mut())
}

/// Free a `PackageCheckResultFFI`.
#[no_mangle]
pub extern "C" fn sec_free_package_check(ptr: *mut PackageCheckResultFFI) {
    if ptr.is_null() { return; }
    unsafe {
        let r = Box::from_raw(ptr);
        free_c_string(r.cve);
        free_c_string(r.source);
    }
}

// ---------------------------------------------------------------------------
// Protection Tier & Effective Config
// ---------------------------------------------------------------------------

/// Get the current protection tier from config. Returns 0=relaxed, 1=balanced, 2=strict.
/// Returns -1 on error.
#[no_mangle]
pub extern "C" fn sec_get_protection_tier(config_path: *const c_char) -> i8 {
    let path = match unsafe { from_c_str(config_path) } {
        Some(p) => p,
        None => return 1, // default to balanced
    };
    let config = SecurityConfig::load_or_default(&path);
    config.general.protection_tier.level() as i8
}

/// Set the protection tier in config.toml. tier: 0=relaxed, 1=balanced, 2=strict.
/// Returns true on success.
#[no_mangle]
pub extern "C" fn sec_set_protection_tier(config_path: *const c_char, tier: i8) -> bool {
    let path = match unsafe { from_c_str(config_path) } {
        Some(p) => p,
        None => return false,
    };
    let tier = match tier {
        0 => ProtectionTier::Relaxed,
        1 => ProtectionTier::Balanced,
        2 => ProtectionTier::Strict,
        _ => return false,
    };
    config::set_protection_tier_in_file(&path, tier).is_ok()
}

/// Get the fully resolved effective security config as a JSON string.
/// Caller must free with sec_free_string.
#[no_mangle]
pub extern "C" fn sec_get_effective_config(config_path: *const c_char) -> *mut c_char {
    let path = match unsafe { from_c_str(config_path) } {
        Some(p) => p,
        None => {
            let config = SecurityConfig::default();
            let eff = config.resolve_effective();
            return serde_json::to_string(&eff)
                .map(|s| to_c_string(&s))
                .unwrap_or(ptr::null_mut());
        }
    };
    let config = SecurityConfig::load_or_default(&path);
    let eff = config.resolve_effective();
    serde_json::to_string(&eff)
        .map(|s| to_c_string(&s))
        .unwrap_or(ptr::null_mut())
}

/// Free a string returned by sec_get_effective_config.
#[no_mangle]
pub extern "C" fn sec_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr)); }
    }
}

// ---------------------------------------------------------------------------
// Local Services — in-process HTTP endpoints for privacy_router + intent_verifier
// ---------------------------------------------------------------------------

/// Tracks whether the listener has already been started in this process.
/// Idempotent: calling `sec_local_services_start` more than once is a no-op
/// and returns true.
static LOCAL_SERVICES_BOUND: OnceLock<String> = OnceLock::new();

/// FFI-safe start result.
#[repr(C)]
pub struct LocalServicesStartResult {
    /// True if the listener is now running (including the case where it was
    /// already running from a prior call).
    pub ok: bool,
    /// The bound address as returned by the OS. Useful when the caller
    /// passed port 0. Null on failure. Caller must free with `sec_free_string`.
    pub bound_addr: *mut c_char,
}

/// Start the in-process HTTP listener that serves:
///   - POST /privacy/evaluate
///   - POST /intent/verify
///   - GET  /health
///
/// Parameters:
///   - `bind_addr`       : e.g. "127.0.0.1:7459". `127.0.0.1:0` picks a free port.
///   - `config_path`     : optional; null uses defaults.
///   - `audit_log_path`  : optional; null disables audit logging.
///
/// Returns a heap-allocated `LocalServicesStartResult`. Caller must free via
/// `sec_free_local_services_start_result`. The listener runs on a detached
/// thread — it lives for the life of the process.
#[no_mangle]
pub extern "C" fn sec_local_services_start(
    bind_addr: *const c_char,
    config_path: *const c_char,
    audit_log_path: *const c_char,
) -> *mut LocalServicesStartResult {
    // Idempotency: if already bound, return the prior address.
    if let Some(addr) = LOCAL_SERVICES_BOUND.get() {
        return Box::into_raw(Box::new(LocalServicesStartResult {
            ok: true,
            bound_addr: to_c_string(addr),
        }));
    }

    let bind = unsafe { from_c_str(bind_addr) }
        .unwrap_or_else(|| "127.0.0.1:7459".to_string());
    let cfg  = unsafe { from_c_str(config_path) };
    let alog = unsafe { from_c_str(audit_log_path) };

    let opts = ServiceOptions {
        bind_addr: bind,
        config_path: cfg,
        audit_log_path: alog,
        security_dir: None,
    };

    match local_services::start_in_background(opts) {
        Some(handle) => {
            // First-writer wins; subsequent calls short-circuit above.
            let _ = LOCAL_SERVICES_BOUND.set(handle.bound_addr.clone());
            Box::into_raw(Box::new(LocalServicesStartResult {
                ok: true,
                bound_addr: to_c_string(&handle.bound_addr),
            }))
        }
        None => Box::into_raw(Box::new(LocalServicesStartResult {
            ok: false,
            bound_addr: ptr::null_mut(),
        })),
    }
}

/// True iff the listener is currently running in this process.
#[no_mangle]
pub extern "C" fn sec_local_services_is_running() -> bool {
    LOCAL_SERVICES_BOUND.get().is_some()
}

/// Free the result struct returned by `sec_local_services_start`.
#[no_mangle]
pub extern "C" fn sec_free_local_services_start_result(ptr: *mut LocalServicesStartResult) {
    if ptr.is_null() { return; }
    unsafe {
        let r = Box::from_raw(ptr);
        free_c_string(r.bound_addr);
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
