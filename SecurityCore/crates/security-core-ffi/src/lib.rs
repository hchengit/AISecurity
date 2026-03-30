//! C ABI FFI layer for security-core.
//!
//! All functions use `#[no_mangle] pub extern "C"` for stable ABI.
//! Callers must free returned pointers via the corresponding `sec_free_*` function.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::{c_char, CStr, CString};
use std::ptr;

use security_core::email_patterns;
use security_core::vault;
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
    pub protection: u8, // 0=locked, 1=read_only, 2=local_only
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
    }
}

fn u8_to_protection(v: u8) -> vault::ProtectionLevel {
    match v {
        1 => vault::ProtectionLevel::ReadOnly,
        2 => vault::ProtectionLevel::LocalOnly,
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

/// Add files to vault. `paths` is a colon-separated list. `protection`: 0=locked, 1=read_only, 2=local_only.
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

    let path_list: Vec<&str> = paths_str.split(':').collect();
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

    let path_list: Vec<&str> = paths_str.split(':').collect();
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

    let path_list: Vec<&str> = paths_str.split(':').collect();
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

    let path_list: Vec<&str> = paths_str.split(':').collect();
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
