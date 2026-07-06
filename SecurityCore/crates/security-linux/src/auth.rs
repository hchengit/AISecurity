//! PAM authentication gate for Linux vault operations.
//!
//! Validates the current user's password via PAM before allowing
//! vault encrypt/decrypt/passphrase operations.
//! Includes session caching (5-minute window) and 3-attempt lockout.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Auth gate configuration.
const SESSION_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
const MAX_FAILED_ATTEMPTS: u32 = 3;
const LOCKOUT_DURATION: Duration = Duration::from_secs(300); // 5 minutes

/// PAM authentication gate with session caching and rate limiting.
pub struct AuthGate {
    state: Mutex<AuthState>,
}

struct AuthState {
    /// When the last successful auth happened.
    last_auth: Option<Instant>,
    /// Failed attempt counter.
    failed_attempts: u32,
    /// When lockout expires (None if not locked out).
    lockout_until: Option<Instant>,
}

#[derive(Debug)]
pub enum AuthError {
    /// PAM authentication failed (wrong password).
    InvalidPassword,
    /// Too many failed attempts — locked out.
    LockedOut { remaining_secs: u64 },
    /// PAM system error.
    PamError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPassword => write!(f, "Invalid password"),
            Self::LockedOut { remaining_secs } => {
                write!(f, "Locked out. Try again in {}s", remaining_secs)
            }
            Self::PamError(msg) => write!(f, "PAM error: {}", msg),
        }
    }
}

impl AuthGate {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(AuthState {
                last_auth: None,
                failed_attempts: 0,
                lockout_until: None,
            }),
        }
    }

    /// Check if we have a valid cached session (within 5-minute window).
    pub fn has_valid_session(&self) -> bool {
        let state = self.state.lock().unwrap();
        if let Some(last) = state.last_auth {
            last.elapsed() < SESSION_TIMEOUT
        } else {
            false
        }
    }

    /// Check if currently locked out.
    pub fn is_locked_out(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if let Some(until) = state.lockout_until {
            if Instant::now() >= until {
                // Lockout expired — reset
                state.lockout_until = None;
                state.failed_attempts = 0;
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Remaining lockout seconds, or 0.
    pub fn lockout_remaining_secs(&self) -> u64 {
        let state = self.state.lock().unwrap();
        if let Some(until) = state.lockout_until {
            let now = Instant::now();
            if now < until {
                (until - now).as_secs()
            } else {
                0
            }
        } else {
            0
        }
    }

    /// Number of failed attempts so far.
    #[allow(dead_code)] // public API; not yet wired into the TUI/daemon
    pub fn failed_attempts(&self) -> u32 {
        self.state.lock().unwrap().failed_attempts
    }

    /// Attempts remaining before lockout.
    pub fn attempts_remaining(&self) -> u32 {
        let state = self.state.lock().unwrap();
        MAX_FAILED_ATTEMPTS.saturating_sub(state.failed_attempts)
    }

    /// Authenticate the current user via PAM.
    /// Returns Ok(()) on success, Err on failure.
    /// On success, starts a 5-minute session cache.
    /// On 3rd failure, triggers a 5-minute lockout.
    pub fn authenticate(&self, password: &str) -> Result<(), AuthError> {
        // Check lockout first
        if self.is_locked_out() {
            return Err(AuthError::LockedOut {
                remaining_secs: self.lockout_remaining_secs(),
            });
        }

        // If we have a valid session, skip PAM
        if self.has_valid_session() {
            return Ok(());
        }

        // Get current username
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .unwrap_or_else(|_| "root".to_string());

        // Authenticate via PAM
        match pam_authenticate(&username, password) {
            Ok(()) => {
                let mut state = self.state.lock().unwrap();
                state.last_auth = Some(Instant::now());
                state.failed_attempts = 0;
                state.lockout_until = None;
                Ok(())
            }
            Err(e) => {
                let mut state = self.state.lock().unwrap();
                state.failed_attempts += 1;
                if state.failed_attempts >= MAX_FAILED_ATTEMPTS {
                    state.lockout_until = Some(Instant::now() + LOCKOUT_DURATION);
                }
                Err(e)
            }
        }
    }

    /// Invalidate the current session (e.g., after passphrase change).
    #[allow(dead_code)] // public API; not yet wired into the TUI/daemon
    pub fn invalidate_session(&self) {
        let mut state = self.state.lock().unwrap();
        state.last_auth = None;
    }
}

/// Low-level PAM authentication.
fn pam_authenticate(username: &str, password: &str) -> Result<(), AuthError> {
    let mut client = pam::Client::with_password("login")
        .map_err(|e| AuthError::PamError(format!("PAM init: {}", e)))?;

    client
        .conversation_mut()
        .set_credentials(username, password);

    client
        .authenticate()
        .map_err(|_| AuthError::InvalidPassword)?;

    client
        .open_session()
        .map_err(|e| AuthError::PamError(format!("PAM session: {}", e)))?;

    Ok(())
}
