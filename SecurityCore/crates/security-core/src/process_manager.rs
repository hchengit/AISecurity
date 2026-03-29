//! Process lifecycle manager — cooperative cancellation and clean shutdown.
//!
//! Tracks scan worker threads and provides coordinated shutdown.
//! Uses atomic flags for zero-overhead cooperative cancellation
//! (no tokio dependency for the core library).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A cancellation token — shared flag for cooperative shutdown.
#[derive(Clone)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal cancellation.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// Create a child token that is cancelled when either parent or child is cancelled.
    pub fn child(&self) -> ChildToken {
        ChildToken {
            parent: self.clone(),
            own: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// A child cancellation token — cancelled when either parent or self is cancelled.
#[derive(Clone)]
pub struct ChildToken {
    parent: CancellationToken,
    own: Arc<AtomicBool>,
}

impl ChildToken {
    /// Signal this child's own cancellation.
    pub fn cancel(&self) {
        self.own.store(true, Ordering::Relaxed);
    }

    /// Check if cancelled (parent OR self).
    pub fn is_cancelled(&self) -> bool {
        self.parent.is_cancelled() || self.own.load(Ordering::Relaxed)
    }
}

/// Managed worker — a named task with a cancellation token.
pub struct Worker {
    pub name: String,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// Process manager — tracks and coordinates worker threads.
pub struct ProcessManager {
    root_token: CancellationToken,
    workers: Vec<Worker>,
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            root_token: CancellationToken::new(),
            workers: Vec::new(),
        }
    }

    /// Get the root cancellation token (shared with all workers).
    pub fn token(&self) -> &CancellationToken {
        &self.root_token
    }

    /// Spawn a named worker thread with the root cancellation token.
    pub fn spawn<F>(&mut self, name: &str, f: F)
    where
        F: FnOnce(CancellationToken) + Send + 'static,
    {
        let token = self.root_token.clone();
        let thread_name = name.to_string();

        let handle = std::thread::Builder::new()
            .name(thread_name.clone())
            .spawn(move || f(token))
            .expect("Failed to spawn worker thread");

        self.workers.push(Worker {
            name: thread_name,
            handle: Some(handle),
        });
    }

    /// Signal all workers to stop.
    pub fn cancel_all(&self) {
        self.root_token.cancel();
    }

    /// Wait for all workers to finish, with a timeout.
    /// Returns names of workers that did not finish in time.
    pub fn wait_all(&mut self, timeout: Duration) -> Vec<String> {
        self.root_token.cancel();
        let deadline = Instant::now() + timeout;
        let mut timed_out = Vec::new();

        for worker in &mut self.workers {
            if let Some(handle) = worker.handle.take() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    timed_out.push(worker.name.clone());
                    continue;
                }
                // park_timeout + join — best effort within timeout
                std::thread::park_timeout(Duration::from_millis(10));
                match handle.join() {
                    Ok(()) => {}
                    Err(_) => timed_out.push(worker.name.clone()),
                }
            }
        }

        self.workers.clear();
        timed_out
    }

    /// Number of active workers.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }

    /// Get worker names.
    pub fn worker_names(&self) -> Vec<&str> {
        self.workers.iter().map(|w| w.name.as_str()).collect()
    }
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Sleep in small increments, checking the cancellation token.
/// Returns true if cancelled, false if the full duration elapsed.
pub fn cancellable_sleep(duration: Duration, token: &CancellationToken) -> bool {
    let start = Instant::now();
    let step = Duration::from_millis(250);

    while start.elapsed() < duration {
        if token.is_cancelled() {
            return true;
        }
        std::thread::sleep(std::cmp::min(step, duration - start.elapsed()));
    }

    token.is_cancelled()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_starts_uncancelled() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn token_cancel_propagates() {
        let token = CancellationToken::new();
        let clone = token.clone();

        assert!(!clone.is_cancelled());
        token.cancel();
        assert!(clone.is_cancelled());
    }

    #[test]
    fn child_token_inherits_parent_cancel() {
        let parent = CancellationToken::new();
        let child = parent.child();

        assert!(!child.is_cancelled());
        parent.cancel();
        assert!(child.is_cancelled());
    }

    #[test]
    fn child_token_own_cancel() {
        let parent = CancellationToken::new();
        let child = parent.child();

        child.cancel();
        assert!(child.is_cancelled());
        assert!(!parent.is_cancelled()); // parent not affected
    }

    #[test]
    fn process_manager_spawn_and_cancel() {
        let mut pm = ProcessManager::new();

        pm.spawn("worker-1", |token| {
            while !token.is_cancelled() {
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        pm.spawn("worker-2", |token| {
            while !token.is_cancelled() {
                std::thread::sleep(Duration::from_millis(50));
            }
        });

        assert_eq!(pm.worker_count(), 2);
        assert!(pm.worker_names().contains(&"worker-1"));
        assert!(pm.worker_names().contains(&"worker-2"));

        let timed_out = pm.wait_all(Duration::from_secs(2));
        assert!(timed_out.is_empty());
        assert_eq!(pm.worker_count(), 0);
    }

    #[test]
    fn cancellable_sleep_returns_early() {
        let token = CancellationToken::new();

        // Cancel from another thread after 100ms
        let t = token.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            t.cancel();
        });

        let start = Instant::now();
        let cancelled = cancellable_sleep(Duration::from_secs(10), &token);
        let elapsed = start.elapsed();

        assert!(cancelled);
        assert!(elapsed < Duration::from_secs(1));
    }

    #[test]
    fn cancellable_sleep_completes_normally() {
        let token = CancellationToken::new();
        let cancelled = cancellable_sleep(Duration::from_millis(100), &token);
        assert!(!cancelled);
    }
}
