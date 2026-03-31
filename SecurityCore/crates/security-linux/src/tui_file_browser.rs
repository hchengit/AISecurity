//! TUI file browser widget — navigate filesystem, multi-select with checkboxes.
//! Used for vault "Protect Files..." operation.

use std::path::{Path, PathBuf};

/// A file/directory entry in the browser.
#[derive(Debug, Clone)]
pub struct BrowserEntry {
    pub path: PathBuf,
    pub name: String,
    pub is_dir: bool,
    pub selected: bool,
}

/// File browser state.
pub struct FileBrowser {
    pub current_dir: PathBuf,
    pub entries: Vec<BrowserEntry>,
    pub cursor: usize,
    pub selected_paths: Vec<PathBuf>,
}

impl FileBrowser {
    /// Create a new file browser starting at `start_dir`.
    pub fn new(start_dir: &Path) -> Self {
        let mut browser = Self {
            current_dir: start_dir.to_path_buf(),
            entries: Vec::new(),
            cursor: 0,
            selected_paths: Vec::new(),
        };
        browser.refresh();
        browser
    }

    /// Reload entries from the current directory.
    pub fn refresh(&mut self) {
        self.entries.clear();
        self.cursor = 0;

        // Parent directory entry (..)
        if self.current_dir.parent().is_some() {
            self.entries.push(BrowserEntry {
                path: self.current_dir.parent().unwrap().to_path_buf(),
                name: "..".to_string(),
                is_dir: true,
                selected: false,
            });
        }

        // Read directory contents
        if let Ok(read_dir) = std::fs::read_dir(&self.current_dir) {
            let mut dirs = Vec::new();
            let mut files = Vec::new();

            for entry in read_dir.flatten() {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();

                // Skip hidden files
                if name.starts_with('.') {
                    continue;
                }

                let is_dir = path.is_dir();
                let selected = self.selected_paths.contains(&path);

                let entry = BrowserEntry {
                    path,
                    name,
                    is_dir,
                    selected,
                };

                if is_dir {
                    dirs.push(entry);
                } else {
                    files.push(entry);
                }
            }

            // Sort: directories first, then files, both alphabetically
            dirs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

            self.entries.extend(dirs);
            self.entries.extend(files);
        }
    }

    /// Move cursor down.
    pub fn next(&mut self) {
        if !self.entries.is_empty() {
            self.cursor = (self.cursor + 1).min(self.entries.len() - 1);
        }
    }

    /// Move cursor up.
    pub fn prev(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    /// Enter directory or toggle selection on file.
    pub fn enter(&mut self) {
        if let Some(entry) = self.entries.get(self.cursor) {
            if entry.is_dir {
                self.current_dir = entry.path.clone();
                self.refresh();
            } else {
                self.toggle_selected();
            }
        }
    }

    /// Toggle selection on current entry (space key).
    pub fn toggle_selected(&mut self) {
        if let Some(entry) = self.entries.get_mut(self.cursor) {
            if entry.name == ".." {
                return;
            }
            entry.selected = !entry.selected;
            if entry.selected {
                if !self.selected_paths.contains(&entry.path) {
                    self.selected_paths.push(entry.path.clone());
                }
            } else {
                self.selected_paths.retain(|p| p != &entry.path);
            }
        }
    }

    /// Get all selected file paths.
    pub fn get_selected(&self) -> Vec<String> {
        self.selected_paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect()
    }

    /// Number of selected items.
    pub fn selection_count(&self) -> usize {
        self.selected_paths.len()
    }

    /// Current directory as string.
    pub fn current_dir_str(&self) -> String {
        self.current_dir.to_string_lossy().to_string()
    }
}
