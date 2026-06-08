use std::sync::Mutex;

pub mod commands;

pub use thr34ds_core::Database;

/// Application state shared across Tauri commands.
pub struct AppState {
    pub db: Mutex<Database>,
}

impl AppState {
    pub fn new(db: Database) -> Self {
        Self {
            db: Mutex::new(db),
        }
    }
}
