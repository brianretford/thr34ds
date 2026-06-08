// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use thr34ds_lib::{AppState, Database, commands::*};

fn main() {
    let db = Database::open().expect("failed to open local database");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState::new(db))
        .invoke_handler(tauri::generate_handler![
            list_threads,
            create_thread,
            delete_thread,
            list_messages,
            create_message,
            delete_message,
            get_synced_time,
        ])
        .run(tauri::generate_context!())
        .expect("error while running thr34ds application");
}
