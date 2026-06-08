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
            list_root_threads,
            list_child_threads,
            create_thread,
            delete_thread,
            list_messages,
            create_message,
            delete_message,
            list_respondents,
            add_respondent,
            summon_agent,
            issue_summons,
            list_summonses,
            certify_summons,
            list_timeline,
            verify_thread,
            state_root,
            prove_thread,
            timeline_public_key,
            attach_anchor,
            record_posterity,
            get_posterity,
            record_cut,
            list_cuts,
            get_cut,
            anchor_cut,
            get_synced_time,
        ])
        .run(tauri::generate_context!())
        .expect("error while running thr34ds application");
}
