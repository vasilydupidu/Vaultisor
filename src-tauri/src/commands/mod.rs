// Tauri-команды (IPC-точки фронтенда).
// Все группы команд раскрываются через invoke_handler в lib.rs.

pub mod auth_gate;
pub mod backup;
pub mod clipboard;
pub mod file_grants;
pub mod generator;
pub mod import;
pub mod records;
pub mod recovery;
pub(crate) mod request;
pub mod security;
pub mod settings;
pub mod system;
pub mod vault;
