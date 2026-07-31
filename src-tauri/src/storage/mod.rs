// Хранилище.
//
// Двухфайловая архитектура:
//   - meta_db (vault.meta.db): открытая SQLite. Хранит wrapped_master_key,
//     pin_hash, integrity_key_dpapi, settings, recovery_local. Доступна
//     ДО разворачивания master_key — иначе cascade unlock невозможен.
//   - records_db (vault.records.db): SQLCipher. Хранит records и fields.
//     Открывается только после разворачивания master_key (sqlcipher_key
//     деривируется из master_key через HKDF).

pub mod integrity;
pub mod meta_db;
pub mod records;
pub mod records_db;

// db.rs теперь содержит только DPAPI-слой обёртки master-key
// (unwrap_dpapi_layer / wrap_dpapi_layer), используемый в commands.
pub mod db;
