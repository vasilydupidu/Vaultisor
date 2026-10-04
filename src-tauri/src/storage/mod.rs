// Хранилище.
//
// Файлы хранилища:
//   - meta_db (vault.meta.db): открытая SQLite под MAC. Хранит обёртку
//     мастер-ключа, integrity_key_dpapi, настройки и восстановление.
//     Доступна ДО разворачивания мастер-ключа — иначе вход невозможен.
//   - records_db (vault.records.db, vault.web.db): SQLCipher с записями и
//     паролями сайтов. Ключи выводятся из мастер-ключа через HKDF.
//   - внешний checkpoint (machine_checkpoint): эпоха и MAC метаданных,
//     задержки PIN и ревизии обеих баз — обнаружение отката файлов.

pub mod integrity;
pub(crate) mod machine_checkpoint;
pub mod meta_db;
pub mod records;
pub mod records_db;
pub mod restore;

// db.rs теперь содержит только DPAPI-слой обёртки master-key
// (unwrap_dpapi_layer / wrap_dpapi_layer), используемый в commands.
pub(crate) mod create_staging;
pub mod db;
pub(crate) mod fsio;
pub(crate) mod osjournal;
pub(crate) mod settle;
