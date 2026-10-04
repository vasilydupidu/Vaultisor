// CRUD для записей и полей.
//
// Все секретные значения шифруются AES-256-GCM с master-key.
// AAD = "vaultisor:field:" + record_id + ":" + field_id + ":" + field_type
// — это привязывает шифротекст к конкретному полю; перенос blob'а на
// другую запись или в другой field_type сделает его нерасшифровываемым.

pub mod crud;
pub(crate) mod field_crypto;
/// Выдачи генератора секретов: черновики с автоочисткой по возрасту.
pub mod generated;

pub use crud::*;
pub(crate) use field_crypto::{field_decrypt, field_encrypt};

use crate::error::{Result, VaultError};
use serde::{Deserialize, Serialize};

/// Тип поля. Перечисление зафиксировано в чек-констрейнте схемы.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FieldType {
    Secret,
    Api,
    Key,
    Id,
    Comment,
    Custom,
}

impl FieldType {
    pub fn as_str(&self) -> &'static str {
        match self {
            FieldType::Secret => "secret",
            FieldType::Api => "api",
            FieldType::Key => "key",
            FieldType::Id => "id",
            FieldType::Comment => "comment",
            FieldType::Custom => "custom",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "secret" => FieldType::Secret,
            "api" => FieldType::Api,
            "key" => FieldType::Key,
            "id" => FieldType::Id,
            "comment" => FieldType::Comment,
            "custom" => FieldType::Custom,
            _ => return Err(VaultError::BadInput(format!("unknown field type: {s}"))),
        })
    }
}

/// Запись (карточка).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub name: String,
    pub project: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub category: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub has_weak: bool,
    #[serde(default)]
    pub has_reused: bool,
    /// Поля включаются только при `record_get`, не при `record_list`.
    #[serde(default)]
    pub fields: Vec<FieldMeta>,
}

/// Метаданные поля БЕЗ значения.
/// `value_preview` = маскированная подсказка для UI ("••••••••").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMeta {
    pub id: String,
    pub field_type: FieldType,
    pub label: String,
    pub is_secret: bool,
    pub sort_order: i64,
    pub value_preview: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Параметры создания/обновления записи.
#[derive(Debug, Clone, Deserialize)]
pub struct RecordInput {
    pub name: String,
    pub project: Option<String>,
    pub icon: Option<String>,
    pub color: Option<String>,
    pub category: Option<String>,
    pub fields: Vec<FieldInput>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FieldInput {
    /// Если задан — обновление существующего поля.
    pub id: Option<String>,
    pub field_type: FieldType,
    pub label: String,
    pub is_secret: bool,
    pub sort_order: i64,
    /// Plaintext-значение. Шифруется при сохранении.
    /// При обновлении значение None означает "оставить как было".
    pub value: Option<String>,
}

/// AAD для шифрования значения поля.
pub(crate) fn field_aad(record_id: &str, field_id: &str, ft: FieldType) -> Vec<u8> {
    format!("vaultisor:field:{record_id}:{field_id}:{}", ft.as_str()).into_bytes()
}

/// AAD для шифрования истории паролей.
pub(crate) fn history_aad(record_id: &str, history_id: &str) -> Vec<u8> {
    format!("vaultisor:history:{record_id}:{history_id}").into_bytes()
}

/// Элемент истории изменения паролей — ТОЛЬКО метаданные.
///
/// AUDIT 3.1.1: раньше сюда клалось расшифрованное значение, и весь архив
/// паролей записи уезжал в webview, где жил в React-state всё время, пока
/// открыта секция истории (притом что интерфейс показывает его под маской).
/// Теперь значение не покидает backend: копирование и восстановление
/// выполняются отдельными командами по идентификатору записи истории.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistoryEntry {
    pub id: String,
    pub record_id: String,
    pub field_id: String,
    pub field_label: String,
    pub created_at: String,
}
