// CRUD для записей и полей.
//
// Все секретные значения шифруются AES-256-GCM с master-key.
// AAD = "vaultisor:field:" + record_id + ":" + field_id + ":" + field_type
// — это привязывает шифротекст к конкретному полю; перенос blob'а на
// другую запись или в другой field_type сделает его нерасшифровываемым.

pub mod crud;
pub mod field_crypto;

pub use crud::*;
pub use field_crypto::*;

use serde::{Deserialize, Serialize};
use crate::error::{Result, VaultError};

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
