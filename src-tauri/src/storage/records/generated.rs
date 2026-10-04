//! Выдачи генератора секретов.
//!
//! Это черновик, а не именованный секрет: значение сгенерировали, скопировали,
//! применили и выбросили. Поэтому хранится отдельно от записей и удаляется по
//! возрасту без участия пользователя — иначе за полгода накопится полсотни
//! валидных секретов неизвестно от чего.
//!
//! Шифрование то же, что у полей записей: per-blob субключ HKDF от мастер-ключа
//! с привязкой к идентификатору выдачи через AAD. Подменить одну выдачу другой
//! нельзя — AAD не сойдётся.

use rusqlite::params;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::state::MasterKey;
use crate::storage::records::field_crypto::{field_decrypt, field_encrypt};
use crate::storage::records_db::RecordsDb;

/// Сколько живёт выдача до автоматического удаления.
pub const RETENTION_HOURS: i64 = 24;

/// Минимальная длина сгенерированного пароля.
///
/// Согласована с `PASSPHRASE_MIN` для секрета без аппаратного якоря: короче
/// смысла генерировать нет, а предлагать пользователю слабый вариант в
/// инструменте, который существует ради стойкости, — противоречие.
pub const PASSWORD_MIN_LEN: usize = 15;
/// Верхняя граница для любого типа: защита от абсурдного ввода из webview.
pub const MAX_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GeneratedKind {
    /// Пароль на полном наборе: буквы, цифры, спецсимволы.
    Password,
    /// Пароль только из латинских букв и цифр.
    ///
    /// Нужен не для красоты: спецсимволы ломают типовые контексты проектов —
    /// `$` подставляется в docker-compose, `#` начинает комментарий в YAML,
    /// `&;<>|` разбираются оболочкой, а часть систем и вовсе принимает только
    /// буквы с цифрами. Цена — 5.95 бит на символ вместо 6.46.
    Alnum,
    Hex,
    Base64url,
}

impl GeneratedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GeneratedKind::Password => "password",
            GeneratedKind::Alnum => "alnum",
            GeneratedKind::Hex => "hex",
            GeneratedKind::Base64url => "base64url",
        }
    }

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "password" => Ok(GeneratedKind::Password),
            "alnum" => Ok(GeneratedKind::Alnum),
            "hex" => Ok(GeneratedKind::Hex),
            "base64url" => Ok(GeneratedKind::Base64url),
            other => Err(VaultError::Storage(format!(
                "unknown generated secret kind: {other}"
            ))),
        }
    }

    /// Допустим ли символ в значении этого типа.
    ///
    /// Генерация живёт во фронтенде (один генератор на весь продукт), но
    /// доверять webview содержимому нельзя: без этой проверки в список
    /// «сгенерированного» можно было бы положить произвольную строку.
    fn accepts(self, c: char) -> bool {
        match self {
            GeneratedKind::Hex => c.is_ascii_hexdigit() && !c.is_ascii_uppercase(),
            GeneratedKind::Alnum => c.is_ascii_alphanumeric(),
            GeneratedKind::Base64url => c.is_ascii_alphanumeric() || c == '-' || c == '_',
            // Пароль: печатаемый ASCII без пробела. Конкретный набор выбирает
            // пользователь, поэтому проверяем только границы диапазона.
            GeneratedKind::Password => c.is_ascii_graphic(),
        }
    }

    /// Нижняя граница длины для этого типа.
    pub fn min_len(self) -> usize {
        match self {
            GeneratedKind::Password | GeneratedKind::Alnum => PASSWORD_MIN_LEN,
            // 16 hex-символов — это всего 64 бита; ниже опускаться незачем.
            GeneratedKind::Hex => 16,
            GeneratedKind::Base64url => 16,
        }
    }
}

/// Метаданные выдачи. Значение сюда не попадает: список рисуется без секретов,
/// а сам секрет запрашивается отдельной командой при копировании.
#[derive(Debug, Clone, Serialize)]
pub struct GeneratedSecretMeta {
    pub id: String,
    pub kind: GeneratedKind,
    pub length: u32,
    pub created_at: String,
}

fn generated_aad(id: &str) -> Vec<u8> {
    format!("vaultisor:generated:{id}").into_bytes()
}

/// Сохранить выдачу. Значение шифруется сразу и в открытом виде не остаётся.
pub fn insert(
    db: &RecordsDb,
    master: &MasterKey,
    kind: GeneratedKind,
    value: &str,
) -> Result<GeneratedSecretMeta> {
    let length = value.chars().count();
    if length < kind.min_len() || length > MAX_LEN {
        return Err(VaultError::BadInput(format!(
            "Длина {length} вне допустимых границ {}..{MAX_LEN}",
            kind.min_len()
        )));
    }

    if let Some(bad) = value.chars().find(|c| !kind.accepts(*c)) {
        return Err(VaultError::BadInput(format!(
            "Символ {bad:?} недопустим для типа {}",
            kind.as_str()
        )));
    }

    let id = uuid::Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now().to_rfc3339();
    let blob = field_encrypt(master, value.as_bytes(), &generated_aad(&id))?;

    crate::failpoint::hit("records.write")?;
    db.with_conn(|c| {
        c.execute(
            "INSERT INTO generated_secrets (id, kind, length, value_blob, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, kind.as_str(), length as i64, blob, created_at],
        )?;
        Ok(())
    })?;

    Ok(GeneratedSecretMeta {
        id,
        kind,
        length: length as u32,
        created_at,
    })
}

/// Список выдач, новые сверху. Без значений.
pub fn list(db: &RecordsDb) -> Result<Vec<GeneratedSecretMeta>> {
    db.with_conn(|c| {
        let mut stmt = c.prepare(
            "SELECT id, kind, length, created_at FROM generated_secrets ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, kind, length, created_at) = row?;
            out.push(GeneratedSecretMeta {
                id,
                kind: GeneratedKind::from_str(&kind)?,
                length: length.max(0) as u32,
                created_at,
            });
        }
        Ok(out)
    })
}

/// Расшифровать одну выдачу для копирования в буфер.
pub fn reveal(db: &RecordsDb, master: &MasterKey, id: &str) -> Result<Zeroizing<String>> {
    let blob: Vec<u8> = db.with_conn(|c| {
        c.query_row(
            "SELECT value_blob FROM generated_secrets WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )
        .map_err(|_| VaultError::BadInput("Выдача генератора не найдена".into()))
    })?;

    field_decrypt(master, &blob, &generated_aad(id))
}

/// Удалить перечисленные выдачи. Возвращает, сколько строк реально ушло.
pub fn delete_many(db: &RecordsDb, ids: &[String]) -> Result<usize> {
    if ids.is_empty() {
        return Ok(0);
    }
    db.with_conn(|c| {
        let tx = c.unchecked_transaction()?;
        let mut removed = 0usize;
        {
            let mut stmt = tx.prepare("DELETE FROM generated_secrets WHERE id = ?1")?;
            for id in ids {
                removed += stmt.execute(params![id])?;
            }
        }
        crate::failpoint::hit("records.commit")?;
        tx.commit()?;
        Ok(removed)
    })
}

/// Удалить выдачи старше `RETENTION_HOURS`.
///
/// Вызывается при открытии списка: отдельного планировщика ради этого заводить
/// незачем, а приложение офлайновое и между запусками ничего не делает.
pub fn purge_expired(db: &RecordsDb) -> Result<usize> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::hours(RETENTION_HOURS)).to_rfc3339();
    crate::failpoint::hit("records.write")?;
    db.with_conn(|c| {
        let removed = c.execute(
            "DELETE FROM generated_secrets WHERE created_at < ?1",
            params![cutoff],
        )?;
        Ok(removed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::master::generate_master_key;
    use crate::storage::records_db::{derive_sqlcipher_key, RecordsDb};

    fn open() -> (tempfile::TempDir, RecordsDb, MasterKey) {
        let dir = tempfile::tempdir().unwrap();
        let master = generate_master_key();
        let key = master.with_decrypted(derive_sqlcipher_key).unwrap();
        let db = RecordsDb::open(&dir.path().join("r.db"), &key).unwrap();
        (dir, db, master)
    }

    #[test]
    fn roundtrip_and_delete() {
        let (_d, db, master) = open();
        let meta = insert(&db, &master, GeneratedKind::Password, "Kx7#mQ2vLp9$wRt4").unwrap();
        assert_eq!(list(&db).unwrap().len(), 1);
        assert_eq!(
            &*reveal(&db, &master, &meta.id).unwrap(),
            "Kx7#mQ2vLp9$wRt4"
        );
        assert_eq!(delete_many(&db, std::slice::from_ref(&meta.id)).unwrap(), 1);
        assert!(list(&db).unwrap().is_empty());
    }

    /// Список не должен раскрывать значения: он рисуется всегда, а секрет
    /// нужен только в момент копирования.
    #[test]
    fn listing_never_returns_the_secret() {
        let (_d, db, master) = open();
        insert(&db, &master, GeneratedKind::Hex, &"a".repeat(32)).unwrap();
        let json = serde_json::to_string(&list(&db).unwrap()).unwrap();
        assert!(!json.contains(&"a".repeat(32)), "значение утекло в список");
    }

    /// AAD привязан к идентификатору выдачи: подставить чужой blob нельзя.
    #[test]
    fn blob_from_another_row_does_not_decrypt() {
        let (_d, db, master) = open();
        let first = insert(&db, &master, GeneratedKind::Password, "Fs1#kQ9mLp4$wRt2").unwrap();
        let second = insert(&db, &master, GeneratedKind::Password, "Sc2#nT8vJp5$xYu3").unwrap();
        db.with_conn(|c| {
            c.execute(
                "UPDATE generated_secrets SET value_blob = \
                 (SELECT value_blob FROM generated_secrets WHERE id = ?1) WHERE id = ?2",
                params![first.id, second.id],
            )?;
            Ok(())
        })
        .unwrap();
        assert!(reveal(&db, &master, &second.id).is_err());
    }

    #[test]
    fn too_short_password_is_rejected() {
        let (_d, db, master) = open();
        assert!(insert(&db, &master, GeneratedKind::Password, "short").is_err());
        assert!(insert(
            &db,
            &master,
            GeneratedKind::Password,
            &"x".repeat(MAX_LEN + 1)
        )
        .is_err());
    }

    /// Значение обязано соответствовать заявленному типу: иначе webview мог бы
    /// выдать за «сгенерированное» что угодно, включая чужой текст.
    #[test]
    fn value_must_match_the_declared_kind() {
        let (_d, db, master) = open();
        assert!(insert(&db, &master, GeneratedKind::Hex, &"Z".repeat(32)).is_err());
        assert!(insert(&db, &master, GeneratedKind::Base64url, &"a+b/".repeat(8)).is_err());
        assert!(insert(&db, &master, GeneratedKind::Password, "пароль-кириллица!!").is_err());
        assert!(insert(&db, &master, GeneratedKind::Hex, &"a1b2".repeat(8)).is_ok());
    }

    /// Набор «только буквы и цифры» обязан отвергать спецсимволы: иначе тип
    /// в базе не соответствовал бы содержимому, и показанная энтропия врала бы.
    #[test]
    fn alnum_kind_rejects_symbols() {
        let (_d, db, master) = open();
        assert!(insert(&db, &master, GeneratedKind::Alnum, "Kx7#mQ2vLp9$wRt4").is_err());
        assert!(insert(&db, &master, GeneratedKind::Alnum, "Kx7mQ2vLp9wRt4Ab").is_ok());
    }

    #[test]
    fn purge_removes_only_expired_rows() {
        let (_d, db, master) = open();
        let fresh = insert(&db, &master, GeneratedKind::Password, "Fr3#hQ7mNp2$vXt8").unwrap();
        let stale = insert(&db, &master, GeneratedKind::Password, "St4#lQ6mKp1$uWt9").unwrap();
        let old = (chrono::Utc::now() - chrono::Duration::hours(RETENTION_HOURS + 1)).to_rfc3339();
        db.with_conn(|c| {
            c.execute(
                "UPDATE generated_secrets SET created_at = ?1 WHERE id = ?2",
                params![old, stale.id],
            )?;
            Ok(())
        })
        .unwrap();

        assert_eq!(purge_expired(&db).unwrap(), 1);
        let left = list(&db).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, fresh.id);
    }
}
