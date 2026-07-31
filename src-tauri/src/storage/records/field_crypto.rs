use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{self, EncryptedBlob, NONCE_LEN, TAG_LEN};
use crate::crypto::kdf::hkdf_derive;
use crate::crypto::master::MasterKey;
use crate::crypto::rng;
use crate::error::{Result, VaultError};
use crate::storage::records_db::RecordsDb;

use super::{field_aad, FieldType};

/// Длина случайной соли per-blob субключа (v2-формат значения поля).
pub(crate) const FIELD_SALT_LEN: usize = 16;

/// v2-формат значения поля: `[16 salt][12 nonce][ciphertext+tag]`.
///
/// Вместо шифрования AES-GCM напрямую master-ключом (v1) каждое значение теперь
/// шифруется отдельным субключом `HKDF(master, salt, "field-aead:v2")`. Это:
///  - снимает birthday-bound случайных 96-битных nonce: коллизия теперь требует
///    совпадения соли (128 бит) И nonce → недостижимо, даже под одним master;
///  - убирает прямое использование master как AES-ключа (гигиена ключей).
/// AAD (record_id:field_id:field_type) сохраняется — привязка поля не меняется.
pub(crate) fn derive_field_subkey(master_key: &[u8; 32], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let derived = hkdf_derive(master_key, salt, b"vaultisor:field-aead:v2", 32)?;
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&derived);
    Ok(k)
}

/// Зашифровать значение поля в v2-формат (соль + AEAD на субключе).
pub(crate) fn field_encrypt(master: &MasterKey, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let salt: [u8; FIELD_SALT_LEN] = rng::random_array();
    // Тип возврата замыкания аннотируем явно: внутри смешиваются VaultError
    // (derive_field_subkey) и CoreError (aead::encrypt) — приводим к VaultError.
    let blob = master.with_decrypted(|decrypted| -> Result<EncryptedBlob> {
        let subkey = derive_field_subkey(decrypted, &salt)?;
        Ok(aead::encrypt(&*subkey, plaintext, aad)?)
    })?;
    let mut out = Vec::with_capacity(FIELD_SALT_LEN + blob.nonce.len() + blob.ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&blob.to_bytes());
    Ok(out)
}

/// Расшифровать значение поля v2-формата.
pub(crate) fn field_decrypt(
    master: &MasterKey,
    bytes: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<String>> {
    if bytes.len() < FIELD_SALT_LEN + NONCE_LEN + TAG_LEN {
        return Err(VaultError::Crypto("field blob too short (v2)".into()));
    }
    let (salt, rest) = bytes.split_at(FIELD_SALT_LEN);
    let blob = EncryptedBlob::from_bytes(rest)?;
    master.with_decrypted(|decrypted| -> Result<Zeroizing<String>> {
        let subkey = derive_field_subkey(decrypted, salt)?;
        Ok(aead::decrypt_string(&*subkey, &blob, aad)?)
    })
}

/// N-02: маркер завершённой v2-миграции полей хранится в `PRAGMA application_id`
/// records-БД (отдельный слот заголовка), чтобы НЕ смешиваться со схемной
/// версией в `PRAGMA user_version` (её ведёт apply_records_migrations, и общий
/// счётчик был бы граблями для будущих схемных миграций). Значение — "VF2\0".
pub(crate) const RECORDS_FIELD_V2_APPID: i32 = 0x5646_3200;
/// Легаси-маркер: прежние сборки помечали завершённую v2-миграцию через
/// user_version>=3. Признаём его как «уже сделано» (обратная совместимость),
/// иначе уже-v2 БД пере-мигрировалась бы (v2-blob расшифровался бы как v1 → крах).
/// ВНИМАНИЕ будущим схемным миграциям: user_version==3 на такой БД означает
/// «схема v2 + крипто-интерим», а НЕ «схема v3».
pub(crate) const RECORDS_FIELD_V2_LEGACY_UVER: i64 = 3;

/// Одноразовая миграция шифрования полей v1 → v2.
///
/// v1: значение шифровалось AES-GCM напрямую master-ключом (все поля под одним
/// ключом → теоретический birthday-bound случайных nonce). v2: каждое значение
/// шифруется отдельным субключом `HKDF(master, random_salt)`.
///
/// Идемпотентна: маркер — `PRAGMA user_version` БД записей. Выполняется в одной
/// транзакции (BEGIN IMMEDIATE): при любой ошибке — полный откат, данные целы.
/// Требует master (нужен для расшифровки старых blob'ов). Вызывается сразу после
/// открытия records/web БД в flow'ах разблокировки/создания/смены PIN.
pub fn migrate_field_encryption(db: &RecordsDb, master: &MasterKey) -> Result<()> {
    db.with_conn(|c| {
        let appid: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let uver: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if appid == RECORDS_FIELD_V2_APPID as i64 || uver >= RECORDS_FIELD_V2_LEGACY_UVER {
            return Ok(());
        }
        c.execute_batch("BEGIN IMMEDIATE")?;
        let res: Result<()> = (|| {
            // Считываем все поля целиком (чтобы не держать prepared stmt во время
            // UPDATE на том же соединении).
            let rows: Vec<(String, String, String, Vec<u8>)> = {
                let mut stmt =
                    c.prepare("SELECT id, record_id, field_type, value_blob FROM fields")?;
                let mapped = stmt.query_map([], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, Vec<u8>>(3)?,
                    ))
                })?;
                let mut v = Vec::new();
                for row in mapped {
                    v.push(row?);
                }
                v
            };
            for (fid, rid, ft_s, blob_bytes) in rows {
                // N-04: НЕ подставляем Custom по-умолчанию — иначе AAD посчитается
                // по неверному типу, и поле станет нечитаемым (reveal считает AAD
                // по реальному типу). Тип валиден по CHECK-констрейнту схемы; при
                // аномалии падаем и откатываем транзакцию, не трогая данные.
                let ft = FieldType::parse(&ft_s)?;
                let aad = field_aad(&rid, &fid, ft);
                // v1: EncryptedBlob напрямую под master.
                let v1 = EncryptedBlob::from_bytes(&blob_bytes)?;
                let mut plaintext =
                    master.with_decrypted(|decrypted| aead::decrypt(decrypted, &v1, &aad))?;
                let new_blob = field_encrypt(master, &plaintext, &aad)?;
                plaintext.zeroize();
                c.execute(
                    "UPDATE fields SET value_blob = ?1 WHERE id = ?2",
                    rusqlite::params![new_blob, fid],
                )?;
            }
            c.execute_batch(&format!(
                "PRAGMA application_id = {RECORDS_FIELD_V2_APPID}"
            ))?;
            Ok(())
        })();
        match res {
            Ok(()) => {
                c.execute_batch("COMMIT")?;
                Ok(())
            }
            Err(e) => {
                let _ = c.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    })
}

/// N-05: явная проверка, что миграция шифрования полей в v2 действительно
/// выполнена для данной records-БД. Вызывается в командном слое перед
/// раскрытием/записью полей — делает связь «reveal/CRUD ⇐ миграция» явной и
/// громко падает, если будущий рефактор откроет БД в обход миграции (иначе
/// v1-blob'ы молча дали бы AEAD-ошибки, похожие на «запись не найдена»).
pub fn ensure_field_crypto_ready(db: &RecordsDb) -> Result<()> {
    let ready = db.with_conn(|c| {
        let appid: i64 = c.query_row("PRAGMA application_id", [], |r| r.get(0))?;
        let uver: i64 = c.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        Ok(appid == RECORDS_FIELD_V2_APPID as i64 || uver >= RECORDS_FIELD_V2_LEGACY_UVER)
    })?;
    if !ready {
        return Err(VaultError::Internal(
            "records field encryption not migrated to v2 (migrate_field_encryption not run)".into(),
        ));
    }
    Ok(())
}
