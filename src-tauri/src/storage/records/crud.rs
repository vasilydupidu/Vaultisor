use rusqlite::params;
use uuid::Uuid;

use crate::crypto::master::MasterKey;
use crate::error::{Result, VaultError};
use crate::storage::records_db::RecordsDb;

use super::{field_encrypt, field_decrypt, field_aad};
use super::{Record, FieldMeta, FieldType, RecordInput};

/// Перечислить записи (без полей) с поиском, фильтром категории и пагинацией.
///
/// R-05: фильтр категории и лимит/оффсет — в SQL (раньше категория фильтровалась
/// на клиенте, а лимит был жёстким 1000). R-03: порядок — по пользовательскому
/// `sort_order`, тай-брейк по `updated_at DESC`.
///
/// `category`: None или "all" — все; "work"/"personal" — фильтр.
pub fn list_records(
    db: &RecordsDb,
    query: Option<&str>,
    category: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Record>> {
    db.with_conn(|c| {
        let q = query.unwrap_or("").trim();
        let mut where_clauses: Vec<&str> = Vec::new();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

        if !q.is_empty() {
            // HIGH-08: экранируем LIKE-wildcards от pattern-инъекции.
            let escaped = q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
            let pattern = format!("%{}%", escaped);
            where_clauses.push(
                "(name LIKE ? ESCAPE '\\' COLLATE NOCASE OR project LIKE ? ESCAPE '\\' COLLATE NOCASE)",
            );
            params_vec.push(Box::new(pattern.clone()));
            params_vec.push(Box::new(pattern));
        }
        if let Some(cat) = category {
            if cat == "work" || cat == "personal" {
                where_clauses.push("category = ?");
                params_vec.push(Box::new(cat.to_string()));
            }
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };
        let sql = format!(
            "SELECT id, name, project, icon, color, created_at, updated_at, category \
             FROM records {where_sql} \
             ORDER BY sort_order ASC, updated_at DESC LIMIT ? OFFSET ?"
        );
        params_vec.push(Box::new(limit.max(1)));
        params_vec.push(Box::new(offset.max(0)));

        let mut stmt = c.prepare(&sql)?;
        let refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|b| b.as_ref()).collect();
        let rows: rusqlite::Result<Vec<_>> =
            stmt.query_map(refs.as_slice(), map_record)?.collect();
        Ok(rows?)
    })
}

/// R-03: сохранить пользовательский порядок записей. Присваивает `sort_order`
/// по позиции в переданном списке id. Транзакционно.
pub fn reorder_records(db: &RecordsDb, ordered_ids: &[String]) -> Result<()> {
    db.with_conn(|c| {
        let tx = c.unchecked_transaction()?;
        for (i, id) in ordered_ids.iter().enumerate() {
            tx.execute(
                "UPDATE records SET sort_order = ?1 WHERE id = ?2",
                params![i as i64, id],
            )?;
        }
        tx.commit()?;
        Ok(())
    })
}

fn map_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Record> {
    Ok(Record {
        id: row.get(0)?,
        name: row.get(1)?,
        project: row.get(2)?,
        icon: row.get(3)?,
        color: row.get(4)?,
        created_at: row.get(5)?,
        updated_at: row.get(6)?,
        category: row.get(7)?,
        fields: vec![],
    })
}

/// Получить запись с метаданными полей (без plaintext-значений).
pub fn get_record(db: &RecordsDb, record_id: &str) -> Result<Record> {
    db.with_conn(|c| {
        let mut rec = c
            .query_row(
                "SELECT id, name, project, icon, color, created_at, updated_at, category \
                 FROM records WHERE id = ?1",
                params![record_id],
                map_record,
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => VaultError::RecordNotFound,
                other => other.into(),
            })?;
        let mut stmt = c.prepare(
            "SELECT id, field_type, label, is_secret, sort_order, value_blob, \
                    created_at, updated_at \
             FROM fields WHERE record_id = ?1 ORDER BY sort_order ASC",
        )?;
        let fields: rusqlite::Result<Vec<_>> = stmt
            .query_map(params![record_id], |row| {
                let blob: Vec<u8> = row.get(5)?;
                let preview = mask_preview(&blob);
                let ft_s: String = row.get(1)?;
                let ft = FieldType::parse(&ft_s).unwrap_or(FieldType::Custom);
                Ok(FieldMeta {
                    id: row.get(0)?,
                    field_type: ft,
                    label: row.get(2)?,
                    is_secret: row.get::<_, i64>(3)? != 0,
                    sort_order: row.get(4)?,
                    value_preview: preview,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            })?
            .collect();
        rec.fields = fields?;
        Ok(rec)
    })
}

fn mask_preview(_blob: &[u8]) -> String {
    "••••••••".into()
}

/// Создать запись + поля.
pub fn create_record(db: &RecordsDb, master: &MasterKey, input: &RecordInput) -> Result<String> {
    let record_id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    // MED-04: input length validation.
    if input.name.len() > 256 {
        return Err(VaultError::BadInput("name too long (max 256)".into()));
    }
    if let Some(ref p) = input.project {
        if p.len() > 256 {
            return Err(VaultError::BadInput("project too long (max 256)".into()));
        }
    }
    for f in &input.fields {
        if f.label.len() > 256 {
            return Err(VaultError::BadInput("field label too long (max 256)".into()));
        }
        if let Some(ref v) = f.value {
            if v.len() > 1_048_576 {
                return Err(VaultError::BadInput("field value too long (max 1MB)".into()));
            }
        }
    }

    db.with_conn(|c| {
        let tx = c.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO records (id, name, project, icon, color, category, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                record_id,
                input.name.trim(),
                input.project.as_deref().map(|s| s.trim()),
                input.icon,
                input.color,
                input.category.as_deref().unwrap_or("personal"),
                now,
            ],
        )?;

        for f in &input.fields {
            let field_id = Uuid::new_v4().to_string();
            let value = f
                .value
                .as_deref()
                .ok_or_else(|| VaultError::BadInput("field without value".into()))?;
            let aad = field_aad(&record_id, &field_id, f.field_type);
            let blob = field_encrypt(master, value.as_bytes(), &aad)?;
            tx.execute(
                "INSERT INTO fields (id, record_id, field_type, label, value_blob, \
                                     is_secret, sort_order, created_at, updated_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                params![
                    field_id,
                    record_id,
                    f.field_type.as_str(),
                    f.label,
                    blob,
                    f.is_secret as i64,
                    f.sort_order,
                    now,
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    })?;

    Ok(record_id)
}

/// Полная замена записи (используется как UPDATE).
pub fn update_record(
    db: &RecordsDb,
    master: &MasterKey,
    record_id: &str,
    input: &RecordInput,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();

    // MED-04: input length validation.
    if input.name.len() > 256 {
        return Err(VaultError::BadInput("name too long (max 256)".into()));
    }
    if let Some(ref p) = input.project {
        if p.len() > 256 {
            return Err(VaultError::BadInput("project too long (max 256)".into()));
        }
    }
    for f in &input.fields {
        if f.label.len() > 256 {
            return Err(VaultError::BadInput("field label too long (max 256)".into()));
        }
        if let Some(ref v) = f.value {
            if v.len() > 1_048_576 {
                return Err(VaultError::BadInput("field value too long (max 1MB)".into()));
            }
        }
    }
    db.with_conn(|c| {
        let tx = c.unchecked_transaction()?;

        // Проверка существования.
        let exists: i64 = tx.query_row(
            "SELECT COUNT(*) FROM records WHERE id = ?1",
            params![record_id],
            |r| r.get(0),
        )?;
        if exists == 0 {
            return Err(VaultError::RecordNotFound);
        }

        tx.execute(
            "UPDATE records SET name = ?2, project = ?3, icon = ?4, color = ?5, category = ?6, updated_at = ?7 \
             WHERE id = ?1",
            params![
                record_id,
                input.name.trim(),
                input.project.as_deref().map(|s| s.trim()),
                input.icon,
                input.color,
                input.category.as_deref().unwrap_or("personal"),
                now,
            ],
        )?;

        // Стратегия для полей:
        //  - Поля с `id` — UPDATE.
        //  - Поля без `id` — INSERT.
        //  - Поля, отсутствующие во входе → DELETE.
        let incoming_ids: Vec<String> = input.fields.iter().filter_map(|f| f.id.clone()).collect();

        // Удаляем поля, которых нет в входе.
        let placeholders = if incoming_ids.is_empty() {
            "''".to_string()
        } else {
            std::iter::repeat("?")
                .take(incoming_ids.len())
                .collect::<Vec<_>>()
                .join(",")
        };
        let sql = format!(
            "DELETE FROM fields WHERE record_id = ? AND id NOT IN ({})",
            placeholders
        );
        let mut stmt = tx.prepare(&sql)?;
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&record_id as &dyn rusqlite::ToSql];
        for id in &incoming_ids {
            args.push(id as &dyn rusqlite::ToSql);
        }
        stmt.execute(args.as_slice())?;
        drop(stmt);

        // INSERT/UPDATE.
        for f in &input.fields {
            let field_id = f.id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());
            let aad = field_aad(record_id, &field_id, f.field_type);

            // Если value=None при UPDATE — оставляем существующий blob.
            let blob_bytes: Option<Vec<u8>> = if let Some(v) = &f.value {
                Some(field_encrypt(master, v.as_bytes(), &aad)?)
            } else {
                None
            };

            // upsert.
            let already: i64 = tx.query_row(
                "SELECT COUNT(*) FROM fields WHERE id = ?1 AND record_id = ?2",
                params![field_id, record_id],
                |r| r.get(0),
            )?;
            if already == 0 {
                let blob = blob_bytes
                    .ok_or_else(|| VaultError::BadInput("new field requires value".into()))?;
                tx.execute(
                    "INSERT INTO fields (id, record_id, field_type, label, value_blob, \
                                         is_secret, sort_order, created_at, updated_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
                    params![
                        field_id,
                        record_id,
                        f.field_type.as_str(),
                        f.label,
                        blob,
                        f.is_secret as i64,
                        f.sort_order,
                        now,
                    ],
                )?;
            } else if let Some(blob) = blob_bytes {
                tx.execute(
                    "UPDATE fields SET field_type = ?2, label = ?3, value_blob = ?4, \
                                       is_secret = ?5, sort_order = ?6, updated_at = ?7 \
                     WHERE id = ?1",
                    params![
                        field_id,
                        f.field_type.as_str(),
                        f.label,
                        blob,
                        f.is_secret as i64,
                        f.sort_order,
                        now,
                    ],
                )?;
            } else {
                tx.execute(
                    "UPDATE fields SET field_type = ?2, label = ?3, \
                                       is_secret = ?4, sort_order = ?5, updated_at = ?6 \
                     WHERE id = ?1",
                    params![
                        field_id,
                        f.field_type.as_str(),
                        f.label,
                        f.is_secret as i64,
                        f.sort_order,
                        now,
                    ],
                )?;
            }
        }

        tx.commit()?;
        Ok(())
    })
}

/// Удалить запись со всеми полями.
pub fn delete_record(db: &RecordsDb, record_id: &str) -> Result<()> {
    db.with_conn(|c| {
        let n = c.execute("DELETE FROM records WHERE id = ?1", params![record_id])?;
        if n == 0 {
            return Err(VaultError::RecordNotFound);
        }
        Ok(())
    })
}

/// Расшифровать конкретное поле и вернуть plaintext.
/// Этот результат немедленно отправляется во фронт; держать его на бэке
/// дольше необходимого не нужно.
pub fn reveal_field(
    db: &RecordsDb,
    master: &MasterKey,
    record_id: &str,
    field_id: &str,
) -> Result<zeroize::Zeroizing<String>> {
    let (ft_s, blob_bytes): (String, Vec<u8>) = db.with_conn(|c| {
        let row = c.query_row(
            "SELECT field_type, value_blob FROM fields WHERE id = ?1 AND record_id = ?2",
            params![field_id, record_id],
            |row| {
                let ft: String = row.get(0)?;
                let blob: Vec<u8> = row.get(1)?;
                Ok((ft, blob))
            },
        );
        match row {
            Ok(v) => Ok(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => Err(VaultError::RecordNotFound),
            Err(e) => Err(e.into()),
        }
    })?;
    let ft = FieldType::parse(&ft_s)?;
    let aad = field_aad(record_id, field_id, ft);
    // v2-формат: соль + AEAD на per-blob субключе (см. field_decrypt).
    field_decrypt(master, &blob_bytes, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::master::generate_master_key;
    use crate::storage::records_db::{derive_sqlcipher_key, RecordsDb};
    use crate::crypto::aead::{self, NONCE_LEN, TAG_LEN};
    use crate::storage::records::{migrate_field_encryption, ensure_field_crypto_ready, FIELD_SALT_LEN, FieldInput};

    fn open_db() -> (tempfile::TempDir, RecordsDb, crate::crypto::master::MasterKey) {
        let dir = tempfile::tempdir().unwrap();
        let master = generate_master_key();
        let key = master
            .with_decrypted(|d| derive_sqlcipher_key(d))
            .unwrap();
        let db = RecordsDb::open(&dir.path().join("t.records.db"), &key).unwrap();
        (dir, db, master)
    }

    fn one_secret_input(value: &str) -> RecordInput {
        RecordInput {
            name: "rec".into(),
            project: None,
            icon: None,
            color: None,
            category: Some("personal".into()),
            fields: vec![FieldInput {
                id: None,
                field_type: FieldType::Secret,
                label: "S".into(),
                is_secret: true,
                sort_order: 0,
                value: Some(value.into()),
            }],
        }
    }

    // H-01: обновление поля с value=None должно СОХРАНИТЬ существующий секрет
    // (не перезаписывать пустой строкой). Это контракт, на который опирается
    // фронтенд-фикс «нетронутое/нерасшифрованное поле → value:null».
    #[test]
    fn update_with_value_none_preserves_secret() {
        let (_dir, db, master) = open_db();
        let rid = create_record(&db, &master, &one_secret_input("super-secret")).unwrap();

        let rec = get_record(&db, &rid).unwrap();
        let fid = rec.fields[0].id.clone();

        // Обновляем метаданные записи, поле шлём с value=None (не менять).
        let mut input = one_secret_input("IGNORED");
        input.name = "renamed".into();
        input.fields[0].id = Some(fid.clone());
        input.fields[0].value = None;
        update_record(&db, &master, &rid, &input).unwrap();

        // Секрет должен остаться прежним.
        let revealed = reveal_field(&db, &master, &rid, &fid).unwrap();
        assert_eq!(&*revealed, "super-secret", "value=None не должен затирать секрет");

        // А явное новое значение — заменяет.
        input.fields[0].value = Some("changed".into());
        update_record(&db, &master, &rid, &input).unwrap();
        let revealed2 = reveal_field(&db, &master, &rid, &fid).unwrap();
        assert_eq!(&*revealed2, "changed", "явное значение должно заменять секрет");
    }

    // v2: два шифрования одного значения дают РАЗНЫЕ blob'ы (разная соль+nonce),
    // но оба расшифровываются. Формат — [16 salt][12 nonce][ct+tag].
    #[test]
    fn field_v2_uses_per_blob_salt() {
        let (_dir, _db, master) = open_db();
        let aad = field_aad("r", "f", FieldType::Secret);
        let a = field_encrypt(&master, b"secret", &aad).unwrap();
        let b = field_encrypt(&master, b"secret", &aad).unwrap();
        assert_ne!(a, b, "разная соль/nonce → разные blob'ы");
        assert_ne!(&a[..FIELD_SALT_LEN], &b[..FIELD_SALT_LEN], "соль должна отличаться");
        assert_eq!(&*field_decrypt(&master, &a, &aad).unwrap(), "secret");
        assert_eq!(&*field_decrypt(&master, &b, &aad).unwrap(), "secret");
        // Неверный AAD не расшифровывается.
        let other = field_aad("r", "f2", FieldType::Secret);
        assert!(field_decrypt(&master, &a, &other).is_err());
    }

    // Backward-compat: существующие v1-blob'ы (AES-GCM напрямую master)
    // мигрируются в v2 и остаются читаемыми. Миграция идемпотентна.
    #[test]
    fn migrates_v1_field_blob_to_v2() {
        let (_dir, db, master) = open_db();
        let rid = "rec1";
        let fid = "f1";
        let now = "2026-01-01T00:00:00Z";
        let aad = field_aad(rid, fid, FieldType::Secret);
        // v1-blob: EncryptedBlob напрямую под master (старый формат).
        let v1 = master
            .with_decrypted(|d| aead::encrypt(d, b"legacy-secret", &aad))
            .unwrap()
            .to_bytes();
        db.with_conn(|c| {
            c.execute(
                "INSERT INTO records (id,name,project,icon,color,category,created_at,updated_at) \
                 VALUES (?1,'r',NULL,NULL,NULL,'personal',?2,?2)",
                rusqlite::params![rid, now],
            )?;
            c.execute(
                "INSERT INTO fields (id,record_id,field_type,label,value_blob,is_secret,sort_order,created_at,updated_at) \
                 VALUES (?1,?2,'secret','L',?3,1,0,?4,?4)",
                rusqlite::params![fid, rid, v1, now],
            )?;
            // Симулируем «до миграции».
            c.execute_batch("PRAGMA user_version = 2")?;
            Ok(())
        })
        .unwrap();

        migrate_field_encryption(&db, &master).unwrap();

        // Значение читается через v2-путь.
        let revealed = reveal_field(&db, &master, rid, fid).unwrap();
        assert_eq!(&*revealed, "legacy-secret", "v1-секрет должен пережить миграцию");

        // Blob теперь в v2-формате (длиннее на соль).
        let new_len: i64 = db
            .with_conn(|c| {
                Ok(c.query_row(
                    "SELECT length(value_blob) FROM fields WHERE id=?1",
                    rusqlite::params![fid],
                    |r| r.get(0),
                )?)
            })
            .unwrap();
        assert!(new_len as usize >= FIELD_SALT_LEN + NONCE_LEN + TAG_LEN + 13);

        // Повторный вызов — no-op (маркер application_id уже проставлен).
        migrate_field_encryption(&db, &master).unwrap();
        let again = reveal_field(&db, &master, rid, fid).unwrap();
        assert_eq!(&*again, "legacy-secret");
    }

    // N-02: маркер миграции живёт в application_id; user_version (схемная версия)
    // не трогается. ensure_field_crypto_ready до миграции — ошибка, после — ок.
    #[test]
    fn migration_marks_application_id_not_user_version() {
        let (_dir, db, master) = open_db(); // apply → user_version=2, application_id=0
        assert!(ensure_field_crypto_ready(&db).is_err(), "до миграции не готова");
        migrate_field_encryption(&db, &master).unwrap(); // пустая БД → ставит appid
        ensure_field_crypto_ready(&db).unwrap();
        let uver: i64 = db
            .with_conn(|c| Ok(c.query_row("PRAGMA user_version", [], |r| r.get(0))?))
            .unwrap();
        assert_eq!(uver, 2, "миграция полей не должна менять схемную user_version");
    }

    // N-02 back-compat: БД, помеченная СТАРОЙ версией через user_version>=3 и с
    // настоящими v2-blob'ами, НЕ должна пере-мигрироваться (иначе v2 расшифруется
    // как v1 → крах) и должна считаться готовой.
    #[test]
    fn legacy_uver3_marker_is_respected() {
        let (_dir, db, master) = open_db();
        let rid = create_record(&db, &master, &one_secret_input("keep-me")).unwrap();
        let fid = get_record(&db, &rid).unwrap().fields[0].id.clone();
        // Симулируем легаси-маркер: user_version=3, application_id обнулён.
        db.with_conn(|c| {
            c.execute_batch("PRAGMA user_version = 3; PRAGMA application_id = 0;")?;
            Ok(())
        })
        .unwrap();
        // Миграция — no-op (v2-blob не трогается).
        migrate_field_encryption(&db, &master).unwrap();
        ensure_field_crypto_ready(&db).unwrap();
        assert_eq!(&*reveal_field(&db, &master, &rid, &fid).unwrap(), "keep-me");
    }

    // R-03/R-05: пользовательский порядок (reorder) + пагинация + фильтр категории.
    #[test]
    fn list_pagination_category_and_reorder() {
        let (_dir, db, master) = open_db();
        let mut ids = Vec::new();
        for n in ["a", "b", "c"] {
            let mut inp = one_secret_input("v");
            inp.name = n.into();
            ids.push(create_record(&db, &master, &inp).unwrap());
        }
        // Ставим детерминированный порядок a,b,c (sort_order 0,1,2).
        reorder_records(&db, &ids).unwrap();
        let page1: Vec<String> = list_records(&db, None, None, 2, 0)
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(page1, vec![ids[0].clone(), ids[1].clone()], "страница 1 (limit=2)");
        let page2: Vec<String> = list_records(&db, None, None, 2, 2)
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(page2, vec![ids[2].clone()], "страница 2 (offset=2)");

        // Фильтр категории в SQL: все записи personal → work пусто.
        assert_eq!(list_records(&db, None, Some("work"), 10, 0).unwrap().len(), 0);
        assert_eq!(
            list_records(&db, None, Some("personal"), 10, 0).unwrap().len(),
            3
        );
        // Поиск + пагинация вместе.
        let found = list_records(&db, Some("b"), None, 10, 0).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, ids[1]);
    }
}
