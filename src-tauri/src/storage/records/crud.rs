use rusqlite::{params, OptionalExtension};
use uuid::Uuid;

use crate::crypto::master::MasterKey;
use crate::error::{Result, VaultError};
use crate::storage::records_db::{read_revision, HealthFlags, RecordsDb};

use super::{field_aad, field_decrypt, field_encrypt};
use super::{FieldMeta, FieldType, Record, RecordInput};

/// Зафиксировать транзакцию записей. Точка отказа стоит перед COMMIT: при
/// отказе транзакция откатывается целиком, как при смерти процесса.
fn commit(tx: rusqlite::Transaction<'_>) -> Result<()> {
    crate::failpoint::hit("records.commit")?;
    tx.commit()?;
    Ok(())
}

/// Одиночная запись вне явной транзакции (SQLite применяет её атомарно).
fn before_write() -> Result<()> {
    crate::failpoint::hit("records.write")
}

/// Перечислить записи (без полей) с поиском, фильтром категории и пагинацией.
///
/// Фильтр категории и лимит/оффсет — в SQL (раньше категория фильтровалась
/// на клиенте, а лимит был жёстким 1000). Порядок — по пользовательскому
/// `sort_order`, тай-брейк по `updated_at DESC`.
///
/// `category`: None или "all" — все; "work"/"personal" — фильтр.
/// Процесс-локальный ключ для меток повторного использования пароля.
/// Живёт только в памяти текущего запуска и никуда не сохраняется, поэтому
/// метка бесполезна за пределами процесса и не поддаётся словарной атаке.
static REUSE_TAG_KEY: once_cell::sync::Lazy<zeroize::Zeroizing<[u8; 32]>> =
    once_cell::sync::Lazy::new(|| {
        let mut key = zeroize::Zeroizing::new([0u8; 32]);
        crate::crypto::rng::fill(key.as_mut_slice());
        key
    });

fn reuse_tag(value: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(REUSE_TAG_KEY.as_slice())
        .expect("HMAC accepts keys of any length");
    mac.update(value);
    mac.finalize().into_bytes().into()
}

fn is_secret_weak(val: &str) -> bool {
    let s = val.trim();
    if s.is_empty() {
        return false;
    }
    if s.len() < 8 {
        return true;
    }
    let lower = s.to_lowercase();
    lower.contains("12345")
        || lower.contains("qwerty")
        || lower.contains("password")
        || lower.contains("admin")
        || lower == "123456"
        || lower == "12345678"
        || lower == "123456789"
        || lower == "00000000"
}

/// Перечислить записи (без полей) с поиском, фильтром категории и пагинацией.
pub fn list_records(
    db: &RecordsDb,
    master: Option<&MasterKey>,
    enable_health: bool,
    query: Option<&str>,
    category: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<Record>> {
    let mut records = db.with_conn(|c| {
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
    })?;

    if enable_health {
        if let Some(m) = master {
            let flags = health_flags(db, m)?;
            for rec in &mut records {
                rec.has_weak = flags.weak.contains(&rec.id);
                rec.has_reused = flags.reused.contains(&rec.id);
            }
        }
    }

    Ok(records)
}

/// Слабые и повторяющиеся пароли по всей базе.
///
/// Расшифровка каждого секрета дорога, а список запрашивается на каждый
/// символ поиска, поэтому итог кэшируется на ревизии базы: любая запись
/// увеличивает её триггером, и кэш сам перестаёт совпадать. В кэше только
/// идентификаторы записей; plaintext живёт внутри итерации (Zeroizing), а для
/// поиска повторов используется метка на основе процесс-локального случайного
/// ключа, не являющаяся словарным оракулом в дампе.
fn health_flags(db: &RecordsDb, m: &MasterKey) -> Result<std::sync::Arc<HealthFlags>> {
    let current = db.revision()?;
    if let Some(hit) = db.cached_health(current) {
        return Ok(hit);
    }
    // Ревизия и секреты читаются под одной блокировкой соединения: кэш не
    // получит ревизию, не соответствующую прочитанным данным.
    let (revision, secret_fields) = db.with_conn(|c| {
        let revision = read_revision(c)?;
        let mut stmt = c.prepare(
            "SELECT record_id, id, field_type, value_blob FROM fields \
             WHERE is_secret = 1 OR field_type = 'secret'",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?;
        let mut res = Vec::new();
        for r in rows.flatten() {
            res.push(r);
        }
        Ok((revision, res))
    })?;

    use std::collections::HashMap;
    let mut weak_records = std::collections::HashSet::new();
    let mut val_counts: HashMap<[u8; 32], usize> = HashMap::new();
    let mut rec_secrets: Vec<(String, [u8; 32])> = Vec::new();

    for (rid, fid, ft_s, blob) in secret_fields {
        let ft = FieldType::parse(&ft_s).unwrap_or(FieldType::Secret);
        let aad = field_aad(&rid, &fid, ft);
        if let Ok(val) = field_decrypt(m, &blob, &aad) {
            if is_secret_weak(&val) {
                weak_records.insert(rid.clone());
            }
            let tag = reuse_tag(val.as_bytes());
            *val_counts.entry(tag).or_insert(0) += 1;
            rec_secrets.push((rid, tag));
        }
    }

    let reused_vals: std::collections::HashSet<[u8; 32]> = val_counts
        .into_iter()
        .filter(|(_, count)| *count > 1)
        .map(|(tag, _)| tag)
        .collect();

    let mut reused_records = std::collections::HashSet::new();
    for (rid, tag) in rec_secrets {
        if reused_vals.contains(&tag) {
            reused_records.insert(rid);
        }
    }

    let flags = std::sync::Arc::new(HealthFlags {
        weak: weak_records,
        reused: reused_records,
    });
    db.store_health(revision, flags.clone());
    Ok(flags)
}

/// Сохранить пользовательский порядок записей. Присваивает `sort_order`
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
        commit(tx)?;
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
        has_weak: false,
        has_reused: false,
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

/// Ограничения на входные данные записи. Проверяются до любой записи в БД.
pub(crate) fn validate_record_input(input: &RecordInput) -> Result<()> {
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
            return Err(VaultError::BadInput(
                "field label too long (max 256)".into(),
            ));
        }
        if let Some(ref v) = f.value {
            if v.len() > 1_048_576 {
                return Err(VaultError::BadInput(
                    "field value too long (max 1MB)".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Вставить запись с полями внутри уже открытой транзакции.
fn insert_record(
    tx: &rusqlite::Transaction<'_>,
    master: &MasterKey,
    input: &RecordInput,
    now: &str,
    request_id: Option<&str>,
) -> Result<String> {
    if let Some(request_id) = request_id {
        let existing: Option<String> = tx
            .query_row(
                "SELECT id FROM records WHERE request_id = ?1",
                params![request_id],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            return Ok(existing);
        }
    }
    let record_id = Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO records (id, request_id, name, project, icon, color, category, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8)",
        params![
            record_id,
            request_id,
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
    Ok(record_id)
}

/// Создать запись + поля.
///
/// С `request_id` повтор того же запроса возвращает уже созданную запись.
pub fn create_record(
    db: &RecordsDb,
    master: &MasterKey,
    input: &RecordInput,
    request_id: Option<&str>,
) -> Result<String> {
    let mut ids = create_records(db, master, std::slice::from_ref(input), request_id)?;
    Ok(ids.remove(0))
}

/// Создать несколько записей одной транзакцией: либо все, либо ни одной.
///
/// Импорт опирается на это, чтобы после сбоя не оставалось половины файла.
/// С `request_id` запись с номером `i` получает идентификатор
/// `{request_id}:{i}`, и повтор того же запроса дубликатов не создаёт.
pub fn create_records(
    db: &RecordsDb,
    master: &MasterKey,
    inputs: &[RecordInput],
    request_id: Option<&str>,
) -> Result<Vec<String>> {
    for input in inputs {
        validate_record_input(input)?;
    }
    let now = chrono::Utc::now().to_rfc3339();
    db.with_conn(|c| {
        let tx = c.unchecked_transaction()?;
        let mut ids = Vec::with_capacity(inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            let item_request = request_id.map(|id| format!("{id}:{index}"));
            ids.push(insert_record(
                &tx,
                master,
                input,
                &now,
                item_request.as_deref(),
            )?);
        }
        commit(tx)?;
        Ok(ids)
    })
}

/// Положить прежнее значение поля в историю и оставить не более 10 записей.
///
/// Любая ошибка (шифрование, вставка, подрезка) уходит вызывающему: он держит
/// транзакцию, и обновление не должно пройти без записи в историю, о которой
/// пользователь рассчитывает.
fn archive_value(
    tx: &rusqlite::Transaction<'_>,
    master: &MasterKey,
    record_id: &str,
    field_id: &str,
    label: &str,
    value: &str,
    now: &str,
) -> Result<()> {
    let hist_id = Uuid::new_v4().to_string();
    let hist_aad = super::history_aad(record_id, &hist_id);
    let enc_hist = field_encrypt(master, value.as_bytes(), &hist_aad)?;
    tx.execute(
        "INSERT INTO record_password_history \
         (id, record_id, field_id, field_label, encrypted_value, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![hist_id, record_id, field_id, label, enc_hist, now],
    )?;
    tx.execute(
        "DELETE FROM record_password_history \
         WHERE record_id = ?1 AND id NOT IN ( \
            SELECT id FROM record_password_history \
            WHERE record_id = ?1 ORDER BY created_at DESC LIMIT 10 \
         )",
        params![record_id],
    )?;
    Ok(())
}

/// Полная замена записи (используется как UPDATE).
///
/// Идентификатор поля из запроса принимается только для поля, которое уже
/// есть у этой записи. Любой другой (в том числе чужой, принадлежащий другой
/// записи) считается новым полем и получает идентификатор, созданный здесь.
pub fn update_record(
    db: &RecordsDb,
    master: &MasterKey,
    record_id: &str,
    input: &RecordInput,
    enable_password_history: bool,
) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    validate_record_input(input)?;
    // Один идентификатор дважды в запросе — два изменения одного поля: какое
    // из них победит, было бы делом порядка в массиве.
    let mut seen = std::collections::HashSet::new();
    for id in input.fields.iter().filter_map(|f| f.id.as_deref()) {
        if !seen.insert(id) {
            return Err(VaultError::BadInput(
                "duplicate field id in one request".into(),
            ));
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
        //  - поле с `id` этой записи — UPDATE;
        //  - поле без `id` или с чужим — INSERT под новым серверным id;
        //  - поля, отсутствующие во входе → DELETE.
        let existing_ids: std::collections::HashSet<String> = {
            let mut stmt = tx.prepare("SELECT id FROM fields WHERE record_id = ?1")?;
            let rows = stmt.query_map(params![record_id], |r| r.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };
        // (id поля, существует ли оно уже) для каждого поля запроса.
        let resolved: Vec<(String, bool)> = input
            .fields
            .iter()
            .map(|f| match &f.id {
                Some(id) if existing_ids.contains(id) => (id.clone(), true),
                _ => (Uuid::new_v4().to_string(), false),
            })
            .collect();

        // Удаляем поля, которых нет в входе.
        let kept: Vec<&String> = resolved
            .iter()
            .filter(|(_, existing)| *existing)
            .map(|(id, _)| id)
            .collect();
        let placeholders = if kept.is_empty() {
            "''".to_string()
        } else {
            std::iter::repeat_n("?", kept.len())
                .collect::<Vec<_>>()
                .join(",")
        };
        let sql = format!(
            "DELETE FROM fields WHERE record_id = ? AND id NOT IN ({})",
            placeholders
        );
        let mut stmt = tx.prepare(&sql)?;
        let mut args: Vec<&dyn rusqlite::ToSql> = vec![&record_id as &dyn rusqlite::ToSql];
        for id in &kept {
            args.push(*id as &dyn rusqlite::ToSql);
        }
        stmt.execute(args.as_slice())?;
        drop(stmt);

        // INSERT/UPDATE.
        for (f, (field_id, existing)) in input.fields.iter().zip(&resolved) {
            let aad = field_aad(record_id, field_id, f.field_type);

            // Если value=None при UPDATE — оставляем существующий blob.
            let blob_bytes: Option<Vec<u8>> = if let Some(v) = &f.value {
                Some(field_encrypt(master, v.as_bytes(), &aad)?)
            } else {
                None
            };

            if !*existing {
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
                // Если поле секретное — сохраняем старое значение в историю перед записью
                if enable_password_history && (f.is_secret || f.field_type == FieldType::Secret) {
                    let (old_ft_str, old_blob): (String, Vec<u8>) = tx.query_row(
                        "SELECT field_type, value_blob FROM fields WHERE id = ?1 AND record_id = ?2",
                        params![field_id, record_id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )?;
                    let old_ft = FieldType::parse(&old_ft_str)?;
                    let old_aad = field_aad(record_id, field_id, old_ft);
                    // Нечитаемое прежнее значение (повреждённый шифротекст)
                    // не должно мешать записать новое: иначе испорченное поле
                    // нельзя было бы исправить. Архивировать там нечего.
                    match field_decrypt(master, &old_blob, &old_aad) {
                        Ok(old) => {
                            if let Some(new_val) = &f.value {
                                if old.as_str() != new_val && !old.is_empty() {
                                    archive_value(
                                        &tx, master, record_id, field_id, &f.label, &old, &now,
                                    )?;
                                }
                            }
                        }
                        Err(error) => {
                            log::warn!("update_record: previous value is unreadable ({error})");
                        }
                    }
                }

                tx.execute(
                    "UPDATE fields SET field_type = ?2, label = ?3, value_blob = ?4, \
                                       is_secret = ?5, sort_order = ?6, updated_at = ?7 \
                     WHERE id = ?1 AND record_id = ?8",
                    params![
                        field_id,
                        f.field_type.as_str(),
                        f.label,
                        blob,
                        f.is_secret as i64,
                        f.sort_order,
                        now,
                        record_id,
                    ],
                )?;
            } else {
                // Значение не передано — оно не меняется. Но тип поля входит в
                // AAD шифротекста, поэтому при смене типа значение обязано быть
                // перешифровано под новым AAD в этой же транзакции: иначе в
                // строке окажется новый тип и шифротекст под старым AAD, и
                // значение станет нерасшифровываемым навсегда.
                let (old_type, old_blob): (String, Vec<u8>) = tx.query_row(
                    "SELECT field_type, value_blob FROM fields WHERE id = ?1 AND record_id = ?2",
                    params![field_id, record_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let old_type = FieldType::parse(&old_type)?;
                let blob = if old_type == f.field_type {
                    old_blob
                } else {
                    let value = field_decrypt(
                        master,
                        &old_blob,
                        &field_aad(record_id, field_id, old_type),
                    )?;
                    field_encrypt(master, value.as_bytes(), &aad)?
                };
                tx.execute(
                    "UPDATE fields SET field_type = ?2, label = ?3, value_blob = ?4, \
                                       is_secret = ?5, sort_order = ?6, updated_at = ?7 \
                     WHERE id = ?1 AND record_id = ?8",
                    params![
                        field_id,
                        f.field_type.as_str(),
                        f.label,
                        blob,
                        f.is_secret as i64,
                        f.sort_order,
                        now,
                        record_id,
                    ],
                )?;
            }
        }

        commit(tx)?;
        Ok(())
    })
}

/// Получить историю изменения паролей для записи (метаданные без значений).
pub fn get_password_history(
    db: &RecordsDb,
    record_id: &str,
) -> Result<Vec<super::PasswordHistoryEntry>> {
    use super::PasswordHistoryEntry;
    db.with_conn(|c| {
        let mut stmt = c.prepare(
            "SELECT id, field_id, field_label, created_at              FROM record_password_history              WHERE record_id = ?1 ORDER BY created_at DESC LIMIT 10",
        )?;
        let rows = stmt.query_map(params![record_id], |row| {
            Ok(PasswordHistoryEntry {
                id: row.get(0)?,
                record_id: record_id.to_string(),
                field_id: row.get(1)?,
                field_label: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        let mut res = Vec::new();
        for entry in rows {
            res.push(entry?);
        }
        Ok(res)
    })
}

/// Расшифровать одно значение из истории. Результат существует ровно столько,
/// сколько нужно вызывающему (копирование в буфер или восстановление поля).
pub fn reveal_password_history_value(
    db: &RecordsDb,
    master: &MasterKey,
    record_id: &str,
    history_id: &str,
) -> Result<zeroize::Zeroizing<String>> {
    let blob: Vec<u8> = db.with_conn(|c| {
        c.query_row(
            "SELECT encrypted_value FROM record_password_history WHERE id = ?1 AND record_id = ?2",
            params![history_id, record_id],
            |row| row.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => VaultError::RecordNotFound,
            other => other.into(),
        })
    })?;
    field_decrypt(master, &blob, &super::history_aad(record_id, history_id))
}

/// Восстановить значение поля из истории, не выпуская его в webview.
/// Текущее значение поля предварительно архивируется (если история включена).
pub fn restore_password_history(
    db: &RecordsDb,
    master: &MasterKey,
    record_id: &str,
    history_id: &str,
    enable_password_history: bool,
) -> Result<()> {
    let restored = reveal_password_history_value(db, master, record_id, history_id)?;
    let now = chrono::Utc::now().to_rfc3339();

    db.with_conn(|c| {
        let tx = c.unchecked_transaction()?;
        let (field_id, field_type, label, current_blob): (String, String, String, Vec<u8>) = tx
            .query_row(
                "SELECT f.id, f.field_type, f.label, f.value_blob                  FROM record_password_history h                  JOIN fields f ON f.id = h.field_id AND f.record_id = h.record_id                  WHERE h.id = ?1 AND h.record_id = ?2",
                params![history_id, record_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => VaultError::RecordNotFound,
                other => VaultError::from(other),
            })?;

        let field_type = FieldType::parse(&field_type)?;
        let aad = field_aad(record_id, &field_id, field_type);

        // Архивируем текущее значение, чтобы восстановление было обратимым.
        if enable_password_history {
            if let Ok(current) = field_decrypt(master, &current_blob, &aad) {
                if current.as_str() != restored.as_str() && !current.is_empty() {
                    archive_value(&tx, master, record_id, &field_id, &label, &current, &now)?;
                }
            }
        }

        let blob = field_encrypt(master, restored.as_bytes(), &aad)?;
        tx.execute(
            "UPDATE fields SET value_blob = ?1, updated_at = ?2 WHERE id = ?3 AND record_id = ?4",
            params![blob, now, field_id, record_id],
        )?;
        tx.execute(
            "UPDATE records SET updated_at = ?1 WHERE id = ?2",
            params![now, record_id],
        )?;
        commit(tx)?;
        Ok(())
    })
}

/// Очистить историю паролей для записи.
pub fn clear_password_history(db: &RecordsDb, record_id: &str) -> Result<()> {
    before_write()?;
    db.with_conn(|c| {
        c.execute(
            "DELETE FROM record_password_history WHERE record_id = ?1",
            params![record_id],
        )?;
        Ok(())
    })
}

/// Удалить всю историю при отключении функции, чтобы старые plaintext-секреты
/// нельзя было вернуть повторным включением настройки.
pub fn clear_all_password_history(db: &RecordsDb) -> Result<()> {
    before_write()?;
    db.with_conn(|c| {
        c.execute("DELETE FROM record_password_history", [])?;
        Ok(())
    })
}

/// Удалить запись со всеми полями. Идемпотентно: повтор после потерянного
/// ответа находит запись уже удалённой и тоже успешен.
pub fn delete_record(db: &RecordsDb, record_id: &str) -> Result<()> {
    before_write()?;
    db.with_conn(|c| {
        c.execute("DELETE FROM records WHERE id = ?1", params![record_id])?;
        Ok(())
    })
}

/// Удалить несколько записей одной транзакцией: выбранное удаляется целиком
/// или не удаляется вовсе. Идемпотентно, как и `delete_record`.
pub fn delete_records(db: &RecordsDb, record_ids: &[String]) -> Result<usize> {
    db.with_conn(|c| {
        let tx = c.unchecked_transaction()?;
        for id in record_ids {
            tx.execute("DELETE FROM records WHERE id = ?1", params![id])?;
        }
        commit(tx)?;
        Ok(record_ids.len())
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
    use crate::storage::records::field_crypto::FIELD_SALT_LEN;
    use crate::storage::records::FieldInput;
    use crate::storage::records_db::{derive_sqlcipher_key, RecordsDb};

    fn open_db() -> (
        tempfile::TempDir,
        RecordsDb,
        crate::crypto::master::MasterKey,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let master = generate_master_key();
        let key = master.with_decrypted(derive_sqlcipher_key).unwrap();
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

    // Обновление поля с value=None должно СОХРАНИТЬ существующий секрет
    // (не перезаписывать пустой строкой). Это контракт, на который опирается
    // фронтенд-фикс «нетронутое/нерасшифрованное поле → value:null».
    #[test]
    fn update_with_value_none_preserves_secret() {
        let (_dir, db, master) = open_db();
        let rid = create_record(&db, &master, &one_secret_input("super-secret"), None).unwrap();

        let rec = get_record(&db, &rid).unwrap();
        let fid = rec.fields[0].id.clone();

        // Обновляем метаданные записи, поле шлём с value=None (не менять).
        let mut input = one_secret_input("IGNORED");
        input.name = "renamed".into();
        input.fields[0].id = Some(fid.clone());
        input.fields[0].value = None;
        update_record(&db, &master, &rid, &input, true).unwrap();

        // Секрет должен остаться прежним.
        let revealed = reveal_field(&db, &master, &rid, &fid).unwrap();
        assert_eq!(
            &*revealed, "super-secret",
            "value=None не должен затирать секрет"
        );

        // А явное новое значение — заменяет.
        input.fields[0].value = Some("changed".into());
        update_record(&db, &master, &rid, &input, true).unwrap();
        let revealed2 = reveal_field(&db, &master, &rid, &fid).unwrap();
        assert_eq!(
            &*revealed2, "changed",
            "явное значение должно заменять секрет"
        );
    }

    // v2: два шифрования одного значения дают РАЗНЫЕ blob'ы (разная соль+nonce),
    // но оба расшифровываются. Формат — [16 salt][12 nonce][ct+tag].
    #[test]
    fn field_values_use_a_per_blob_salt() {
        let (_dir, _db, master) = open_db();
        let aad = field_aad("r", "f", FieldType::Secret);
        let a = field_encrypt(&master, b"secret", &aad).unwrap();
        let b = field_encrypt(&master, b"secret", &aad).unwrap();
        assert_ne!(a, b, "разная соль/nonce → разные blob'ы");
        assert_ne!(
            &a[..FIELD_SALT_LEN],
            &b[..FIELD_SALT_LEN],
            "соль должна отличаться"
        );
        assert_eq!(&*field_decrypt(&master, &a, &aad).unwrap(), "secret");
        assert_eq!(&*field_decrypt(&master, &b, &aad).unwrap(), "secret");
        // Неверный AAD не расшифровывается.
        let other = field_aad("r", "f2", FieldType::Secret);
        assert!(field_decrypt(&master, &a, &other).is_err());
    }

    // Пользовательский порядок (reorder) + пагинация + фильтр категории.
    #[test]
    fn list_pagination_category_and_reorder() {
        let (_dir, db, master) = open_db();
        let mut ids = Vec::new();
        for n in ["a", "b", "c"] {
            let mut inp = one_secret_input("v");
            inp.name = n.into();
            ids.push(create_record(&db, &master, &inp, None).unwrap());
        }
        // Ставим детерминированный порядок a,b,c (sort_order 0,1,2).
        reorder_records(&db, &ids).unwrap();
        let page1: Vec<String> = list_records(&db, Some(&master), true, None, None, 2, 0)
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(
            page1,
            vec![ids[0].clone(), ids[1].clone()],
            "страница 1 (limit=2)"
        );
        let page2: Vec<String> = list_records(&db, Some(&master), true, None, None, 2, 2)
            .unwrap()
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert_eq!(page2, vec![ids[2].clone()], "страница 2 (offset=2)");

        // Фильтр категории в SQL: все записи personal → work пусто.
        assert_eq!(
            list_records(&db, Some(&master), true, None, Some("work"), 10, 0)
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            list_records(&db, Some(&master), true, None, Some("personal"), 10, 0)
                .unwrap()
                .len(),
            3
        );
        // Поиск + пагинация вместе.
        let found = list_records(&db, Some(&master), true, Some("b"), None, 10, 0).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].id, ids[1]);
    }
}
