// Команда импорта паролей из Chromium-браузеров (Chrome, Opera, Yandex, Edge)
// и безопасного удаления сырого CSV-файла с диска.

use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

use serde::Serialize;
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::records::{create_records, FieldInput, FieldType, RecordInput};

/// Строка CSV, которую не удалось перенести, и почему.
#[derive(Debug, Clone, Serialize)]
pub struct RejectedRow {
    /// Номер строки данных (без заголовка), с единицы.
    pub row: usize,
    pub site: String,
    pub reason: String,
}

/// Итог импорта. Отчитывается о каждой строке файла: `imported` + число
/// отклонённых = `total`.
#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub total: usize,
    pub imported: usize,
    pub rejected: Vec<RejectedRow>,
    pub imported_ids: Vec<String>,
    /// Разрешение затереть исходный CSV. Выдаётся только при полном импорте:
    /// файл, из которого что-то не перенеслось, — единственная копия этих
    /// паролей, и предлагать его уничтожить нельзя.
    pub deletion_token: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ChromiumEntry {
    /// Номер строки данных, с единицы.
    row: usize,
    name: String,
    url: String,
    username: String,
    password: String,
    note: String,
}

/// Разобрать CSV-экспорт Chromium.
///
/// Раньше файл резался по `lines()`, поэтому запись с переводом
/// строки внутри кавычек (Chrome так экспортирует многострочные заметки)
/// разваливалась на несколько «строк», и импорт молча портил данные или терял
/// пароли. Теперь весь файл разбирается одним проходом с учётом кавычек.
pub(crate) fn parse_chromium_csv(content: &str) -> Vec<ChromiumEntry> {
    let mut entries = Vec::new();
    let mut rows = parse_csv_rows(content).into_iter();

    let headers: Vec<String> = match rows.next() {
        Some(header) => header.into_iter().map(|h| h.to_lowercase()).collect(),
        None => return entries,
    };

    let name_idx = headers.iter().position(|h| h == "name" || h == "title");
    let url_idx = headers.iter().position(|h| h == "url");
    let user_idx = headers
        .iter()
        .position(|h| h == "username" || h == "login" || h == "user");
    let pass_idx = headers.iter().position(|h| h == "password" || h == "pass");
    let note_idx = headers
        .iter()
        .position(|h| h == "note" || h == "notes" || h == "comment");

    let Some(pass_idx) = pass_idx else {
        return entries;
    };

    for (index, cols) in rows.enumerate() {
        if cols.is_empty() || cols.iter().all(|c| c.trim().is_empty()) {
            continue;
        }

        let get_col = |idx: Option<usize>| -> String {
            idx.and_then(|i| cols.get(i))
                .map(|s| s.trim().to_string())
                .unwrap_or_default()
        };

        // Строка без пароля не пропускается молча: логин и адрес — тоже данные,
        // и при затирании исходника они пропали бы. Она уходит в отклонённые.
        let password = cols
            .get(pass_idx)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        let mut url = get_col(url_idx);
        let raw_name = get_col(name_idx);
        let username = get_col(user_idx);
        let note = get_col(note_idx);

        if !url.is_empty() && !url.starts_with("http://") && !url.starts_with("https://") {
            url = format!("https://{}", url);
        }

        // Очищаем и извлекаем аккуратный чистый домен для названия записи
        let name = extract_clean_domain(&raw_name, &url);

        entries.push(ChromiumEntry {
            row: index + 1,
            name,
            url,
            username,
            password,
            note,
        });
    }

    entries
}

/// Разбить CSV на строки и поля, уважая кавычки (включая переводы строк внутри).
fn parse_csv_rows(content: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                row.push(std::mem::take(&mut field));
            }
            '\r' if !in_quotes => {
                // CRLF: сам перевод строки обработает следующая итерация.
            }
            '\n' if !in_quotes => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            _ => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Двухуровневые публичные суффиксы, встречающиеся в паролях чаще всего.
/// Полный Public Suffix List тянуть в офлайн-приложение избыточно, а без
/// этого списка `bbc.co.uk` превращался в бесполезное имя «co.uk».
const MULTI_LEVEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk", "com.au", "net.au",
    "org.au", "edu.au", "gov.au", "co.nz", "net.nz", "org.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
    "go.jp", "com.br", "net.br", "org.br", "com.cn", "net.cn", "org.cn", "gov.cn", "co.in",
    "net.in", "org.in", "com.tr", "com.mx", "com.ar", "com.sg", "com.hk", "co.za", "co.kr",
    "com.ua", "net.ua", "org.ua", "com.pl", "net.pl", "org.pl",
];

/// Извлечь чистое корневое доменное имя сайта (например, openai.com вместо
/// auth.openai.com) или название записи.
fn extract_clean_domain(raw_name: &str, url: &str) -> String {
    let candidate = if !url.is_empty() {
        url
    } else if !raw_name.is_empty() {
        raw_name
    } else {
        return "Импортированный сайт".to_string();
    };

    let clean = candidate
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_start_matches("www.");

    let host = clean
        .split(&['/', ':', '?'][..])
        .next()
        .unwrap_or(clean)
        .trim();
    if host.is_empty() {
        return "Импортированный сайт".to_string();
    }

    let lower = host.to_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() < 3 {
        return lower;
    }

    // Для доменов вида bbc.co.uk два последних компонента дают
    // публичный суффикс, а не имя сайта. Берём на один уровень выше.
    let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
    if MULTI_LEVEL_SUFFIXES.contains(&last_two.as_str()) {
        return format!("{}.{}", parts[parts.len() - 3], last_two);
    }
    last_two
}

/// Импорт паролей из Chromium CSV в веб-базу (vault.web.db).
#[tauri::command]
pub async fn import_chromium_csv(
    capability: String,
    state: State<'_, AppState>,
) -> Result<ImportResult> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let (requested_path, initial) = {
        let session = state.session.lock();
        let stamp =
            crate::commands::file_grants::session_stamp(&session).ok_or(VaultError::Locked)?;
        let path = state.file_grants.lock().consume(
            &capability,
            crate::commands::file_grants::FileOperation::CsvImport,
            Some(stamp),
        )?;
        (path, stamp)
    };
    let requested_path = requested_path.as_path();
    if !requested_path.exists() {
        return Err(VaultError::BadInput("Файл не найден".into()));
    }

    let link_meta = std::fs::symlink_metadata(requested_path)?;
    if link_meta.file_type().is_symlink() || !link_meta.is_file() {
        return Err(VaultError::BadInput(
            "Разрешён только обычный CSV-файл".into(),
        ));
    }
    if requested_path
        .extension()
        .and_then(|v| v.to_str())
        .map(|v| v.eq_ignore_ascii_case("csv"))
        != Some(true)
    {
        return Err(VaultError::BadInput(
            "Файл импорта должен иметь расширение .csv".into(),
        ));
    }
    if link_meta.len() > 50 * 1024 * 1024 {
        return Err(VaultError::BadInput(
            "CSV-файл превышает лимит 50 МБ".into(),
        ));
    }
    let canonical_path = std::fs::canonicalize(requested_path)?;

    // CSV целиком состоит из паролей в открытом виде. Держим его
    // в Zeroizing, чтобы буфер был затёрт при выходе из команды, а не остался
    // в куче процесса до следующего аллокатора.
    let mut file = File::open(&canonical_path)?;
    let mut content = zeroize::Zeroizing::new(String::new());
    file.read_to_string(&mut content)?;

    let entries = parse_chromium_csv(&content);
    if entries.is_empty() {
        return Err(VaultError::BadInput(
            "Не найдено паролей для импорта или некорректный формат CSV".into(),
        ));
    }

    if state.check_autolock() {
        return Err(VaultError::Locked);
    }
    let mut result = {
        let session = state.session.lock();
        if crate::commands::file_grants::session_stamp(&session) != Some(initial) {
            return Err(VaultError::Locked);
        }
        match &*session {
            SessionState::Unlocked {
                master_key, web_db, ..
            } => {
                let request_id = format!("csv-{}", hex::encode(Sha256::digest(content.as_bytes())));
                import_entries(web_db, master_key, entries, Some(&request_id))?
            }
            _ => return Err(VaultError::Locked),
        }
    };

    if result.rejected.is_empty() && result.imported == result.total {
        let digest: [u8; 32] = Sha256::digest(content.as_bytes()).into();
        let deletion_token = uuid::Uuid::new_v4().to_string();
        state.pending_import_deletions.lock().insert(
            deletion_token.clone(),
            crate::state::PendingImportDeletion {
                canonical_path,
                sha256: digest,
                length: content.len() as u64,
            },
        );
        result.deletion_token = Some(deletion_token);
    }
    Ok(result)
}

/// Предел длины полей записи (как в `validate_record_input`).
const TEXT_MAX: usize = 256;

/// Обрезать строку до `max` байт по границе символа.
fn truncate_to(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

/// Хост из URL без схемы, пути и параметров.
fn url_host(url: &str) -> &str {
    let without_scheme = url
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    without_scheme
        .split(&['/', '?', '#'][..])
        .next()
        .unwrap_or(without_scheme)
}

/// Превратить строку CSV в запись или объяснить, почему это невозможно.
///
/// Полный URL сохраняется в поле «URL сайта», где предел — мегабайт, а в
/// метаданные записи (`project`, предел 256) идёт хост. Раньше туда шёл
/// URL целиком, и строки с длинными адресами входа молча отвергались.
fn entry_to_input(entry: &ChromiumEntry) -> std::result::Result<RecordInput, String> {
    if entry.password.is_empty() {
        return Err("пустой пароль".into());
    }
    let mut fields = Vec::new();
    let mut push = |label: &str, field_type: FieldType, value: &str, is_secret: bool| {
        let sort_order = fields.len() as i64;
        fields.push(FieldInput {
            id: None,
            label: label.into(),
            field_type,
            value: Some(value.to_owned()),
            is_secret,
            sort_order,
        });
    };
    if !entry.username.is_empty() {
        push("Логин", FieldType::Custom, &entry.username, false);
    }
    push("Пароль", FieldType::Secret, &entry.password, true);
    if !entry.url.is_empty() {
        push("URL сайта", FieldType::Custom, &entry.url, false);
    }
    if !entry.note.is_empty() {
        push("Заметка", FieldType::Comment, &entry.note, false);
    }
    let input = RecordInput {
        name: truncate_to(&entry.name, TEXT_MAX),
        project: (!entry.url.is_empty()).then(|| truncate_to(url_host(&entry.url), TEXT_MAX)),
        icon: None,
        color: None,
        category: Some("personal".into()),
        fields,
    };
    crate::storage::records::validate_record_input(&input).map_err(|error| error.to_string())?;
    Ok(input)
}

/// Перенести разобранные строки в базу паролей сайтов одной транзакцией.
///
/// Проверка каждой строки выполняется до записи; все прошедшие проверку
/// вставляются вместе или не вставляются вовсе, поэтому после сбоя нет
/// половины импорта, а повторный импорт не дублирует записи.
///
/// `request_id` выводится из содержимого файла: повторный импорт того же
/// CSV (в том числе после потерянного ответа) не создаёт дубликатов.
pub(crate) fn import_entries(
    db: &crate::storage::records_db::RecordsDb,
    master: &crate::crypto::master::MasterKey,
    entries: Vec<ChromiumEntry>,
    request_id: Option<&str>,
) -> Result<ImportResult> {
    let total = entries.len();
    let mut rejected = Vec::new();
    let mut inputs = Vec::new();
    for entry in &entries {
        match entry_to_input(entry) {
            Ok(input) => inputs.push(input),
            Err(reason) => rejected.push(RejectedRow {
                row: entry.row,
                site: truncate_to(&entry.name, TEXT_MAX),
                reason,
            }),
        }
    }
    drop(entries);

    let imported_ids = if inputs.is_empty() {
        Vec::new()
    } else {
        create_records(db, master, &inputs, request_id)?
    };
    // Значения уже зашифрованы и записаны; открытые копии больше не нужны.
    for input in inputs.iter_mut() {
        for field in input.fields.iter_mut() {
            if let Some(value) = field.value.as_mut() {
                zeroize::Zeroize::zeroize(value);
            }
        }
    }
    Ok(ImportResult {
        total,
        imported: imported_ids.len(),
        rejected,
        imported_ids,
        deletion_token: None,
    })
}

/// Безопасное шредирование (затирание и удаление) файла с диска.
#[tauri::command]
pub async fn secure_delete_file(deletion_token: String, state: State<'_, AppState>) -> Result<()> {
    if state.check_autolock() || !state.session.lock().is_unlocked() {
        return Err(VaultError::Locked);
    }
    let pending = state
        .pending_import_deletions
        .lock()
        .remove(&deletion_token)
        .ok_or_else(|| {
            VaultError::BadInput(
                "Недействительное или уже использованное разрешение на удаление".into(),
            )
        })?;
    secure_delete_authorized_file(pending)
}

/// Исполнитель удаления принимает только server-side receipt, созданный
/// успешным импортом. Функция публична для security regression tests, но не
/// зарегистрирована как Tauri command.
pub fn secure_delete_authorized_file(pending: crate::state::PendingImportDeletion) -> Result<()> {
    let path = pending.canonical_path;
    let link_meta = std::fs::symlink_metadata(&path)?;
    if link_meta.file_type().is_symlink()
        || !link_meta.is_file()
        || link_meta.len() != pending.length
    {
        return Err(VaultError::BadInput(
            "Файл изменился после импорта; удаление отменено".into(),
        ));
    }
    // Validate and overwrite through one handle so a path swap cannot change
    // the file between hashing and shredding.
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != pending.length {
        return Err(VaultError::BadInput(
            "Файл изменился после импорта; удаление отменено".into(),
        ));
    }
    let mut current = Vec::with_capacity(pending.length as usize);
    file.read_to_end(&mut current)?;
    let current_digest: [u8; 32] = Sha256::digest(&current).into();
    if current_digest != pending.sha256 {
        return Err(VaultError::BadInput(
            "Содержимое файла изменилось после импорта; удаление отменено".into(),
        ));
    }
    let len = pending.length;

    if len > 0 {
        file.seek(SeekFrom::Start(0))?;
        let overwrite = core_shared::rng::random_vec(len.min(1024 * 1024) as usize);
        let mut written = 0;
        while written < len {
            let to_write = (len - written).min(overwrite.len() as u64) as usize;
            file.write_all(&overwrite[..to_write])?;
            written += to_write as u64;
        }
        file.flush()?;
        file.sync_all()?;
    }

    drop(file);
    std::fs::remove_file(&path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn records_db() -> (
        tempfile::TempDir,
        crate::storage::records_db::RecordsDb,
        crate::crypto::master::MasterKey,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let master = crate::crypto::master::generate_master_key();
        let key = master
            .with_decrypted(crate::storage::records_db::derive_sqlcipher_key)
            .unwrap();
        let db =
            crate::storage::records_db::RecordsDb::open(&dir.path().join("web.db"), &key).unwrap();
        (dir, db, master)
    }

    /// Адрес входа длиннее 256 символов раньше молча отвергал строку, а
    /// интерфейс сразу предлагал затереть исходник. Теперь строка переносится,
    /// полный адрес сохраняется в поле, а в метаданные идёт хост.
    #[test]
    fn long_login_urls_are_imported_with_the_full_url_kept() {
        let (_dir, db, master) = records_db();
        let long = format!(
            "https://accounts.example.com/signin?continue={}",
            "a".repeat(400)
        );
        let csv = format!("name,url,username,password\nExample,{long},user,P4ss\n");
        let result = import_entries(&db, &master, parse_chromium_csv(&csv), None).unwrap();
        assert_eq!((result.total, result.imported), (1, 1));
        assert!(result.rejected.is_empty());

        let record = crate::storage::records::get_record(&db, &result.imported_ids[0]).unwrap();
        let url_field = record
            .fields
            .iter()
            .find(|f| f.label == "URL сайта")
            .unwrap();
        let stored =
            crate::storage::records::reveal_field(&db, &master, &record.id, &url_field.id).unwrap();
        assert_eq!(stored.as_str(), long, "полный URL не должен обрезаться");
    }

    /// Строки, которые перенести нельзя, называются поимённо, и тогда
    /// разрешения затереть исходник нет.
    #[test]
    fn partial_import_reports_every_rejected_row() {
        let (_dir, db, master) = records_db();
        let huge = "x".repeat(1_048_577);
        let csv = format!(
            "name,url,username,password\nGood,https://a.example,u,P1\nNoPass,https://b.example,u,\nHuge,https://c.example,u,{huge}\n"
        );
        let result = import_entries(&db, &master, parse_chromium_csv(&csv), None).unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.imported, 1);
        assert_eq!(
            result.rejected.iter().map(|r| r.row).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(result.deletion_token.is_none());
    }

    #[test]
    fn test_parse_chromium_csv() {
        let csv = "name,url,username,password,note
                   https://www.google.com/auth,https://google.com,testuser,Secret123,my note
                   GitHub,https://github.com/login,gituser,Pass456,
";
        let entries = parse_chromium_csv(csv);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "google.com");
        assert_eq!(entries[0].username, "testuser");
        assert_eq!(entries[0].password, "Secret123");
        assert_eq!(entries[0].note, "my note");
        assert_eq!(entries[1].name, "github.com");
    }

    /// Chrome экспортирует многострочные заметки в кавычках.
    /// Построчный разбор ломал такие записи и терял пароли следующих строк.
    #[test]
    fn multiline_quoted_fields_do_not_break_rows() {
        let csv = "name,url,username,password,note
                   Site,https://site.example,user1,Pass1,\"first line
second line\"
                   Other,https://other.example,user2,Pass2,plain
";
        let entries = parse_chromium_csv(csv);
        assert_eq!(
            entries.len(),
            2,
            "многострочная заметка не должна рвать CSV"
        );
        assert_eq!(
            entries[0].note,
            "first line
second line"
        );
        assert_eq!(entries[1].username, "user2");
        assert_eq!(entries[1].password, "Pass2");
    }

    #[test]
    fn quoted_commas_and_escaped_quotes_survive() {
        let csv = "name,url,username,password,note
                   Site,https://site.example,\"last, first\",\"pa,ss\"\"word\",note
";
        let entries = parse_chromium_csv(csv);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].username, "last, first");
        assert_eq!(entries[0].password, "pa,ss\"word");
    }

    #[test]
    fn crlf_line_endings_are_handled() {
        let csv = "name,url,username,password\r\nSite,https://site.example,u,P4ssw0rd\r\n";
        let entries = parse_chromium_csv(csv);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].password, "P4ssw0rd");
    }

    #[test]
    fn rows_without_password_are_reported_not_dropped() {
        let csv = "name,url,username,password
                   Site,https://site.example,user,
                   Other,https://other.example,user2,Pass2
";
        let entries = parse_chromium_csv(csv);
        assert_eq!(entries.len(), 2, "строка без пароля не исчезает молча");
        assert_eq!(entry_to_input(&entries[0]).unwrap_err(), "пустой пароль");
        assert!(entry_to_input(&entries[1]).is_ok());
    }

    #[test]
    fn csv_without_password_column_imports_nothing() {
        let csv = "name,url,username
Site,https://site.example,user
";
        assert!(parse_chromium_csv(csv).is_empty());
        assert!(parse_chromium_csv("").is_empty());
    }

    #[test]
    fn alternative_header_names_are_recognised() {
        let csv = "title,url,login,pass,notes
Site,https://site.example,u,P4ssw0rd,n
";
        let entries = parse_chromium_csv(csv);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].username, "u");
        assert_eq!(entries[0].password, "P4ssw0rd");
        assert_eq!(entries[0].note, "n");
    }

    #[test]
    fn url_without_scheme_gets_https() {
        let csv = "name,url,username,password
Site,site.example/login,u,P4ssw0rd
";
        let entries = parse_chromium_csv(csv);
        assert_eq!(entries[0].url, "https://site.example/login");
    }

    /// `bbc.co.uk` раньше сокращался до бесполезного «co.uk».
    #[test]
    fn multi_level_public_suffixes_keep_the_site_name() {
        assert_eq!(
            extract_clean_domain("", "https://www.bbc.co.uk/news"),
            "bbc.co.uk"
        );
        assert_eq!(
            extract_clean_domain("", "https://shop.mycompany.com.au"),
            "mycompany.com.au"
        );
        assert_eq!(
            extract_clean_domain("", "https://auth.openai.com"),
            "openai.com"
        );
        assert_eq!(extract_clean_domain("", "https://google.com"), "google.com");
        assert_eq!(
            extract_clean_domain("", "https://localhost:3000"),
            "localhost"
        );
        assert_eq!(extract_clean_domain("Моя запись", ""), "моя запись");
        assert_eq!(extract_clean_domain("", ""), "Импортированный сайт");
    }

    /// Удаление исходного CSV принимает только расписку сервера и
    /// отказывается работать, если файл изменился после импорта.
    #[test]
    fn secure_delete_requires_an_unchanged_file() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passwords.csv");
        let content = b"name,url,username,password
Site,https://s.example,u,P4ssw0rd
";
        std::fs::write(&path, content).unwrap();

        let digest: [u8; 32] = Sha256::digest(content).into();
        let receipt = crate::state::PendingImportDeletion {
            canonical_path: std::fs::canonicalize(&path).unwrap(),
            sha256: digest,
            length: content.len() as u64,
        };

        // Подмена содержимого после импорта останавливает удаление.
        std::fs::write(&path, b"something completely different content!!").unwrap();
        assert!(secure_delete_authorized_file(receipt.clone()).is_err());
        assert!(path.exists(), "изменённый файл не должен удаляться");

        // Исходный файл удаляется и перезаписывается.
        std::fs::write(&path, content).unwrap();
        secure_delete_authorized_file(receipt).unwrap();
        assert!(!path.exists(), "исходный CSV должен быть удалён");
    }

    #[test]
    fn secure_delete_rejects_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let receipt = crate::state::PendingImportDeletion {
            canonical_path: dir.path().join("gone.csv"),
            sha256: [0u8; 32],
            length: 10,
        };
        assert!(secure_delete_authorized_file(receipt).is_err());
    }
}
