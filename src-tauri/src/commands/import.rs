// Команда импорта паролей из Chromium-браузеров (Chrome, Opera, Yandex, Edge)
// и безопасного удаления сырого CSV-файла с диска.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use serde::Serialize;
use tauri::State;

use crate::error::{Result, VaultError};
use crate::state::{AppState, SessionState};
use crate::storage::records::{create_record, FieldInput, FieldType, RecordInput};

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub count: usize,
    pub imported_ids: Vec<String>,
}

#[derive(Debug, Default)]
struct ChromiumEntry {
    name: String,
    url: String,
    username: String,
    password: String,
    note: String,
}

/// Распарсить строку CSV от Chromium.
/// Формат Chromium CSV: header = name,url,username,password,note (или title,url,username,password).
fn parse_chromium_csv(content: &str) -> Vec<ChromiumEntry> {
    let mut entries = Vec::new();
    let mut lines = content.lines();

    let header = match lines.next() {
        Some(h) => h.to_lowercase(),
        None => return entries,
    };

    let headers: Vec<String> = parse_csv_line(&header);
    let name_idx = headers.iter().position(|h| h == "name" || h == "title");
    let url_idx = headers.iter().position(|h| h == "url");
    let user_idx = headers.iter().position(|h| h == "username" || h == "login" || h == "user");
    let pass_idx = headers.iter().position(|h| h == "password" || h == "pass");
    let note_idx = headers.iter().position(|h| h == "note" || h == "notes" || h == "comment");

    if pass_idx.is_none() {
        return entries;
    }

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cols = parse_csv_line(line);
        if cols.is_empty() {
            continue;
        }

        let get_col = |idx: Option<usize>| -> String {
            idx.and_then(|i| cols.get(i)).map(|s| s.trim().to_string()).unwrap_or_default()
        };

        let password = get_col(pass_idx);
        if password.is_empty() {
            continue;
        }

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
            name,
            url,
            username,
            password,
            note,
        });
    }

    entries
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current = String::new();
            }
            _ => {
                current.push(c);
            }
        }
    }
    fields.push(current.trim().to_string());
    fields
}

/// Извлечь чистое корневое доменное имя сайта (например, openai.com вместо auth.openai.com) или название.
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

    let host = clean.split(&['/', ':', '?'][..]).next().unwrap_or(clean).trim();
    if host.is_empty() {
        return "Импортированный сайт".to_string();
    }

    // Если кандидат — URL или доменная строка, извлекаем корневой домен (2 последних компонента)
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 3 {
        // auth.openai.com -> openai.com
        // accounts.google.com -> google.com
        // account.apple.com -> apple.com
        // auth.meta.com -> meta.com
        let len = parts.len();
        format!("{}.{}", parts[len - 2], parts[len - 1]).to_lowercase()
    } else if parts.len() == 2 {
        host.to_lowercase()
    } else {
        host.to_string()
    }
}

/// Импорт паролей из Chromium CSV в веб-базу (vault.web.db).
#[tauri::command]
pub async fn import_chromium_csv(
    file_path: String,
    state: State<'_, AppState>,
) -> Result<ImportResult> {
    let path = Path::new(&file_path);
    if !path.exists() {
        return Err(VaultError::BadInput("Файл не найден".into()));
    }

    let mut file = File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let entries = parse_chromium_csv(&content);
    if entries.is_empty() {
        return Err(VaultError::BadInput(
            "Не найдено паролей для импорта или некорректный формат CSV".into(),
        ));
    }

    let mut imported_ids = Vec::new();

    let session = state.session.lock();
    match &*session {
        SessionState::Unlocked { master_key, web_db, .. } => {
            crate::storage::records::ensure_field_crypto_ready(web_db)?;

            for (_idx, entry) in entries.into_iter().enumerate() {
                let mut fields = Vec::new();
                let mut f_idx = 0i64;

                if !entry.username.is_empty() {
                    fields.push(FieldInput {
                        id: None,
                        label: "Логин".into(),
                        field_type: FieldType::Custom,
                        value: Some(entry.username),
                        is_secret: false,
                        sort_order: f_idx,
                    });
                    f_idx += 1;
                }

                fields.push(FieldInput {
                    id: None,
                    label: "Пароль".into(),
                    field_type: FieldType::Secret,
                    value: Some(entry.password),
                    is_secret: true,
                    sort_order: f_idx,
                });
                f_idx += 1;

                if !entry.url.is_empty() {
                    fields.push(FieldInput {
                        id: None,
                        label: "URL сайта".into(),
                        field_type: FieldType::Custom,
                        value: Some(entry.url.clone()),
                        is_secret: false,
                        sort_order: f_idx,
                    });
                    f_idx += 1;
                }

                if !entry.note.is_empty() {
                    fields.push(FieldInput {
                        id: None,
                        label: "Заметка".into(),
                        field_type: FieldType::Comment,
                        value: Some(entry.note),
                        is_secret: false,
                        sort_order: f_idx,
                    });
                }

                let input = RecordInput {
                    name: entry.name,
                    project: if entry.url.is_empty() { None } else { Some(entry.url) },
                    icon: None,
                    color: None,
                    category: Some("personal".into()),
                    fields,
                };

                if let Ok(rec_id) = create_record(web_db, master_key, &input) {
                    imported_ids.push(rec_id);
                }
            }
        }
        _ => return Err(VaultError::Locked),
    }

    let count = imported_ids.len();
    Ok(ImportResult { count, imported_ids })
}

/// Безопасное шредирование (затирание и удаление) файла с диска.
#[tauri::command]
pub async fn secure_delete_file(file_path: String) -> Result<()> {
    let path = Path::new(&file_path);
    if !path.exists() {
        return Ok(());
    }

    let metadata = std::fs::metadata(path)?;
    let len = metadata.len();

    if len > 0 {
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            let zeros = core_shared::rng::random_vec(len.min(1024 * 1024) as usize);
            let mut written = 0;
            while written < len {
                let to_write = (len - written).min(zeros.len() as u64) as usize;
                if file.write_all(&zeros[..to_write]).is_err() {
                    break;
                }
                written += to_write as u64;
            }
            let _ = file.flush();
        }
    }

    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_chromium_csv() {
        let csv = "name,url,username,password,note\n\
                   https://www.google.com/auth,https://google.com,testuser,Secret123,my note\n\
                   GitHub,https://github.com/login,gituser,Pass456,\n";
        let entries = parse_chromium_csv(csv);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "google.com");
        assert_eq!(entries[0].username, "testuser");
        assert_eq!(entries[0].password, "Secret123");
        assert_eq!(entries[0].note, "my note");
        assert_eq!(entries[1].name, "github.com");
    }
}
