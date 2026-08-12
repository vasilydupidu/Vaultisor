// Vaultisor library entrypoint.
//
// Здесь собираются все модули и регистрируются Tauri-команды.
// Принцип: backend полностью контролирует криптографию и ключи.
// Frontend не имеет прямого доступа к мастер-ключу — только к расшифрованным
// значениям полей по запросу авторизованной сессии.

pub mod auth;
pub mod commands;
pub mod crypto;
pub mod error;
pub mod recovery;
pub mod state;
pub mod storage;

#[cfg(windows)]
pub mod windows_api;

use tauri::Manager;

use crate::state::AppState;

/// Запуск приложения.
/// Вызывается из main() и из integration-тестов.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[allow(unused_mut)]
    let mut builder = tauri::Builder::default();

    // Single-instance ДОЛЖЕН быть зарегистрирован первым (требование плагина).
    // Повторный запуск .exe не поднимает второй процесс, а разворачивает и
    // фокусирует уже открытое окно первого экземпляра.
    #[cfg(desktop)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.unminimize();
                let _ = window.set_focus();
                let _ = window.set_always_on_top(true);
                let _ = window.set_always_on_top(false);
            }
        }));
    }

    builder
        // Логирование — только в файл рядом с %APPDATA%\Vaultisor\logs.
        // НИКАКИХ удалённых endpoint'ов.
        .plugin({
            // DEBUG: логи в файл ./vault/logs/Vaultisor.log рядом с .exe + stdout.
            // РЕЛИЗ: логирование ПОЛНОСТЬЮ отключено — ни папки logs, ни файла
            // не создаётся (приватность portable-приложения, без диагностики).
            #[cfg(debug_assertions)]
            let builder = {
                let log_dir = std::env::current_exe()
                    .ok()
                    .and_then(|p| p.parent().map(|d| d.join("vault").join("logs")))
                    .unwrap_or_else(|| std::path::PathBuf::from("logs"));
                let _ = std::fs::create_dir_all(&log_dir);
                tauri_plugin_log::Builder::new()
                    .targets([
                        tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Folder {
                            path: log_dir,
                            file_name: Some("Vaultisor".into()),
                        }),
                        tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::Stdout),
                    ])
                    .max_file_size(2_000_000)
                    .level(log::LevelFilter::Info)
            };
            // Релиз: единственный таргет — Stdout (в оконном приложении уходит в
            // никуда), уровень Off. Никаких файловых таргетов и создания папки.
            #[cfg(not(debug_assertions))]
            let builder = tauri_plugin_log::Builder::new()
                .targets([tauri_plugin_log::Target::new(
                    tauri_plugin_log::TargetKind::Stdout,
                )])
                .level(log::LevelFilter::Off);

            builder.build()
        })
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_os::init())
        .setup(|app| {
            // Инициализация общего состояния приложения.
            // AppState хранит handle к разблокированной сессии (если она есть)
            // и подключение к SQLite. Мастер-ключ держим в памяти,
            // защищённой Zeroize при сбросе.
            let app_state = AppState::initialize(app.handle())?;

            // Браузерное расширение и сетевая синхронизация отключены в релизе
            // (решение по продукту: убираем сетевую поверхность атаки и трение
            // с фаерволом/mDNS). Перенос на телефон — только air-gapped QR.
            // WS-сервер расширения больше не поднимаем — localhost-порт не открыт.

            app.manage(app_state);

            // Показываем главное окно после initial setup.
            // (visible: false в tauri.conf.json → исключаем "белый flash").
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Системные проверки
            commands::system::system_check,
            commands::system::vault_exists,
            // Создание / разблокировка
            commands::vault::vault_create,
            commands::vault::vault_unlock,
            commands::vault::vault_unlock_with_hello,
            commands::vault::vault_unlock_with_fido2,
            commands::vault::vault_lock,
            commands::vault::vault_lock_info,
            commands::vault::vault_change_pin,
            commands::vault::vault_export,
            commands::vault::vault_import,
            commands::vault::vault_restore,
            // Записи
            commands::records::record_list,
            commands::records::record_get,
            commands::records::record_create,
            commands::records::record_update,
            commands::records::record_delete,
            commands::records::records_batch_delete,
            commands::records::record_reveal_field,
            commands::records::record_reorder,
            commands::records::record_get_password_history,
            commands::records::record_clear_password_history,
            // Буфер обмена
            commands::clipboard::clipboard_copy_secret,
            commands::clipboard::clipboard_copy_text,
            commands::clipboard::clipboard_clear,
            // Recovery
            commands::recovery::recovery_save_to_usb,
            commands::recovery::recovery_load_from_usb,
            commands::recovery::recovery_restore,
            commands::recovery::recovery_status,
            commands::recovery::recovery_regenerate,
            commands::recovery::recovery_disable,
            // Настройки
            commands::settings::settings_get,
            commands::settings::settings_update,
            commands::settings::get_ui_language,
            commands::settings::set_ui_language,
            commands::settings::get_enable_health_check,
            commands::settings::set_enable_health_check,
            commands::settings::get_enable_password_history,
            commands::settings::set_enable_password_history,
            commands::settings::get_fido2_status,
            commands::settings::register_fido2_key,
            commands::settings::unbind_fido2_key,
            // Idle / autolock
            commands::system::idle_seconds,
            commands::system::session_heartbeat,
            // Резервные копии и импорт
            commands::backup::backup_get_config,
            commands::backup::backup_set_config,
            commands::backup::backup_now,
            commands::import::import_chromium_csv,
            commands::import::secure_delete_file,
        ])
        .on_window_event(|window, event| {
            // Авто-блокировка только на закрытие окна.
            // НЕ блокируем по потере фокуса: file-dialog'и (Save/Open),
            // alt-tab и системные popup'ы тоже снимают фокус — иначе
            // любое взаимодействие с системой выкидывает в lock-screen.
            // Idle-блокировка работает отдельно через VaultSettings.autolock_seconds.
            use tauri::WindowEvent;
            if matches!(event, WindowEvent::CloseRequested { .. }) {
                if let Some(state) = window.try_state::<AppState>() {
                    state.notify_window_event_lock();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("Vaultisor: фатальная ошибка инициализации Tauri");
}
