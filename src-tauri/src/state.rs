// Глобальное состояние приложения.
//
// Хранит:
//  - подключение к зашифрованной БД (после разблокировки);
//  - master-key in-memory с Zeroize при сбросе;
//  - метку времени последнего использования (для autolock);
//  - конфиг (autolock_seconds, clipboard_clear_seconds).
//
// Никогда не сериализуется на диск целиком.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tauri::AppHandle;
use zeroize::Zeroizing;

use crate::error::Result;
use crate::storage::meta_db::MetaDb;
use crate::storage::records_db::RecordsDb;

/// Размер мастер-ключа AES-256.
pub const MASTER_KEY_LEN: usize = 32;

/// Тип мастер-ключа: 32 байта, зашифрованные в RAM во время простоя.
pub type MasterKey = crate::crypto::master::MasterKey;

/// Состояние сессии: либо разблокирована (содержит ключ и подключение к
/// зашифрованной records-БД), либо заблокирована.
///
/// `records_db` — это уже открытая SQLCipher-БД с правильным ключом.
/// Закрывается при transition в Locked (Drop chain → Connection close).
pub enum SessionState {
    Locked,
    Unlocked {
        master_key: MasterKey,
        /// Ключ HMAC для защиты целостности vault_meta.
        integrity_key: Zeroizing<[u8; 32]>,
        records_db: RecordsDb,
        web_db: RecordsDb,
        unlocked_at: Instant,
        last_activity: Instant,
        /// N-03 (вариант B): время последнего успешного Windows Hello для гейта
        /// «копирование/просмотр» (require_auth_for_copy). Живёт внутри Unlocked,
        /// поэтому автоматически сбрасывается при ЛЮБОЙ блокировке сессии.
        auth_verified_at: Option<Instant>,
    },
}

impl SessionState {
    pub fn is_unlocked(&self) -> bool {
        matches!(self, SessionState::Unlocked { .. })
    }
}

/// Дефолтные настройки. Применяются при первом запуске.
#[derive(Clone, Debug)]
pub struct VaultSettings {
    /// Секунды до автоблокировки (0 = выключено).
    pub autolock_seconds: u32,
    /// Секунды до автоматической очистки буфера обмена (0 = выключено).
    pub clipboard_clear_seconds: u32,
    /// Требовать аутентификацию для копирования секрета.
    pub require_auth_for_copy: bool,
    /// Использовать Windows Hello при разблокировке.
    pub use_windows_hello: bool,
    /// Максимальное число неудачных попыток PIN до блокировки до рестарта.
    pub max_pin_attempts: u32,
}

impl Default for VaultSettings {
    fn default() -> Self {
        Self {
            // 5 минут — баланс между security и UX. 60 секунд было
            // слишком агрессивно: пользователь не успевал заполнить
            // запись с несколькими полями без срабатывания autolock.
            autolock_seconds: 300,
            clipboard_clear_seconds: 10,
            require_auth_for_copy: false,
            use_windows_hello: false,
            max_pin_attempts: 10,
        }
    }
}

/// Главное состояние приложения, передаётся в Tauri-команды
/// через State<AppState>.
#[derive(Clone)]
pub struct AppState {
    /// Корневой каталог для БД и метаданных хранилища.
    /// True-portable: ./vault/ рядом с .exe.
    pub data_dir: std::path::PathBuf,

    /// Состояние сессии (records_db живёт здесь когда unlocked).
    pub session: Arc<Mutex<SessionState>>,

    /// Настройки.
    pub settings: Arc<Mutex<VaultSettings>>,

    /// Системный tauri::AppHandle для эмиттинга глобальных событий.
    pub app_handle: tauri::AppHandle,
}

impl AppState {
    /// Инициализация при старте приложения.
    /// Создаёт data_dir, если его нет.
    pub fn initialize(app: &AppHandle) -> Result<Self> {
        let data_dir = resolve_data_dir(app)?;
        std::fs::create_dir_all(&data_dir)?;

        Ok(Self {
            data_dir,
            session: Arc::new(Mutex::new(SessionState::Locked)),
            settings: Arc::new(Mutex::new(VaultSettings::default())),
            app_handle: app.clone(),
        })
    }

    /// Путь к открытой meta-БД.
    pub fn meta_path(&self) -> std::path::PathBuf {
        self.data_dir.join("vault.meta.db")
    }

    /// Путь к зашифрованной records-БД.
    pub fn records_path(&self) -> std::path::PathBuf {
        self.data_dir.join("vault.records.db")
    }

    /// Путь к зашифрованной web-БД.
    pub fn web_path(&self) -> std::path::PathBuf {
        self.data_dir.join("vault.web.db")
    }

    /// Открыть meta-БД (открытая SQLite). Каждый вызов — fresh connection.
    /// MetaDb сама применяет миграции при open.
    pub fn open_meta(&self) -> Result<MetaDb> {
        MetaDb::open(&self.meta_path())
    }

    /// Полный сброс сессии — ключ зачищается из памяти (Zeroize),
    /// БД-handle закрывается, состояние переводится в Locked.
    pub fn lock(&self) {
        let mut s = self.session.lock();
        *s = SessionState::Locked;
    }

    /// Колбэк на window event (focus lost / close request) — мягкая блокировка.
    pub fn notify_window_event_lock(&self) {
        // Минимизация и закрытие окна → блокировка.
        // Это безопасный дефолт; конкретное поведение можно конфигурировать
        // через VaultSettings (TODO в settings).
        self.lock();
    }

    /// Обновить отметку активности (вызывается из любой команды,
    /// которая считается user-action).
    pub fn touch(&self) {
        let mut s = self.session.lock();
        if let SessionState::Unlocked { last_activity, .. } = &mut *s {
            *last_activity = Instant::now();
        }
    }

    /// Проверить, не пора ли сделать autolock на основании настроек.
    /// Возвращает true, если был выполнен lock.
    pub fn check_autolock(&self) -> bool {
        let timeout = {
            let s = self.settings.lock();
            s.autolock_seconds
        };
        if timeout == 0 {
            return false;
        }
        let mut s = self.session.lock();
        if let SessionState::Unlocked { last_activity, .. } = &*s {
            let elapsed = last_activity.elapsed().as_secs();
            if elapsed >= timeout as u64 {
                log::warn!(
                    "check_autolock: idle {}s >= timeout {}s, locking session",
                    elapsed,
                    timeout
                );
                *s = SessionState::Locked;
                return true;
            }
        }
        false
    }
}

/// True-portable: data_dir = ./vault/ рядом с .exe.
/// AppHandle намеренно игнорируется (используем executable path).
fn resolve_data_dir(_app: &AppHandle) -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe()
        .map_err(|e| crate::error::VaultError::System(format!("current_exe: {e}")))?;
    let parent = exe
        .parent()
        .ok_or_else(|| crate::error::VaultError::System("exe has no parent".into()))?;
    Ok(parent.join("vault"))
}
