//! Окружение сценарных тестов: каталог хранилища, тестовая ОС и «перезапуск».

use std::cell::Cell;
use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use crate::auth::backoff::BackoffState;
use crate::commands::security::SecurityAction;
use crate::commands::vault::{VaultCreateInput, VaultCreateOutput, VaultUnlockInput};
use crate::error::Result;
use crate::failpoint::{self, Mode};
use crate::platform::fake::FakePlatform;
use crate::platform::Os;
use crate::state::{AppState, SessionState};
use crate::storage::records::{FieldInput, FieldType, RecordInput};

pub const PIN: &str = "19472856302";
pub const NEW_PIN: &str = "58392071465";
pub const WRONG_PIN: &str = "70000000013";
/// Значение-канарейка: если после сбоя оно читается, данные целы.
pub const CANARY: &str = "sk-live-canary-7f3a";
const CANARY_RECORD: &str = "canary";

pub struct Env {
    _dir: tempfile::TempDir,
    pub root: PathBuf,
    pub fake: Arc<FakePlatform>,
    pub state: AppState,
    /// Внешние ресурсы, которые законно переживают отсутствие хранилища:
    /// TPM-ключ и checkpoint потерянного хранилища, из копии которого будет
    /// импорт на том же устройстве.
    pub foreign_tpm: BTreeSet<String>,
    pub foreign_checkpoints: BTreeSet<String>,
}

impl Env {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("vault");
        let fake = Arc::new(FakePlatform::default());
        let state = AppState::new(root.clone(), Os::new(fake.clone())).expect("startup");
        Self {
            _dir: dir,
            root,
            fake,
            state,
            foreign_tpm: BTreeSet::new(),
            foreign_checkpoints: BTreeSet::new(),
        }
    }

    /// Смерть процесса и новый запуск: память теряется, ОС (TPM, ключи Hello,
    /// токены) и диск остаются. Старт выполняет штатное восстановление.
    pub fn restart(&mut self) {
        failpoint::disarm();
        self.state.lock();
        self.state = AppState::new(self.root.clone(), Os::new(self.fake.clone()))
            .expect("startup recovery must succeed after any interruption");
    }

    pub async fn create(&self) -> VaultCreateOutput {
        crate::commands::vault::create_vault(
            &self.state,
            VaultCreateInput {
                pin: PIN.into(),
                use_windows_hello: false,
                autolock_seconds: None,
                clipboard_clear_seconds: None,
            },
        )
        .await
        .expect("vault creation")
    }

    pub async fn unlock(&self, pin: &str) -> Result<()> {
        crate::commands::vault::unlock_with_pin(&self.state, VaultUnlockInput { pin: pin.into() })
            .await
    }

    /// Свежее подтверждение действия верным PIN.
    pub async fn authorize(&self, action: SecurityAction) {
        crate::commands::security::authorize(&self.state, action, PIN)
            .await
            .expect("authorization with the correct PIN");
    }

    /// Включить Hello штатным путём: подтверждение, затем операция.
    pub async fn enable_hello(&self) {
        self.authorize(SecurityAction::EnableHello).await;
        crate::commands::settings::set_hello(&self.state, true)
            .await
            .expect("enable Hello");
    }

    /// Привязать FIDO2-ключ штатным путём; возвращает его credential id.
    pub async fn bind_fido(&self) -> Vec<u8> {
        let before = self.fake.fido_credentials();
        self.authorize(SecurityAction::BindFido).await;
        crate::commands::settings::bind_fido2_key(
            &self.state,
            None,
            Some(false),
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .expect("bind FIDO2");
        self.fake
            .fido_credentials()
            .difference(&before)
            .next()
            .cloned()
            .expect("new credential on the token")
    }

    /// Действующее состояние задержек PIN: строжайшее из метаданных и
    /// внешнего checkpoint — именно его применяет проверка PIN.
    pub fn backoff(&self) -> BackoffState {
        let db = self.state.open_meta().expect("meta");
        let meta = db.vault_load().expect("load").expect("vault");
        let blob = db
            .get_integrity_key_dpapi()
            .expect("integrity key")
            .expect("integrity key");
        let key = crate::commands::vault::unwrap_integrity_key(&blob, &meta.dpapi_entropy)
            .expect("integrity key unwraps");
        match db.checkpoint_backoff(&key).expect("checkpoint") {
            Some(anchored) => meta.backoff.strictest(anchored),
            None => meta.backoff,
        }
    }

    /// Файлы хранилища, скопированные на другой компьютер, к которому
    /// поднесли те же FIDO2-токены. TPM и Hello там свои (пустые).
    pub fn copy_to_other_device(&self) -> Env {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().join("vault");
        std::fs::create_dir_all(&root).expect("vault dir");
        for name in ["vault.meta.db", "vault.records.db", "vault.web.db"] {
            let source = self.root.join(name);
            if source.exists() {
                std::fs::copy(&source, root.join(name)).expect("copy vault file");
            }
        }
        let fake = Arc::new(FakePlatform::default());
        fake.share_tokens_with(&self.fake);
        let state = AppState::new(root.clone(), Os::new(fake.clone())).expect("startup");
        Env {
            _dir: dir,
            root,
            fake,
            state,
            foreign_tpm: BTreeSet::new(),
            foreign_checkpoints: BTreeSet::new(),
        }
    }

    /// Другой компьютер: пустой, с теми же FIDO2-токенами.
    pub fn other_device(&self) -> Env {
        let env = Env::new();
        env.fake.share_tokens_with(&self.fake);
        env
    }

    /// Бандл резервной копии текущего хранилища (оно должно быть открыто).
    pub fn bundle(&self) -> Vec<u8> {
        crate::commands::backup::build_bundle(&self.state).expect("backup bundle")
    }

    /// Положить файл рядом с хранилищем (вне его каталога).
    pub fn put_file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self._dir.path().join(name);
        std::fs::write(&path, bytes).expect("write file");
        path
    }

    /// Полномочие на файл для операции, как после системного диалога.
    pub fn grant(
        &self,
        path: &Path,
        operation: crate::commands::file_grants::FileOperation,
    ) -> String {
        let stamp = crate::commands::file_grants::session_stamp(&self.state.session.lock());
        self.state
            .file_grants
            .lock()
            .issue_for_test(path.to_path_buf(), operation, stamp)
    }

    /// Живое хранилище потеряно (удалено вместе с каталогом), а внешние
    /// ресурсы устройства — TPM-ключ и checkpoint — остались.
    pub fn lose_live_vault(&mut self) {
        self.state.lock();
        for path in [
            self.state.meta_path(),
            self.state.records_path(),
            self.state.web_path(),
        ] {
            std::fs::remove_file(path).expect("remove vault file");
        }
        self.foreign_tpm = self.fake.tpm_keys();
        self.foreign_checkpoints = self.checkpoints();
        self.restart();
    }

    /// Внешние checkpoint'ы этого «устройства».
    pub fn checkpoints(&self) -> BTreeSet<String> {
        std::fs::read_dir(self.root.join(".test-machine-checkpoints"))
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| name.ends_with(".checkpoint"))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Выполнить действие над открытой сессией.
    pub fn with_session<R>(
        &self,
        f: impl FnOnce(
            &crate::crypto::master::MasterKey,
            &crate::storage::records_db::RecordsDb,
            &crate::storage::records_db::RecordsDb,
        ) -> R,
    ) -> Option<R> {
        let session = self.state.session.lock();
        match &*session {
            SessionState::Unlocked {
                master_key,
                records_db,
                web_db,
                ..
            } => Some(f(master_key, records_db, web_db)),
            SessionState::Locked => None,
        }
    }

    /// Положить запись с канарейкой. Хранилище должно быть открыто.
    pub fn add_canary(&self) {
        self.with_session(|master, records, _| {
            crate::storage::records::create_record(
                records,
                master,
                &RecordInput {
                    name: CANARY_RECORD.into(),
                    project: None,
                    icon: None,
                    color: None,
                    category: Some("work".into()),
                    fields: vec![FieldInput {
                        id: None,
                        field_type: FieldType::Secret,
                        label: "token".into(),
                        is_secret: true,
                        sort_order: 0,
                        value: Some(CANARY.into()),
                    }],
                },
                None,
            )
            .expect("canary record")
        })
        .expect("vault must be unlocked to add the canary");
    }

    /// Запись-канарейка: (id записи, id поля, тип поля, значение), если
    /// хранилище открыто и запись читается.
    pub fn canary(&self) -> Option<(String, String, FieldType, Option<String>)> {
        self.with_session(|master, records, _| {
            let list = crate::storage::records::list_records(
                records,
                None,
                false,
                Some(CANARY_RECORD),
                None,
                10,
                0,
            )
            .ok()?;
            let record = list.first()?;
            let full = crate::storage::records::get_record(records, &record.id).ok()?;
            let field = full.fields.first()?;
            let value =
                crate::storage::records::reveal_field(records, master, &record.id, &field.id)
                    .ok()
                    .map(|value| value.to_string());
            Some((record.id.clone(), field.id.clone(), field.field_type, value))
        })
        .flatten()
    }

    pub fn read_canary(&self) -> Option<String> {
        self.canary().and_then(|(_, _, _, value)| value)
    }

    /// Открывается ли хранилище этим PIN с чистого запуска и с целыми данными.
    pub async fn opens_with_pin(&mut self, pin: &str) -> bool {
        self.restart();
        self.unlock(pin).await.is_ok() && self.read_canary().as_deref() == Some(CANARY)
    }
}

/// Итог прогона: хранилище в старом или новом валидном состоянии.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Old,
    New,
}

thread_local! {
    static OUTCOME: Cell<Option<Outcome>> = const { Cell::new(None) };
}

/// Сценарий сообщает, в каком состоянии оказалось хранилище.
pub fn record(outcome: Outcome) {
    OUTCOME.with(|cell| cell.set(Some(outcome)));
}

fn take_outcome() -> Option<Outcome> {
    OUTCOME.with(|cell| cell.take())
}

/// Результат одного прогона сценария.
pub struct Case {
    /// Сколько шагов персистентности прошло за операцию.
    pub steps: usize,
    pub trace: Vec<&'static str>,
    /// Нарушения общих инвариантов и постусловий операции.
    pub violations: Vec<String>,
}

pub type Scenario = fn(Option<(usize, Mode)>) -> Pin<Box<dyn Future<Output = Case>>>;

/// Взвести план для операции: `None` — только посчитать шаги.
pub fn arm(plan: Option<(usize, Mode)>) {
    match plan {
        Some((step, mode)) => failpoint::arm(step, mode),
        None => failpoint::disarm(),
    }
}

/// Снять показания после операции.
pub fn observed() -> (usize, Vec<&'static str>) {
    (failpoint::steps(), failpoint::trace())
}

/// Прогнать сценарий с отказом на каждом шаге в обоих режимах.
///
/// Возвращает нарушения с номером шага и его именем; пустой список означает,
/// что после любого сбоя хранилище в старом или новом валидном состоянии.
pub async fn sweep(name: &str, scenario: Scenario) -> Vec<String> {
    let baseline = scenario(None).await;
    if !baseline.violations.is_empty() {
        return baseline
            .violations
            .into_iter()
            .map(|v| format!("{name}: сценарий без сбоев нарушает инвариант: {v}"))
            .collect();
    }
    assert!(
        baseline.steps > 0,
        "{name}: операция не прошла ни одного шага персистентности"
    );

    let mut failures = Vec::new();
    for mode in [Mode::Crash, Mode::Error] {
        for step in 1..=baseline.steps {
            let case = scenario(Some((step, mode))).await;
            for violation in case.violations {
                failures.push(format!(
                    "{name}: {mode:?} на шаге {step}/{} ({}): {violation}",
                    baseline.steps,
                    baseline.trace[step - 1]
                ));
            }
        }
    }
    failures
}

/// Сводка свипа по режиму отказа.
#[derive(Debug, Default, Clone, Copy)]
pub struct ModeSummary {
    pub old: usize,
    pub new: usize,
    pub violations: usize,
}

/// Сводка свипа: шаги и итоги по режимам.
pub struct SweepReport {
    pub steps: usize,
    pub crash: ModeSummary,
    pub error: ModeSummary,
    pub failures: Vec<String>,
}

/// Свип с подсчётом итогов OLD/NEW по каждому режиму.
pub async fn sweep_report(name: &str, scenario: Scenario) -> SweepReport {
    take_outcome();
    let baseline = scenario(None).await;
    take_outcome();
    let mut report = SweepReport {
        steps: baseline.steps,
        crash: ModeSummary::default(),
        error: ModeSummary::default(),
        failures: baseline
            .violations
            .iter()
            .map(|v| format!("{name}: сценарий без сбоев нарушает инвариант: {v}"))
            .collect(),
    };
    if !report.failures.is_empty() {
        return report;
    }
    // Без шагов свип ничего не проверяет: изменение состояния прошло мимо
    // точек отказа.
    assert!(
        baseline.steps > 0,
        "{name}: операция не прошла ни одного шага персистентности"
    );
    for mode in [Mode::Crash, Mode::Error] {
        for step in 1..=baseline.steps {
            let case = scenario(Some((step, mode))).await;
            let summary = match mode {
                Mode::Crash => &mut report.crash,
                Mode::Error => &mut report.error,
            };
            match take_outcome() {
                Some(Outcome::Old) => summary.old += 1,
                Some(Outcome::New) => summary.new += 1,
                None => {}
            }
            summary.violations += case.violations.len();
            for violation in case.violations {
                report.failures.push(format!(
                    "{name}: {mode:?} на шаге {step}/{} ({}): {violation}",
                    baseline.steps,
                    baseline.trace[step - 1]
                ));
            }
        }
    }
    eprintln!(
        "| {name} | {} | Crash: OLD {} / NEW {} / нарушений {} | Error: OLD {} / NEW {} / нарушений {} |",
        report.steps,
        report.crash.old,
        report.crash.new,
        report.crash.violations,
        report.error.old,
        report.error.new,
        report.error.violations,
    );
    report
}

/// Свип с итогами OLD/NEW; нарушений быть не должно.
pub async fn assert_atomic_outcomes(name: &str, scenario: Scenario) {
    let report = sweep_report(name, scenario).await;
    assert!(
        report.failures.is_empty(),
        "{} нарушений атомарности:\n{}",
        report.failures.len(),
        report.failures.join("\n")
    );
}

/// Прогнать сценарий и потребовать отсутствия нарушений.
pub async fn assert_atomic(name: &str, scenario: Scenario) {
    let steps = scenario(None).await.steps;
    let failures = sweep(name, scenario).await;
    eprintln!(
        "{name}: {steps} шагов x 2 режима, нарушений: {}",
        failures.len()
    );
    assert!(
        failures.is_empty(),
        "{} нарушений атомарности:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
