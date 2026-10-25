//! Свипы отказов для остальных команд, меняющих состояние: генератор,
//! настройки, успешные входы, подтверждение долей, конфиг резервных копий,
//! импорт CSV и удаление исходного файла, операции с записями.
//!
//! Схема та же, что в соседних модулях: подготовка → команда с отказом на
//! шаге N (Crash и Error) → перезапуск → общие инварианты → вход PIN →
//! наблюдаемое состояние целиком старое (OLD) или целиком новое (NEW).

use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

use super::data_flow::{add, count, unlocked, CHANGED};
use super::harness::{
    arm, assert_atomic_outcomes, observed, record, Case, Env, Outcome, CANARY, PIN, WRONG_PIN,
};
use super::recovery_flow::{created, meta, restart_and_inspect, shares_open, Shares};
use crate::commands::file_grants::FileOperation;
use crate::commands::security::SecurityAction;
use crate::error::VaultError;
use crate::failpoint::Mode;
use crate::storage::meta_db::{RecoveryState, VaultMetaRow};
use crate::storage::records::generated::GeneratedKind;
use crate::storage::records::{FieldInput, RecordInput};

type CaseFuture = Pin<Box<dyn Future<Output = Case>>>;

/// Перезапуск, общие инварианты и вход PIN. Метаданные — только если вход
/// прошёл: наблюдаемое состояние читается в открытой сессии.
async fn reopen(env: &mut Env) -> (Option<VaultMetaRow>, Vec<String>) {
    let (meta, mut violations) = restart_and_inspect(env).await;
    if let Err(error) = env.unlock(PIN).await {
        violations.push(format!("PIN не открывает хранилище: {error}"));
        return (None, violations);
    }
    (meta, violations)
}

/// Отнести наблюдаемое состояние к старому или новому.
fn classify<T: PartialEq + Debug>(now: T, old: T, new: T, violations: &mut Vec<String>) {
    if now == old {
        record(Outcome::Old);
    } else if now == new {
        record(Outcome::New);
    } else {
        violations.push(format!(
            "ни старое, ни новое состояние: {now:?} (старое {old:?}, новое {new:?})"
        ));
    }
}

fn db_type(web: bool) -> String {
    if web { "web" } else { "records" }.into()
}

/// Та же запись с новым значением первого поля.
fn with_value(record: &crate::storage::records::Record, value: &str) -> RecordInput {
    let field = &record.fields[0];
    RecordInput {
        name: record.name.clone(),
        project: record.project.clone(),
        icon: record.icon.clone(),
        color: record.color.clone(),
        category: Some(record.category.clone()),
        fields: vec![FieldInput {
            id: Some(field.id.clone()),
            field_type: field.field_type,
            label: field.label.clone(),
            is_secret: field.is_secret,
            sort_order: field.sort_order,
            value: Some(value.into()),
        }],
    }
}

fn get(env: &Env, web: bool, id: &str) -> crate::storage::records::Record {
    env.with_session(|_, records, web_db| {
        crate::storage::records::get_record(if web { web_db } else { records }, id)
    })
    .expect("unlocked")
    .expect("record")
}

/// Сменить значение записи; прежнее уходит в историю.
fn change_value(env: &Env, web: bool, id: &str, value: &str) {
    let input = with_value(&get(env, web, id), value);
    env.with_session(|master, records, web_db| {
        let db = if web { web_db } else { records };
        crate::storage::records::update_record(db, master, id, &input, true)
    })
    .expect("unlocked")
    .expect("update");
}

fn history_len(env: &Env, web: bool, id: &str) -> Option<usize> {
    env.with_session(|_, records, web_db| {
        let db = if web { web_db } else { records };
        crate::storage::records::get_password_history(db, id)
            .map(|history| history.len())
            .ok()
    })
    .flatten()
}

/// Id записей в пользовательском порядке.
fn order(env: &Env) -> Option<Vec<String>> {
    env.with_session(|_, records, _| {
        crate::storage::records::list_records(records, None, false, None, None, 100, 0)
            .map(|list| list.into_iter().map(|record| record.id).collect())
            .ok()
    })
    .flatten()
}

fn canary_id(env: &Env) -> String {
    env.canary().expect("canary").0
}

fn web_id(env: &Env) -> String {
    env.with_session(|_, _, web| {
        crate::storage::records::list_records(web, None, false, None, None, 10, 0)
            .expect("web list")
            .remove(0)
            .id
    })
    .expect("unlocked")
}

// ------------------------------------------------------------ генератор

const GENERATED: [&str; 2] = [
    "0123456789abcdef0123456789abcdef",
    "fedcba9876543210fedcba9876543210",
];

/// Открытое хранилище с включённым генератором.
async fn with_generator() -> Env {
    let (env, _) = unlocked().await;
    crate::commands::settings::update_generator(&env.state, true).expect("enable generator");
    env
}

fn generate(env: &Env, value: &str) -> crate::error::Result<String> {
    crate::commands::generator::create_generated(
        &env.state,
        crate::commands::generator::GeneratorCreateInput {
            kind: GeneratedKind::Hex,
            value: value.into(),
        },
    )
    .map(|meta| meta.id)
}

/// Значения всех выдач генератора, по возрастанию.
fn generated(env: &Env) -> Option<Vec<String>> {
    env.with_session(|master, records, _| {
        let mut values = Vec::new();
        for item in crate::storage::records::generated::list(records).ok()? {
            let value = crate::storage::records::generated::reveal(records, master, &item.id);
            values.push(value.ok()?.to_string());
        }
        values.sort();
        Some(values)
    })
    .flatten()
}

/// OLD: выдач нет. NEW: одна выдача, и она расшифровывается в своё значение.
fn generator_create_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = with_generator().await;
        arm(plan);
        let _ = generate(&env, GENERATED[0]);
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(
                generated(&env),
                Some(vec![]),
                Some(vec![GENERATED[0].to_string()]),
                &mut violations,
            );
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn generator_create_is_atomic() {
    assert_atomic_outcomes("generator_create", generator_create_case).await;
}

/// OLD: обе выдачи на месте. NEW: обеих нет. Одной из двух — не бывает.
fn generator_delete_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = with_generator().await;
        let ids = GENERATED
            .iter()
            .map(|value| generate(&env, value).expect("generated"))
            .collect();
        arm(plan);
        let _ = crate::commands::generator::delete_generated(
            &env.state,
            crate::commands::generator::GeneratorDeleteInput { ids },
        );
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(
                generated(&env),
                Some(GENERATED.iter().map(|value| value.to_string()).collect()),
                Some(vec![]),
                &mut violations,
            );
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn generator_delete_is_atomic() {
    assert_atomic_outcomes("generator_delete", generator_delete_case).await;
}

// ------------------------------------------------------------ настройки

/// Настройка, которую меняет одна команда, и её значение после команды.
#[derive(Clone, Copy)]
enum Setting {
    /// `settings_update`: автоблокировка и очистка буфера.
    Convenience,
    /// `set_ui_language`.
    Language,
    /// `set_enable_health_check`.
    HealthCheck,
    /// `set_enable_generator`.
    Generator,
    /// `set_enable_password_history(true)` после выключения.
    PasswordHistoryOn,
}

impl Setting {
    fn value(self, meta: &VaultMetaRow) -> String {
        match self {
            Setting::Convenience => {
                format!("{}/{}", meta.autolock_seconds, meta.clipboard_clear_seconds)
            }
            Setting::Language => meta.ui_language.clone(),
            Setting::HealthCheck => meta.enable_health_check.to_string(),
            Setting::Generator => meta.enable_generator.to_string(),
            Setting::PasswordHistoryOn => meta.enable_password_history.to_string(),
        }
    }

    fn target(self) -> String {
        match self {
            Setting::Convenience => "900/45".into(),
            Setting::Language => "en".into(),
            Setting::HealthCheck => "false".into(),
            Setting::Generator => "true".into(),
            Setting::PasswordHistoryOn => "true".into(),
        }
    }

    async fn apply(self, env: &Env) -> crate::error::Result<()> {
        let state = &env.state;
        match self {
            Setting::Convenience => {
                crate::commands::settings::update_settings(
                    state,
                    crate::commands::settings::ConvenienceSettings {
                        autolock_seconds: 900,
                        clipboard_clear_seconds: 45,
                    },
                )
                .await
            }
            Setting::Language => crate::commands::settings::update_ui_language(state, "en"),
            Setting::HealthCheck => crate::commands::settings::update_health_check(state, false),
            Setting::Generator => crate::commands::settings::update_generator(state, true),
            Setting::PasswordHistoryOn => {
                crate::commands::settings::update_password_history(state, true)
            }
        }
    }
}

/// OLD: значение до команды. NEW: заданное командой.
fn setting_case(setting: Setting, plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        if let Setting::PasswordHistoryOn = setting {
            crate::commands::settings::update_password_history(&env.state, false)
                .expect("disable password history");
        }
        let old = setting.value(&meta(&env));
        assert_ne!(old, setting.target(), "команда обязана что-то менять");
        arm(plan);
        let _ = setting.apply(&env).await;
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if let Some(meta) = opened {
            classify(setting.value(&meta), old, setting.target(), &mut violations);
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

fn convenience_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    setting_case(Setting::Convenience, plan)
}

fn language_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    setting_case(Setting::Language, plan)
}

fn health_check_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    setting_case(Setting::HealthCheck, plan)
}

fn generator_toggle_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    setting_case(Setting::Generator, plan)
}

fn password_history_on_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    setting_case(Setting::PasswordHistoryOn, plan)
}

#[tokio::test]
async fn settings_update_is_atomic() {
    assert_atomic_outcomes("settings_update", convenience_case).await;
}

#[tokio::test]
async fn ui_language_change_is_atomic() {
    assert_atomic_outcomes("set_ui_language", language_case).await;
}

#[tokio::test]
async fn health_check_toggle_is_atomic() {
    assert_atomic_outcomes("set_enable_health_check", health_check_case).await;
}

#[tokio::test]
async fn generator_toggle_is_atomic() {
    assert_atomic_outcomes("set_enable_generator", generator_toggle_case).await;
}

#[tokio::test]
async fn password_history_enable_is_atomic() {
    assert_atomic_outcomes(
        "set_enable_password_history(true)",
        password_history_on_case,
    )
    .await;
}

/// Выключение истории стирает её в обеих базах: старые значения нельзя
/// вернуть повторным включением. OLD: флаг включён, история в обеих базах.
/// NEW: флаг выключен, истории нет нигде.
fn password_history_off_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let (canary, site) = (canary_id(&env), web_id(&env));
        change_value(&env, false, &canary, CHANGED);
        change_value(&env, true, &site, CHANGED);
        arm(plan);
        let _ = crate::commands::settings::update_password_history(&env.state, false);
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if let Some(meta) = opened {
            classify(
                (
                    meta.enable_password_history,
                    history_len(&env, false, &canary),
                    history_len(&env, true, &site),
                ),
                (true, Some(1), Some(1)),
                (false, Some(0), Some(0)),
                &mut violations,
            );
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

/// Повторное включение уже включённой истории ничего не стирает: очистка
/// нужна только при переходе из выключенного состояния.
#[tokio::test]
async fn enabling_password_history_again_keeps_it() {
    let (env, _) = unlocked().await;
    let canary = canary_id(&env);
    change_value(&env, false, &canary, CHANGED);
    assert_eq!(history_len(&env, false, &canary), Some(1));
    crate::commands::settings::update_password_history(&env.state, true).unwrap();
    assert_eq!(history_len(&env, false, &canary), Some(1));
}

#[tokio::test]
async fn password_history_disable_is_atomic() {
    assert_atomic_outcomes(
        "set_enable_password_history(false)",
        password_history_off_case,
    )
    .await;
}

// ------------------------------------------------------------ успешный вход

/// Неверных PIN до сценария: задержки ещё нет, но счётчик не нулевой.
const PRIOR_FAILURES: u32 = 3;

async fn after_wrong_pins(env: &Env) {
    for _ in 0..PRIOR_FAILURES {
        assert!(matches!(
            env.unlock(WRONG_PIN).await,
            Err(VaultError::InvalidPin)
        ));
    }
}

/// Счётчик задержек после успешного входа. NEW: сброшен. OLD: не сброшен —
/// прежний или с одной списанной попыткой (`verify_pin` списывает попытку до
/// проверки, и сбой до сброса оставляет её списанной: это безопасная
/// сторона). Успешный ответ без сброса — нарушение.
fn classify_backoff(failures: u32, unlocked: bool, violations: &mut Vec<String>) {
    match failures {
        0 => record(Outcome::New),
        n if n == PRIOR_FAILURES || n == PRIOR_FAILURES + 1 => {
            record(Outcome::Old);
            if unlocked {
                violations.push(format!("вход успешен, а задержки не сняты: {n}"));
            }
        }
        n => violations.push(format!("счётчик неверных PIN {n}")),
    }
}

fn pin_unlock_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = created().await;
        after_wrong_pins(&env).await;
        arm(plan);
        let result = env.unlock(PIN).await;
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        classify_backoff(env.backoff().failures, result.is_ok(), &mut violations);
        // Постоянной блокировки нет: после задержки верный PIN открывает.
        env.fake.advance_clock(crate::auth::backoff::MAX_DELAY_SECS);
        if !env.opens_with_pin(PIN).await {
            violations.push("верный PIN не открывает хранилище".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn pin_unlock_after_failures_is_atomic() {
    assert_atomic_outcomes("vault_unlock", pin_unlock_case).await;
}

fn fido_unlock_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = created().await;
        env.unlock(PIN).await.expect("unlock");
        env.bind_fido().await;
        env.state.lock();
        after_wrong_pins(&env).await;
        arm(plan);
        let result = crate::commands::vault::unlock_with_fido2(&env.state).await;
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        // Ключ поднесён один раз: списанной попытки PIN здесь не бывает.
        match env.backoff().failures {
            n if n == PRIOR_FAILURES + 1 => {
                violations.push("вход ключом списал попытку PIN".into())
            }
            n => classify_backoff(n, result.is_ok(), &mut violations),
        }
        // Оба пути входа остаются рабочими.
        let opened = crate::commands::vault::unlock_with_fido2(&env.state).await;
        if opened.is_err() || env.read_canary().as_deref() != Some(CANARY) {
            violations.push(format!("FIDO2 не открывает хранилище: {opened:?}"));
        }
        if !env.opens_with_pin(PIN).await {
            violations.push("PIN не открывает хранилище".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn fido_unlock_after_failures_is_atomic() {
    assert_atomic_outcomes("vault_unlock_with_fido2", fido_unlock_case).await;
}

/// Записи базы `records` подменены копией, снятой до последнего изменения:
/// обычный вход сообщает `DATA_ROLLBACK`. Возвращает показанный снимок.
async fn rolled_back() -> (Env, String) {
    let (mut env, _) = unlocked().await;
    env.state.lock();
    let aside = env.put_file(
        "records.old",
        &std::fs::read(env.state.records_path()).expect("records"),
    );
    env.unlock(PIN).await.expect("unlock");
    add(&env, false, "after-copy").expect("record");
    env.state.lock();
    std::fs::copy(&aside, env.state.records_path()).expect("swap in the old copy");
    env.restart();
    match env.unlock(PIN).await {
        Err(VaultError::DataRollback(snapshot)) => (env, snapshot),
        other => panic!("откат не обнаружен: {other:?}"),
    }
}

async fn accept(env: &Env, snapshot: String) -> crate::error::Result<()> {
    crate::commands::vault::unlock_with_pin_policy(
        &env.state,
        crate::commands::vault::VaultUnlockInput { pin: PIN.into() },
        crate::commands::vault::helpers::DataRollback::Accept { snapshot },
    )
    .await
}

/// OLD: решение не зафиксировано — обычный вход снова сообщает об откате, и
/// принять его можно повторно. NEW: обычный вход открывает старый снимок.
fn accept_rollback_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, snapshot) = rolled_back().await;
        arm(plan);
        let _ = accept(&env, snapshot).await;
        let (steps, trace) = observed();

        let (_, mut violations) = restart_and_inspect(&mut env).await;
        match env.unlock(PIN).await {
            Ok(()) => record(Outcome::New),
            Err(VaultError::DataRollback(again)) => {
                record(Outcome::Old);
                if let Err(error) = accept(&env, again).await {
                    violations.push(format!("OLD, но откат не принимается повторно: {error}"));
                }
            }
            Err(error) => violations.push(format!("вход не проходит: {error}")),
        }
        // В обоих исходах данные — из подложенного снимка: только канарейка.
        if count(&env, false) != Some(1) || env.read_canary().as_deref() != Some(CANARY) {
            violations.push(format!(
                "данные не из снимка: записей {:?}",
                count(&env, false)
            ));
        }
        env.restart();
        if env.unlock(PIN).await.is_err() {
            violations.push("после принятия обычный вход не проходит".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn accept_rollback_is_atomic() {
    assert_atomic_outcomes("vault_unlock_accept_rollback", accept_rollback_case).await;
}

// ------------------------------------------------------------ доли

/// OLD: `pending`. NEW: `active`. В обоих выданные доли открывают конверт.
fn acknowledge_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let mut env = Env::new();
        let output = env.create().await;
        env.add_canary();
        let shares = Shares {
            generation: output.recovery_generation,
            b: output.recovery_share_b_hex,
            c: output.recovery_share_c_hex,
        };
        arm(plan);
        let _ = crate::commands::recovery::acknowledge_recovery(&env.state, shares.generation);
        let (steps, trace) = observed();

        let (meta, mut violations) = restart_and_inspect(&mut env).await;
        if let Some(meta) = meta {
            match meta.recovery_state {
                RecoveryState::Pending => record(Outcome::Old),
                RecoveryState::Active => record(Outcome::New),
                other => violations.push(format!("состояние восстановления {other:?}")),
            }
            if meta.recovery_generation != shares.generation || !shares_open(&env, &shares) {
                violations.push("выданные доли не открывают хранилище".into());
            }
        }
        if !env.opens_with_pin(PIN).await {
            violations.push("PIN не открывает хранилище".into());
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn recovery_acknowledge_is_atomic() {
    assert_atomic_outcomes("recovery_acknowledge", acknowledge_case).await;
}

// ------------------------------------------------------------ backup config

/// Следы оборванной записи в каталоге хранилища.
fn temporaries(env: &Env) -> Vec<String> {
    std::fs::read_dir(&env.root)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(".tmp"))
                .collect()
        })
        .unwrap_or_default()
}

/// Конфиг резервных копий наблюдается поведением: OLD — каталог не выбран,
/// копия не создаётся (`BadInput`). NEW — копия пишется в выбранный каталог.
/// Испорченный конфиг (ошибка MAC) — нарушение.
fn backup_config_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let dir = env.root.parent().expect("parent").join("backups");
        std::fs::create_dir_all(&dir).expect("backup dir");
        env.authorize(SecurityAction::ChangeBackupDirectory).await;
        let capability = env.grant(&dir, FileOperation::BackupDirectory);
        arm(plan);
        let _ = crate::commands::backup::set_backup_config(
            &env.state,
            crate::commands::backup::BackupSetInput {
                directory_capability: Some(capability),
                frequency: "daily".into(),
            },
        );
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        let left = temporaries(&env);
        if !left.is_empty() {
            violations.push(format!("после старта остались временные файлы: {left:?}"));
        }
        if opened.is_some() {
            match crate::commands::backup::backup_now_blocking(
                &env.state,
                &uuid::Uuid::new_v4().to_string(),
            ) {
                Ok(_) => record(Outcome::New),
                Err(VaultError::BadInput(_)) => record(Outcome::Old),
                Err(error) => violations.push(format!("конфиг не читается: {error}")),
            }
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn backup_set_config_is_atomic() {
    assert_atomic_outcomes("backup_set_config", backup_config_case).await;
}

// ------------------------------------------------------------ импорт CSV

const CSV: &str = "name,url,username,password\n\
    A,https://a.example,u1,P1\n\
    B,https://b.example,u2,P2\n\
    C,https://c.example,u3,P3\n";

/// Импорт CSV командой: файл, полномочие, разбор, запись в `web`.
fn import_command(env: &Env, path: &std::path::Path) -> crate::error::Result<Option<String>> {
    let capability = env.grant(path, FileOperation::CsvImport);
    crate::commands::import::import_csv(&env.state, &capability).map(|result| result.deletion_token)
}

/// OLD: в `web` только прежняя запись. NEW: она и три импортированные.
fn import_csv_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let path = env.put_file("passwords.csv", CSV.as_bytes());
        arm(plan);
        let _ = import_command(&env, &path);
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(count(&env, true), Some(1), Some(4), &mut violations);
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn import_chromium_csv_is_atomic() {
    assert_atomic_outcomes("import_chromium_csv", import_csv_case).await;
}

/// Затирание исходного CSV после полного импорта. Наблюдается открытый текст
/// по пути файла: OLD — файл байт в байт прежний; NEW — открытого текста
/// нет (файл удалён, либо сбой пришёлся между затиранием и удалением и на
/// месте остался мусор той же длины). OLD обязан оставлять путь к повтору:
/// повторный импорт того же файла выдаёт новое разрешение.
fn secure_delete_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let path = env.put_file("passwords.csv", CSV.as_bytes());
        let token = import_command(&env, &path)
            .expect("import")
            .expect("deletion token after a full import");
        arm(plan);
        let _ = crate::commands::import::delete_imported_csv(&env.state, &token);
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            if count(&env, true) != Some(4) {
                violations.push(format!("импортированные записи: {:?}", count(&env, true)));
            }
            match std::fs::read(&path) {
                Ok(bytes) if bytes == CSV.as_bytes() => {
                    record(Outcome::Old);
                    match import_command(&env, &path) {
                        Ok(Some(token)) => {
                            if let Err(error) =
                                crate::commands::import::delete_imported_csv(&env.state, &token)
                            {
                                violations.push(format!("OLD, но повтор удаления: {error}"));
                            }
                        }
                        other => {
                            violations.push(format!("OLD, но нового разрешения нет: {other:?}"))
                        }
                    }
                }
                Ok(bytes) if bytes.len() == CSV.len() => record(Outcome::New),
                Ok(bytes) => {
                    violations.push(format!("файл изменён частично: {} байт", bytes.len()))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => record(Outcome::New),
                Err(error) => violations.push(format!("файл не читается: {error}")),
            }
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn secure_delete_file_is_atomic() {
    assert_atomic_outcomes("secure_delete_file", secure_delete_case).await;
}

// ------------------------------------------------------------ записи

/// OLD: прежнее значение, истории нет. NEW: новое значение, прежнее — в
/// истории.
fn record_update_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let id = canary_id(&env);
        let data = with_value(&get(&env, false, &id), CHANGED);
        arm(plan);
        let _ = crate::commands::records::update_entry(
            &env.state,
            crate::commands::records::UpdateInput {
                id: id.clone(),
                data,
                db_type: db_type(false),
            },
        )
        .await;
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(
                (env.read_canary(), history_len(&env, false, &id)),
                (Some(CANARY.to_string()), Some(0)),
                (Some(CHANGED.to_string()), Some(1)),
                &mut violations,
            );
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn record_update_is_atomic() {
    assert_atomic_outcomes("record_update", record_update_case).await;
}

/// OLD: запись на месте. NEW: её нет. Канарейка цела в обоих.
fn record_delete_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let id = add(&env, false, "victim").expect("record");
        arm(plan);
        let _ = crate::commands::records::delete_entry(
            &env.state,
            crate::commands::records::DeleteInput {
                id,
                db_type: db_type(false),
            },
        );
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(count(&env, false), Some(2), Some(1), &mut violations);
            if env.read_canary().as_deref() != Some(CANARY) {
                violations.push("удалена не та запись".into());
            }
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn record_delete_is_atomic() {
    assert_atomic_outcomes("record_delete", record_delete_case).await;
}

/// OLD: все три выбранные записи на месте. NEW: ни одной. Удаление части
/// выбранного — нарушение: пользователь удалял их одним действием.
fn batch_delete_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let record_ids = ["victim-1", "victim-2", "victim-3"]
            .iter()
            .map(|name| add(&env, false, name).expect("record"))
            .collect();
        arm(plan);
        let _ = crate::commands::records::batch_delete_entries(
            &env.state,
            crate::commands::records::BatchDeleteInput {
                db_type: db_type(false),
                record_ids,
            },
        );
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(count(&env, false), Some(4), Some(1), &mut violations);
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn records_batch_delete_is_atomic() {
    assert_atomic_outcomes("records_batch_delete", batch_delete_case).await;
}

/// OLD: прежний порядок. NEW: обратный. Смешанного порядка не бывает.
fn reorder_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, _) = unlocked().await;
        let mut ids = vec![canary_id(&env)];
        ids.extend(["first", "second"].map(|name| add(&env, false, name).expect("record")));
        env.with_session(|_, records, _| crate::storage::records::reorder_records(records, &ids))
            .expect("unlocked")
            .expect("initial order");
        let reversed: Vec<String> = ids.iter().rev().cloned().collect();
        arm(plan);
        let _ = crate::commands::records::reorder_entries(
            &env.state,
            crate::commands::records::ReorderInput {
                ordered_ids: reversed.clone(),
                db_type: db_type(false),
            },
        );
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(order(&env), Some(ids), Some(reversed), &mut violations);
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn record_reorder_is_atomic() {
    assert_atomic_outcomes("record_reorder", reorder_case).await;
}

/// Канарейка изменена: прежнее значение — единственная запись истории.
async fn with_history() -> (Env, String) {
    let (env, _) = unlocked().await;
    let id = canary_id(&env);
    change_value(&env, false, &id, CHANGED);
    (env, id)
}

/// OLD: текущее значение изменённое, в истории одна запись. NEW: значение
/// из истории, а изменённое само ушло в историю (записей две).
fn restore_history_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, id) = with_history().await;
        let history_id = env
            .with_session(|_, records, _| {
                crate::storage::records::get_password_history(records, &id)
            })
            .expect("unlocked")
            .expect("history")
            .remove(0)
            .id;
        arm(plan);
        let _ = crate::commands::records::restore_history_entry(
            &env.state,
            crate::commands::records::HistoryEntryInput {
                record_id: id.clone(),
                history_id,
                db_type: db_type(false),
            },
        )
        .await;
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(
                (env.read_canary(), history_len(&env, false, &id)),
                (Some(CHANGED.to_string()), Some(1)),
                (Some(CANARY.to_string()), Some(2)),
                &mut violations,
            );
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn record_restore_password_history_is_atomic() {
    assert_atomic_outcomes("record_restore_password_history", restore_history_case).await;
}

/// OLD: запись истории на месте. NEW: истории нет. Текущее значение не
/// меняется ни в одном исходе.
fn clear_history_case(plan: Option<(usize, Mode)>) -> CaseFuture {
    Box::pin(async move {
        let (mut env, id) = with_history().await;
        arm(plan);
        let _ = crate::commands::records::clear_history(
            &env.state,
            crate::commands::records::HistoryInput {
                record_id: id.clone(),
                db_type: db_type(false),
            },
        );
        let (steps, trace) = observed();

        let (opened, mut violations) = reopen(&mut env).await;
        if opened.is_some() {
            classify(
                history_len(&env, false, &id),
                Some(1),
                Some(0),
                &mut violations,
            );
            if env.read_canary().as_deref() != Some(CHANGED) {
                violations.push("очистка истории изменила текущее значение".into());
            }
        }
        Case {
            steps,
            trace,
            violations,
        }
    })
}

#[tokio::test]
async fn record_clear_password_history_is_atomic() {
    assert_atomic_outcomes("record_clear_password_history", clear_history_case).await;
}
