use crate::error::{Result, VaultError};
use crate::storage::integrity::{compute_meta_mac, verify_meta_mac, MacInputs};
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::schema::{Fido2KeyRow, VaultMetaRow};
use super::MetaDb;

type HmacSha256 = Hmac<Sha256>;
const CHECKPOINT_DOMAIN: &[u8] = b"vaultisor:vault-checkpoint:v4";
const CHECKPOINT_ID_DOMAIN: &[u8] = b"vaultisor:vault-checkpoint-id:v3";
/// epoch ‖ meta_mac ‖ failures ‖ next_allowed ‖ last_failure
/// ‖ records (revision ‖ sha256) ‖ web (revision ‖ sha256) ‖ tag.
const CHECKPOINT_LEN: usize = 8 + 32 + 4 + 8 + 8 + (8 + 32) * 2 + 32;

/// Подтверждённое состояние базы записей или паролей сайтов.
///
/// Ревизия ловит замену файла целиком, SHA-256 файла — подмену отдельных
/// страниц: SQLCipher аутентифицирует страницы по одной, и старая версия
/// страницы N проходит проверку на месте страницы N, оставляя страницу с
/// ревизией текущей. Нулевой дайджест — «ещё не зафиксирован» (только у
/// только что созданного хранилища до первого входа).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct DataState {
    pub revision: u64,
    pub digest: [u8; 32],
}

impl DataState {
    pub fn recorded(&self) -> bool {
        self.digest != [0u8; 32]
    }
}

/// Внешний checkpoint хранилища — единственный якорь против отката файлов.
///
/// Лежит вне каталога хранилища (профиль пользователя, DPAPI) и подписан
/// integrity-ключом. Имя файла выводится из integrity-ключа, поэтому у
/// каждого ключа свой checkpoint: смена ключа (восстановление по долям)
/// создаёт новый файл до commit и удаляет старый после — ни в какой момент
/// живые метаданные не остаются без подходящего якоря.
///
/// Фиксирует:
/// - эпоху и MAC метаданных — откат `vault.meta.db`;
/// - задержки PIN — монотонное состояние безопасности, которое не уменьшают
///   ни откат, ни импорт, ни восстановление из копии;
/// - состояние `vault.records.db` и `vault.web.db` (ревизия и SHA-256 файла) —
///   откат баз целиком и подмена отдельных страниц. Ревизия растёт
///   триггерами в той же транзакции, что и изменение данных.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Anchor {
    pub epoch: u64,
    pub meta_mac: [u8; 32],
    pub backoff: crate::auth::backoff::BackoffState,
    pub records: DataState,
    pub web: DataState,
}

/// Идентификатор checkpoint'а для integrity-ключа: HMAC, а не сам ключ.
pub(crate) fn checkpoint_id(integrity_key: &[u8; 32]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(integrity_key)
        .expect("HMAC accepts keys of any length");
    mac.update(CHECKPOINT_ID_DOMAIN);
    hex::encode(mac.finalize().into_bytes())
}

/// Полная замена ключей и обёрток при восстановлении по долям.
pub(crate) struct Reseed<'a> {
    pub integrity_key: &'a [u8; 32],
    pub integrity_key_dpapi: &'a [u8],
    pub dpapi_entropy: &'a [u8],
    pub wrapped_master_dpapi: &'a [u8],
    pub params: crate::crypto::kdf::Argon2Params,
    /// Имя TPM-ключа и зашифрованный Device Secret; `None` — режим
    /// мастер-пароля (на устройстве нет TPM 2.0).
    pub device_secret: Option<(&'a str, &'a [u8])>,
    pub op_id: &'a str,
    /// Состояние баз после rebase: точка отсчёта нового ключа.
    pub records: DataState,
    pub web: DataState,
}

type FidoStatus = (bool, Option<Vec<u8>>, Option<Vec<u8>>);

impl MetaDb {
    pub fn vault_initialized(&self) -> Result<bool> {
        self.with_conn(|c| {
            let v: Option<i32> = c
                .query_row("SELECT 1 FROM vault_meta WHERE id = 1", [], |row| {
                    row.get(0)
                })
                .optional()?;
            Ok(v.is_some())
        })
    }

    /// Создать метаданные хранилища и сразу запечатать их MAC-ом и anchor-ом.
    #[allow(clippy::too_many_arguments)]
    pub fn vault_create(
        &self,
        wrapped_master_dpapi: &[u8],
        autolock: u32,
        clipboard_clear: u32,
        integrity_key_dpapi: &[u8],
        integrity_key: &[u8; 32],
        dpapi_entropy: &[u8],
        op_id: Option<&str>,
    ) -> Result<()> {
        let _security = super::SECURITY_WRITE_LOCK.lock();
        self.with_conn(|c| {
            c.execute_batch("BEGIN IMMEDIATE")?;
            let res: Result<()> = (|| {
                let now = chrono::Utc::now().to_rfc3339();
                c.execute(
                    r#"INSERT INTO vault_meta
                        (id, created_at, wrapped_master_key,
                         autolock_seconds, clipboard_clear_seconds,
                         integrity_key_dpapi, dpapi_entropy, last_op_id)
                       VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7)"#,
                    params![
                        now,
                        wrapped_master_dpapi,
                        autolock as i64,
                        clipboard_clear as i64,
                        integrity_key_dpapi,
                        dpapi_entropy,
                        op_id,
                    ],
                )?;
                update_meta_mac(c, integrity_key)?;
                Ok(())
            })();
            commit_or_rollback(c, res)
        })?;
        self.write_checkpoint(integrity_key)
    }

    pub fn vault_load(&self) -> Result<Option<VaultMetaRow>> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    r#"SELECT created_at, wrapped_master_key,
                              autolock_seconds, clipboard_clear_seconds,
                              require_auth_for_copy, use_windows_hello,
                              pin_next_allowed, failed_pin_attempts,
                              crypto_version, device_secret_tpm_name, device_secret_tpm_blob,
                              argon2_m_cost, argon2_t_cost, argon2_p_cost,
                              ui_language, enable_health_check, enable_password_history,
                              dpapi_entropy,
                              recovery_generation, recovery_wrapped_master, security_epoch,
                              hello_key_credential_name, hello_key_credential_public_key,
                              enable_generator, last_op_id, pin_last_failure,
                              recovery_state,
                              data_rebase_pending, pin_change_request_id,
                              import_records_sha256, import_web_sha256
                       FROM vault_meta WHERE id = 1"#,
                    [],
                    |row| {
                        Ok(VaultMetaRow {
                            created_at: row.get(0)?,
                            wrapped_master_dpapi: row.get(1)?,
                            autolock_seconds: row.get::<_, i64>(2)? as u32,
                            clipboard_clear_seconds: row.get::<_, i64>(3)? as u32,
                            require_auth_for_copy: row.get::<_, i64>(4)? != 0,
                            use_windows_hello: row.get::<_, i64>(5)? != 0,
                            backoff: crate::auth::backoff::BackoffState {
                                failures: row.get::<_, i64>(7)?.clamp(0, u32::MAX as i64) as u32,
                                next_allowed: row.get(6)?,
                                last_failure: row.get(25)?,
                            },
                            crypto_version: row.get::<_, i64>(8)? as u32,
                            device_secret_tpm_name: row.get(9)?,
                            device_secret_tpm_blob: row.get(10)?,
                            argon2_m_cost: row.get::<_, i64>(11)? as u32,
                            argon2_t_cost: row.get::<_, i64>(12)? as u32,
                            argon2_p_cost: row.get::<_, i64>(13)? as u32,
                            ui_language: row.get(14)?,
                            enable_health_check: row.get::<_, i64>(15)? != 0,
                            enable_password_history: row.get::<_, i64>(16)? != 0,
                            dpapi_entropy: row.get(17)?,
                            recovery_generation: row.get::<_, i64>(18)?.max(0) as u64,
                            recovery_wrapped_master: row.get(19)?,
                            recovery_state: super::RecoveryState::parse(&row.get::<_, String>(26)?)
                                .map_err(|_| {
                                    rusqlite::Error::InvalidColumnType(
                                        26,
                                        "recovery_state".into(),
                                        rusqlite::types::Type::Text,
                                    )
                                })?,
                            data_rebase_pending: row.get::<_, i64>(27)? != 0,
                            pin_change_request_id: row.get(28)?,
                            imported_snapshot: match (
                                row.get::<_, Option<Vec<u8>>>(29)?,
                                row.get::<_, Option<Vec<u8>>>(30)?,
                            ) {
                                (Some(records), Some(web)) => {
                                    match (records.try_into(), web.try_into()) {
                                        (Ok(records), Ok(web)) => Some((records, web)),
                                        _ => None,
                                    }
                                }
                                _ => None,
                            },
                            security_epoch: row.get::<_, i64>(20)?.max(0) as u64,
                            hello_key_credential_name: row.get(21)?,
                            hello_key_credential_public_key: row.get(22)?,
                            enable_generator: row.get::<_, i64>(23)? != 0,
                            last_op_id: row.get(24)?,
                        })
                    },
                )
                .optional()?;
            Ok(row)
        })
    }

    pub fn get_integrity_key_dpapi(&self) -> Result<Option<Vec<u8>>> {
        self.with_conn(|c| {
            let blob: Option<Option<Vec<u8>>> = c
                .query_row(
                    "SELECT integrity_key_dpapi FROM vault_meta WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .optional()?;
            Ok(blob.flatten())
        })
    }

    /// Полная проверка: подпись метаданных плюс защита от отката к старому снимку.
    pub fn verify_meta_integrity(&self, integrity_key: &[u8; 32]) -> Result<()> {
        let _security = super::SECURITY_WRITE_LOCK.lock();
        self.verify_meta_mac_only(integrity_key)?;
        self.verify_checkpoint(integrity_key)
    }

    /// Проверить только подпись, не трогая rollback-состояние.
    /// Нужна для снимков: проверка бэкапа не должна двигать якорь живой базы.
    pub fn verify_meta_mac_only(&self, integrity_key: &[u8; 32]) -> Result<()> {
        let _security = super::SECURITY_WRITE_LOCK.lock();
        self.with_conn(|c| {
            let row = read_meta_for_mac(c)?;
            let stored_mac: Option<Vec<u8>> = c
                .query_row("SELECT meta_mac FROM vault_meta WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .optional()?
                .flatten();
            let stored_mac = stored_mac.ok_or(VaultError::MetaTampered)?;
            if verify_meta_mac(integrity_key, &mac_inputs_from(&row), &stored_mac) {
                Ok(())
            } else {
                Err(VaultError::MetaTampered)
            }
        })
    }

    /// Любая защищённая мутация: изменение + инкремент эпохи + пересчёт MAC в
    /// одной транзакции, затем обновление rollback-якоря.
    pub fn update_meta_secure<F>(&self, integrity_key: &[u8; 32], f: F) -> Result<()>
    where
        F: FnOnce(&Connection) -> Result<()>,
    {
        let _security = super::SECURITY_WRITE_LOCK.lock();
        self.with_conn(|c| {
            c.execute_batch("BEGIN IMMEDIATE")?;
            let res: Result<()> = (|| {
                f(c)?;
                c.execute(
                    "UPDATE vault_meta SET security_epoch = security_epoch + 1 WHERE id = 1",
                    [],
                )?;
                update_meta_mac(c, integrity_key)?;
                Ok(())
            })();
            commit_or_rollback(c, res)
        })?;
        self.write_checkpoint(integrity_key)
    }

    /// Защищённая мутация операции из журнала ресурсов ОС: изменение и
    /// `last_op_id` фиксируются одной транзакцией — это и есть commit операции.
    pub fn commit_operation<F>(&self, integrity_key: &[u8; 32], op_id: &str, f: F) -> Result<()>
    where
        F: FnOnce(&Connection) -> Result<()>,
    {
        self.update_meta_secure(integrity_key, |c| {
            f(c)?;
            c.execute(
                "UPDATE vault_meta SET last_op_id = ?1 WHERE id = 1",
                params![op_id],
            )?;
            Ok(())
        })
    }

    /// Пере-подписать уже снятый снимок метаданных, НЕ меняя его эпоху.
    /// Бэкап намеренно сохраняет эпоху источника, но санитизация меняет
    /// защищённые поля, поэтому подпись нужно пересчитать.
    pub fn reseal_snapshot(&self, integrity_key: &[u8; 32]) -> Result<()> {
        let _security = super::SECURITY_WRITE_LOCK.lock();
        self.with_conn(|c| {
            c.execute_batch("BEGIN IMMEDIATE")?;
            let result = update_meta_mac(c, integrity_key);
            commit_or_rollback(c, result)
        })
    }

    /// Состояние метаданных, которое фиксирует checkpoint (без ревизий баз).
    fn current_anchor(&self) -> Result<Anchor> {
        self.with_conn(current_anchor_in)
    }

    fn anchor_body(anchor: &Anchor) -> Vec<u8> {
        let mut body = Vec::with_capacity(CHECKPOINT_LEN - 32);
        body.extend_from_slice(&anchor.epoch.to_le_bytes());
        body.extend_from_slice(&anchor.meta_mac);
        body.extend_from_slice(&anchor.backoff.failures.to_le_bytes());
        body.extend_from_slice(&anchor.backoff.next_allowed.to_le_bytes());
        body.extend_from_slice(&anchor.backoff.last_failure.to_le_bytes());
        for state in [&anchor.records, &anchor.web] {
            body.extend_from_slice(&state.revision.to_le_bytes());
            body.extend_from_slice(&state.digest);
        }
        body
    }

    fn checkpoint_tag(integrity_key: &[u8; 32], body: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(integrity_key)
            .expect("HMAC accepts keys of any length");
        mac.update(CHECKPOINT_DOMAIN);
        mac.update(body);
        mac.finalize().into_bytes().into()
    }

    fn seal_anchor(integrity_key: &[u8; 32], anchor: &Anchor) -> Vec<u8> {
        let mut data = Self::anchor_body(anchor);
        let tag = Self::checkpoint_tag(integrity_key, &data);
        data.extend_from_slice(&tag);
        data
    }

    /// Прочитать checkpoint этого integrity-ключа. `None` — файла нет;
    /// испорченный или чужой файл — `MetaTampered`.
    fn read_checkpoint(&self, integrity_key: &[u8; 32]) -> Result<Option<Anchor>> {
        crate::storage::machine_checkpoint::read(
            &self.checkpoint_root,
            &checkpoint_id(integrity_key),
        )?
        .map(|data| Self::parse_anchor(integrity_key, &data))
        .transpose()
    }

    fn store_checkpoint(&self, integrity_key: &[u8; 32], anchor: &Anchor) -> Result<()> {
        crate::storage::machine_checkpoint::write(
            &self.checkpoint_root,
            &checkpoint_id(integrity_key),
            &Self::seal_anchor(integrity_key, anchor),
        )
    }

    /// Записать checkpoint текущего состояния метаданных. Ревизии баз
    /// переносятся из прежнего checkpoint'а этого ключа: мутация метаданных
    /// их не меняет.
    fn write_checkpoint(&self, integrity_key: &[u8; 32]) -> Result<()> {
        let previous = self.read_checkpoint(integrity_key)?;
        let mut anchor = self.current_anchor()?;
        if let Some(previous) = previous {
            anchor.records = previous.records;
            anchor.web = previous.web;
        }
        self.store_checkpoint(integrity_key, &anchor)
    }

    /// Checkpoint обязан существовать и не опережать метаданные; отстающий
    /// (сбой между commit и записью checkpoint'а) догоняется.
    fn verify_checkpoint(&self, integrity_key: &[u8; 32]) -> Result<()> {
        let anchor = self
            .read_checkpoint(integrity_key)?
            .ok_or(VaultError::MetaTampered)?;
        let current = self.current_anchor()?;
        if anchor.epoch > current.epoch
            || (anchor.epoch == current.epoch
                && !bool::from(anchor.meta_mac.ct_eq(&current.meta_mac)))
        {
            return Err(VaultError::MetaTampered);
        }
        if current.epoch > anchor.epoch {
            self.write_checkpoint(integrity_key)?;
        }
        Ok(())
    }

    /// Разобрать и проверить подпись checkpoint'а, не сравнивая с живыми данными.
    fn parse_anchor(integrity_key: &[u8; 32], data: &[u8]) -> Result<Anchor> {
        if data.len() != CHECKPOINT_LEN {
            return Err(VaultError::MetaTampered);
        }
        let (body, tag) = data.split_at(CHECKPOINT_LEN - 32);
        let expected = Self::checkpoint_tag(integrity_key, body);
        if !bool::from(expected.ct_eq(tag)) {
            return Err(VaultError::MetaTampered);
        }
        let u64_at = |at: usize| u64::from_le_bytes(body[at..at + 8].try_into().expect("8 bytes"));
        let i64_at = |at: usize| i64::from_le_bytes(body[at..at + 8].try_into().expect("8 bytes"));
        Ok(Anchor {
            epoch: u64_at(0),
            meta_mac: body[8..40].try_into().expect("32 bytes"),
            backoff: crate::auth::backoff::BackoffState {
                failures: u32::from_le_bytes(body[40..44].try_into().expect("4 bytes")),
                next_allowed: i64_at(44),
                last_failure: i64_at(52),
            },
            records: DataState {
                revision: u64_at(60),
                digest: body[68..100].try_into().expect("32 bytes"),
            },
            web: DataState {
                revision: u64_at(100),
                digest: body[108..140].try_into().expect("32 bytes"),
            },
        })
    }

    /// Состояние задержек PIN из checkpoint'а этого ключа, если он есть.
    /// Живые метаданные с ним не сравниваются: это нужно именно там, где они
    /// могли быть заменены.
    pub(crate) fn checkpoint_backoff(
        &self,
        integrity_key: &[u8; 32],
    ) -> Result<Option<crate::auth::backoff::BackoffState>> {
        Ok(self
            .read_checkpoint(integrity_key)?
            .map(|anchor| anchor.backoff))
    }

    /// Подтверждённое состояние `records` и `web`. Checkpoint обязан быть.
    pub(crate) fn data_state(&self, integrity_key: &[u8; 32]) -> Result<(DataState, DataState)> {
        let anchor = self
            .read_checkpoint(integrity_key)?
            .ok_or(VaultError::MetaTampered)?;
        Ok((anchor.records, anchor.web))
    }

    /// Подтвердить новое состояние баз. Ревизия в checkpoint'е только растёт:
    /// состояние с меньшей ревизией игнорируется, поэтому повтор и гонка
    /// безопасны. С той же ревизией принимается только первый дайджест
    /// (у хранилища, где он ещё не зафиксирован).
    pub(crate) fn advance_data_state(
        &self,
        integrity_key: &[u8; 32],
        records: Option<DataState>,
        web: Option<DataState>,
    ) -> Result<()> {
        let _security = super::SECURITY_WRITE_LOCK.lock();
        let mut anchor = self
            .read_checkpoint(integrity_key)?
            .ok_or(VaultError::MetaTampered)?;
        let mut changed = false;
        for (slot, update) in [(&mut anchor.records, records), (&mut anchor.web, web)] {
            let Some(update) = update else { continue };
            let newer = update.revision > slot.revision;
            let first_digest = update.revision == slot.revision && !slot.recorded();
            if newer || first_digest {
                *slot = update;
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        crate::failpoint::hit("revision.checkpoint")?;
        self.store_checkpoint(integrity_key, &anchor)
    }

    /// Импорт на устройство, где integrity-ключ бандла не разворачивается:
    /// подпись проверить и пересчитать нечем. Отмечается только операция
    /// публикации; подпись станет недействительной, но на этом устройстве её
    /// и так никто не проверит — вход возможен лишь восстановлением по долям,
    /// которое заново создаёт ключи и подпись (`reseed`).
    pub(crate) fn mark_unsealed_import(&self, op_id: &str) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                "UPDATE vault_meta SET last_op_id = ?1 WHERE id = 1",
                params![op_id],
            )?;
            Ok(())
        })
    }

    /// Ревизии баз подняты выше подтверждённых после импорта: отметка о
    /// необходимости rebase снимается.
    pub(crate) fn finish_data_rebase(&self, integrity_key: &[u8; 32]) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET data_rebase_pending = 0, import_records_sha256 = NULL, \
                 import_web_sha256 = NULL WHERE id = 1",
                [],
            )?;
            Ok(())
        })
    }

    /// Восстановление по долям: новые integrity-ключ, энтропия DPAPI, обёртка
    /// мастер-ключа, Device Secret и параметры Argon2 — одной транзакцией.
    ///
    /// ```text
    /// BEGIN → все поля → MAC новым ключом → checkpoint нового ключа → COMMIT
    /// ```
    ///
    /// Checkpoint нового ключа — отдельный файл, поэтому его запись до COMMIT
    /// безопасна: до commit живые метаданные опираются на старый checkpoint,
    /// после — на новый. Старый удаляется журналом только после commit.
    ///
    /// Сбрасывается всё, что держалось на старом устройстве или старых
    /// ключах: Hello, подтверждение копирования, FIDO2-ключи (их конверты
    /// завязаны на прежние Device Secret и энтропию), задержки PIN (владелец
    /// доказал себя долями и задал новый PIN). Поколение восстановления
    /// отзывается: доли израсходованы, хранилище переходит в `pending` и при
    /// следующем входе выдаст новый комплект.
    pub(crate) fn reseed(&self, spec: &Reseed<'_>) -> Result<()> {
        let _security = super::SECURITY_WRITE_LOCK.lock();
        self.with_conn(|c| {
            c.execute_batch("BEGIN IMMEDIATE")?;
            let res: Result<()> = (|| {
                let (ds_name, ds_blob) = match spec.device_secret {
                    Some((name, blob)) => (Some(name), Some(blob)),
                    None => (None, None),
                };
                c.execute(
                    r#"UPDATE vault_meta SET
                           integrity_key_dpapi = ?1,
                           dpapi_entropy = ?2,
                           wrapped_master_key = ?3,
                           argon2_m_cost = ?4, argon2_t_cost = ?5, argon2_p_cost = ?6,
                           crypto_version = ?7,
                           device_secret_tpm_name = ?8, device_secret_tpm_blob = ?9,
                           use_windows_hello = 0, require_auth_for_copy = 0,
                           hello_key_credential_name = NULL,
                           hello_key_credential_public_key = NULL,
                           recovery_generation = recovery_generation + 1,
                           recovery_wrapped_master = NULL,
                           recovery_state = 'pending',
                           failed_pin_attempts = 0, pin_next_allowed = 0, pin_last_failure = 0,
                           data_rebase_pending = 0,
                           import_records_sha256 = NULL, import_web_sha256 = NULL,
                           last_op_id = ?10,
                           security_epoch = security_epoch + 1
                       WHERE id = 1"#,
                    params![
                        spec.integrity_key_dpapi,
                        spec.dpapi_entropy,
                        spec.wrapped_master_dpapi,
                        spec.params.m_cost as i64,
                        spec.params.t_cost as i64,
                        spec.params.p_cost as i64,
                        if spec.device_secret.is_some() {
                            2i64
                        } else {
                            1i64
                        },
                        ds_name,
                        ds_blob,
                        spec.op_id,
                    ],
                )?;
                c.execute("DELETE FROM fido2_keys", [])?;
                update_meta_mac(c, spec.integrity_key)?;
                let mut anchor = current_anchor_in(c)?;
                anchor.records = spec.records;
                anchor.web = spec.web;
                self.store_checkpoint(spec.integrity_key, &anchor)
            })();
            commit_or_rollback(c, res)
        })
    }

    /// Подготовить импортированные метаданные (ещё в каталоге сборки) к
    /// публикации на устройстве, где их integrity-ключ разворачивается.
    ///
    /// Бандл — недоверенный файл: подпись обязана сойтись. Затем метаданные
    /// перепечатываются так, чтобы импорт никогда не ослаблял монотонное
    /// состояние из checkpoint'а этого ключа:
    /// - эпоха — выше и снимка, и checkpoint'а;
    /// - задержки PIN — строжайшие из снимка и checkpoint'а;
    /// - ревизии баз в checkpoint'е не уменьшаются: без мастер-ключа поднять
    ///   ревизии внутри баз нельзя, поэтому ставится `data_rebase_pending`, и
    ///   первый вход (он даёт мастер-ключ) переносит ревизии баз выше
    ///   подтверждённых. Подтверждённая ревизия не уменьшается никогда.
    ///
    /// Доли A в бандле нет (она привязана к устройству и из копий удаляется),
    /// поэтому восстановление переводится в `pending`: при первом входе будет
    /// выдан новый полный комплект.
    ///
    /// Отметка `data_rebase_pending` привязана к импортированному снимку:
    /// SHA-256 обеих баз записываются под MAC, и первый вход переносит
    /// ревизии вперёд только над этими самыми файлами.
    pub(crate) fn reseal_import(
        &self,
        integrity_key: &[u8; 32],
        op_id: &str,
        imported: ([u8; 32], [u8; 32]),
    ) -> Result<()> {
        let _security = super::SECURITY_WRITE_LOCK.lock();
        self.verify_meta_mac_only(integrity_key)?;
        let known = self.read_checkpoint(integrity_key)?;
        self.with_conn(|c| {
            c.execute_batch("BEGIN IMMEDIATE")?;
            let res: Result<()> = (|| {
                let snapshot = current_anchor_in(c)?;
                let (epoch, backoff) = match &known {
                    Some(anchor) => (
                        snapshot.epoch.max(anchor.epoch) + 1,
                        snapshot.backoff.strictest(anchor.backoff),
                    ),
                    None => (snapshot.epoch + 1, snapshot.backoff),
                };
                c.execute(
                    r#"UPDATE vault_meta SET
                           security_epoch = ?1,
                           failed_pin_attempts = ?2, pin_next_allowed = ?3, pin_last_failure = ?4,
                           recovery_state = CASE
                               WHEN recovery_wrapped_master IS NULL THEN 'disabled'
                               ELSE 'pending' END,
                           data_rebase_pending = 1,
                           import_records_sha256 = ?6, import_web_sha256 = ?7,
                           last_op_id = ?5
                       WHERE id = 1"#,
                    params![
                        epoch as i64,
                        backoff.failures as i64,
                        backoff.next_allowed,
                        backoff.last_failure,
                        op_id,
                        &imported.0[..],
                        &imported.1[..],
                    ],
                )?;
                update_meta_mac(c, integrity_key)
            })();
            commit_or_rollback(c, res)
        })?;
        self.write_checkpoint(integrity_key)
    }

    /// Настройки удобства: автоблокировка и очистка буфера. Факторы и
    /// подтверждения меняются только своими операциями (`set_hello`,
    /// `set_step_up`), которые требуют повторной аутентификации.
    pub fn update_settings(
        &self,
        integrity_key: &[u8; 32],
        autolock: u32,
        clipboard_clear: u32,
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET autolock_seconds = ?1, clipboard_clear_seconds = ?2 \
                 WHERE id = 1",
                params![autolock as i64, clipboard_clear as i64],
            )?;
            Ok(())
        })
    }

    /// Включить Hello (имя и публичный ключ credential'а) или выключить его —
    /// вместе с подтверждением копирования, которое без Hello невозможно.
    /// Одна транзакция и commit операции журнала ресурсов ОС.
    pub fn set_hello(
        &self,
        integrity_key: &[u8; 32],
        op_id: &str,
        credential: Option<(&str, &[u8])>,
    ) -> Result<()> {
        self.commit_operation(integrity_key, op_id, |c| {
            match credential {
                Some((name, public_key)) => c.execute(
                    "UPDATE vault_meta SET use_windows_hello = 1, \
                     hello_key_credential_name = ?1, hello_key_credential_public_key = ?2 \
                     WHERE id = 1",
                    params![name, public_key],
                )?,
                None => c.execute(
                    "UPDATE vault_meta SET use_windows_hello = 0, require_auth_for_copy = 0, \
                     hello_key_credential_name = NULL, hello_key_credential_public_key = NULL \
                     WHERE id = 1",
                    [],
                )?,
            };
            Ok(())
        })
    }

    /// Подтверждение Hello для копирования и просмотра секретов.
    pub fn set_step_up(&self, integrity_key: &[u8; 32], enabled: bool) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            if enabled {
                let hello: i64 = c.query_row(
                    "SELECT use_windows_hello FROM vault_meta WHERE id = 1",
                    [],
                    |r| r.get(0),
                )?;
                if hello == 0 {
                    return Err(VaultError::BadInput(
                        "Подтверждение для копирования требует включённого Windows Hello".into(),
                    ));
                }
            }
            c.execute(
                "UPDATE vault_meta SET require_auth_for_copy = ?1 WHERE id = 1",
                params![enabled as i64],
            )?;
            Ok(())
        })
    }

    /// Заменить обёртку мастер-ключа под новым PIN вместе с параметрами
    /// Argon2, которыми она сделана. Одна транзакция: обёртка и параметры
    /// никогда не принадлежат разным состояниям.
    pub fn replace_pin_wrapper(
        &self,
        integrity_key: &[u8; 32],
        wrapped_dpapi: &[u8],
        params: crate::crypto::kdf::Argon2Params,
        request_id: &str,
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET wrapped_master_key = ?1, argon2_m_cost = ?2, \
                 argon2_t_cost = ?3, argon2_p_cost = ?4, pin_change_request_id = ?5 WHERE id = 1",
                params![
                    wrapped_dpapi,
                    params.m_cost as i64,
                    params.t_cost as i64,
                    params.p_cost as i64,
                    request_id
                ],
            )?;
            Ok(())
        })
    }

    /// Новое поколение восстановления: конверт и номер — одной транзакцией.
    /// Прежнее поколение этим же commit'ом отозвано. Поколение `pending`, пока
    /// пользователь не подтвердит, что сохранил части B и C.
    pub fn replace_recovery(
        &self,
        integrity_key: &[u8; 32],
        generation: u64,
        wrapped_master: &[u8],
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET recovery_generation = ?1, recovery_wrapped_master = ?2, \
                 recovery_state = 'pending' WHERE id = 1",
                params![generation as i64, wrapped_master],
            )?;
            Ok(())
        })
    }

    /// Пользователь подтвердил, что сохранил доли поколения `generation`.
    /// Подтверждается только текущее поколение с конвертом.
    /// Повтор подтверждения того же поколения — успех без мутации.
    pub fn acknowledge_recovery(&self, integrity_key: &[u8; 32], generation: u64) -> Result<()> {
        let meta = self.vault_load()?.ok_or(VaultError::NotInitialized)?;
        if meta.recovery_state == super::RecoveryState::Active
            && meta.recovery_generation == generation
        {
            return Ok(());
        }
        self.update_meta_secure(integrity_key, |c| {
            let changed = c.execute(
                "UPDATE vault_meta SET recovery_state = 'active' \
                 WHERE id = 1 AND recovery_state = 'pending' AND recovery_generation = ?1 \
                   AND recovery_wrapped_master IS NOT NULL",
                params![generation as i64],
            )?;
            if changed != 1 {
                return Err(VaultError::Recovery(
                    "Это поколение восстановления уже не текущее".into(),
                ));
            }
            Ok(())
        })
    }

    /// Выключить восстановление: отозвать поколение и удалить конверт.
    pub fn clear_recovery(&self, integrity_key: &[u8; 32]) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET recovery_generation = recovery_generation + 1, \
                 recovery_wrapped_master = NULL, recovery_state = 'disabled' WHERE id = 1",
                [],
            )?;
            Ok(())
        })
    }

    /// Состояние задержек после неверного PIN. Защищённая мутация: MAC,
    /// эпоха и оба якоря, поэтому откат файлов его не уменьшает.
    pub fn set_backoff(
        &self,
        integrity_key: &[u8; 32],
        state: crate::auth::backoff::BackoffState,
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET failed_pin_attempts = ?1, pin_next_allowed = ?2, \
                 pin_last_failure = ?3 WHERE id = 1",
                params![
                    state.failures as i64,
                    state.next_allowed,
                    state.last_failure
                ],
            )?;
            Ok(())
        })
    }

    /// Сохранить Device Secret: имя TPM-ключа и зашифрованный blob.
    pub fn save_device_secret(
        &self,
        integrity_key: &[u8; 32],
        tpm_name: &str,
        tpm_blob: &[u8],
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                r#"UPDATE vault_meta
                   SET device_secret_tpm_name = ?1,
                       device_secret_tpm_blob = ?2,
                       crypto_version = 2
                   WHERE id = 1"#,
                params![tpm_name, tpm_blob],
            )?;
            Ok(())
        })
    }

    pub fn get_device_secret(&self) -> Result<Option<(String, Vec<u8>)>> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT device_secret_tpm_name, device_secret_tpm_blob FROM vault_meta WHERE id = 1",
                    [],
                    |r| {
                        let name: Option<String> = r.get(0)?;
                        let blob: Option<Vec<u8>> = r.get(1)?;
                        Ok((name, blob))
                    },
                )
                .optional()?;
            match row {
                Some((Some(name), Some(blob))) => Ok(Some((name, blob))),
                _ => Ok(None),
            }
        })
    }

    pub fn save_argon2_params(
        &self,
        integrity_key: &[u8; 32],
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                r#"UPDATE vault_meta
                   SET argon2_m_cost = ?1, argon2_t_cost = ?2, argon2_p_cost = ?3
                   WHERE id = 1"#,
                params![m_cost as i64, t_cost as i64, p_cost as i64],
            )?;
            Ok(())
        })
    }

    pub fn get_ui_language(&self) -> Result<String> {
        self.with_conn(|c| {
            let lang = c
                .query_row("SELECT ui_language FROM vault_meta WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .unwrap_or_else(|_| "ru".to_string());
            Ok(lang)
        })
    }

    /// Пользовательские переключатели тоже идут под MAC: документация обещает
    /// защиту всех настроек от незаметного изменения.
    pub fn set_ui_language(&self, integrity_key: &[u8; 32], lang: &str) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET ui_language = ?1 WHERE id = 1",
                params![lang],
            )?;
            Ok(())
        })
    }

    pub fn get_enable_health_check(&self) -> Result<bool> {
        self.with_conn(|c| {
            let enabled: i64 = c
                .query_row(
                    "SELECT enable_health_check FROM vault_meta WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(1);
            Ok(enabled != 0)
        })
    }

    pub fn set_enable_health_check(&self, integrity_key: &[u8; 32], enabled: bool) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET enable_health_check = ?1 WHERE id = 1",
                params![enabled as i64],
            )?;
            Ok(())
        })
    }

    pub fn get_enable_password_history(&self) -> Result<bool> {
        self.with_conn(|c| {
            let enabled: i64 = c
                .query_row(
                    "SELECT enable_password_history FROM vault_meta WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(1);
            Ok(enabled != 0)
        })
    }

    pub fn set_enable_password_history(
        &self,
        integrity_key: &[u8; 32],
        enabled: bool,
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET enable_password_history = ?1 WHERE id = 1",
                params![enabled as i64],
            )?;
            Ok(())
        })
    }

    pub fn get_enable_generator(&self) -> Result<bool> {
        self.with_conn(|c| {
            let enabled: i64 = c
                .query_row(
                    "SELECT enable_generator FROM vault_meta WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            Ok(enabled != 0)
        })
    }

    pub fn set_enable_generator(&self, integrity_key: &[u8; 32], enabled: bool) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET enable_generator = ?1 WHERE id = 1",
                params![enabled as i64],
            )?;
            Ok(())
        })
    }

    pub fn get_fido2_status(&self) -> Result<FidoStatus> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT credential_id, fido2_wrapped_key FROM fido2_keys ORDER BY created_at ASC LIMIT 1",
                    [],
                    |r| {
                        let cred_id: Vec<u8> = r.get(0)?;
                        let wrapped: Vec<u8> = r.get(1)?;
                        Ok((cred_id, wrapped))
                    },
                )
                .optional()?;
            match row {
                Some((cred_id, wrapped)) => Ok((true, Some(cred_id), Some(wrapped))),
                None => Ok((false, None, None)),
            }
        })
    }

    pub fn get_fido2_keys(&self) -> Result<Vec<Fido2KeyRow>> {
        self.with_conn(|c| {
            let mut stmt = c.prepare("SELECT id, name, credential_id, public_key, fido2_wrapped_key, created_at, aaguid, require_pin, request_id FROM fido2_keys ORDER BY created_at ASC")?;
            let rows = stmt.query_map([], |r| {
                Ok(Fido2KeyRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    credential_id: r.get(2)?,
                    public_key: r.get(3)?,
                    fido2_wrapped_key: r.get(4)?,
                    created_at: r.get(5)?,
                    aaguid: r.get(6)?,
                    require_pin: r.get::<_, i64>(7)? != 0,
                    request_id: r.get(8)?,
                })
            })?;
            let mut list = Vec::new();
            for item in rows {
                list.push(item?);
            }
            Ok(list)
        })
    }

    // Явные поля сохранённого FIDO-credential остаются на этой границе.
    #[allow(clippy::too_many_arguments)]
    pub fn add_fido2_key(
        &self,
        integrity_key: &[u8; 32],
        name: &str,
        credential_id: &[u8],
        public_key: &[u8],
        fido2_wrapped_key: &[u8],
        aaguid: Option<&str>,
        require_pin: bool,
        request_id: Option<&str>,
    ) -> Result<Fido2KeyRow> {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let require_pin_i = if require_pin { 1i64 } else { 0i64 };
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "INSERT INTO fido2_keys (id, name, credential_id, public_key, fido2_wrapped_key, created_at, aaguid, require_pin, request_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![id, name, credential_id, public_key, fido2_wrapped_key, now, aaguid, require_pin_i, request_id],
            )?;
            Ok(())
        })?;
        Ok(Fido2KeyRow {
            id,
            name: name.to_string(),
            credential_id: credential_id.to_vec(),
            public_key: public_key.to_vec(),
            fido2_wrapped_key: fido2_wrapped_key.to_vec(),
            created_at: now,
            aaguid: aaguid.map(|s| s.to_string()),
            require_pin,
            request_id: request_id.map(str::to_string),
        })
    }

    /// Ключ, привязанный запросом `request_id`, если такой запрос уже выполнен.
    pub fn fido2_key_by_request(&self, request_id: &str) -> Result<Option<Fido2KeyRow>> {
        Ok(self
            .get_fido2_keys()?
            .into_iter()
            .find(|key| key.request_id.as_deref() == Some(request_id)))
    }

    pub fn delete_fido2_key(&self, integrity_key: &[u8; 32], id: &str) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute("DELETE FROM fido2_keys WHERE id = ?1", params![id])?;
            Ok(())
        })
    }
}

/// Состояние метаданных, которое фиксирует checkpoint (ревизии баз — нули:
/// их подставляет вызывающий).
fn current_anchor_in(c: &Connection) -> Result<Anchor> {
    let (epoch, mac, failures, next_allowed, last_failure): (i64, Vec<u8>, i64, i64, i64) = c
        .query_row(
            "SELECT security_epoch, meta_mac, failed_pin_attempts, pin_next_allowed, \
                pin_last_failure FROM vault_meta WHERE id = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
    Ok(Anchor {
        epoch: u64::try_from(epoch).map_err(|_| VaultError::MetaTampered)?,
        meta_mac: mac.try_into().map_err(|_| VaultError::MetaTampered)?,
        backoff: crate::auth::backoff::BackoffState {
            failures: u32::try_from(failures).map_err(|_| VaultError::MetaTampered)?,
            next_allowed,
            last_failure,
        },
        records: DataState::default(),
        web: DataState::default(),
    })
}

struct MetaForMac {
    failed_pin_attempts: u32,
    pin_next_allowed: i64,
    pin_last_failure: i64,
    autolock_seconds: u32,
    clipboard_clear_seconds: u32,
    require_auth_for_copy: bool,
    use_windows_hello: bool,
    created_at: String,
    wrapped_master: Vec<u8>,
    device_secret_tpm_name: Option<String>,
    device_secret_tpm_blob: Option<Vec<u8>>,
    crypto_version: u32,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    dpapi_entropy: Vec<u8>,
    fido2_keys_digest: Option<[u8; 32]>,
    recovery_generation: u64,
    recovery_wrapped_master: Option<Vec<u8>>,
    recovery_state: String,
    data_rebase_pending: bool,
    pin_change_request_id: Option<String>,
    import_records_sha256: Option<Vec<u8>>,
    import_web_sha256: Option<Vec<u8>>,
    security_epoch: u64,
    hello_key_credential_name: Option<String>,
    hello_key_credential_public_key: Option<Vec<u8>>,
    ui_language: String,
    enable_health_check: bool,
    enable_password_history: bool,
    enable_generator: bool,
    last_op_id: Option<String>,
}

/// Свёртка таблицы FIDO2-ключей: сама таблица под MAC не попадает, поэтому
/// её содержимое сводится к одному дайджесту с префиксами длины.
fn compute_fido2_keys_digest(c: &Connection) -> Result<Option<[u8; 32]>> {
    use sha2::{Digest, Sha256};
    let mut stmt = c.prepare(
        "SELECT id, credential_id, public_key, fido2_wrapped_key, aaguid, require_pin, request_id FROM fido2_keys ORDER BY id ASC",
    )?;
    let mut hasher = Sha256::new();
    hasher.update(b"vaultisor:fido2-keys-digest:v1");
    let mut count = 0usize;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Vec<u8>>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, Option<String>>(4)?,
            r.get::<_, i64>(5)?,
            r.get::<_, Option<String>>(6)?,
        ))
    })?;
    for row in rows {
        let (id, cid, pk, wrapped, aaguid, req_pin, request_id) = row?;
        hasher.update([1u8]);
        update_digest_blob(&mut hasher, id.as_bytes());
        update_digest_blob(&mut hasher, &cid);
        update_digest_blob(&mut hasher, &pk);
        update_digest_blob(&mut hasher, &wrapped);
        update_digest_optional_blob(&mut hasher, aaguid.as_deref().map(str::as_bytes));
        hasher.update(req_pin.to_le_bytes());
        update_digest_optional_blob(&mut hasher, request_id.as_deref().map(str::as_bytes));
        count += 1;
    }
    if count == 0 {
        Ok(None)
    } else {
        Ok(Some(hasher.finalize().into()))
    }
}

fn update_digest_blob(hasher: &mut sha2::Sha256, bytes: &[u8]) {
    use sha2::Digest;
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn update_digest_optional_blob(hasher: &mut sha2::Sha256, bytes: Option<&[u8]>) {
    use sha2::Digest;
    match bytes {
        Some(value) => {
            hasher.update([1u8]);
            update_digest_blob(hasher, value);
        }
        None => hasher.update([0u8]),
    }
}

fn read_meta_for_mac(c: &Connection) -> Result<MetaForMac> {
    let fido2_keys_digest = compute_fido2_keys_digest(c)?;
    let row = c.query_row(
        r#"SELECT failed_pin_attempts, pin_next_allowed,
                  autolock_seconds, clipboard_clear_seconds,
                  require_auth_for_copy, use_windows_hello,
                  created_at, wrapped_master_key,
                  device_secret_tpm_name, device_secret_tpm_blob,
                  crypto_version, argon2_m_cost, argon2_t_cost, argon2_p_cost,
                  dpapi_entropy,
                  recovery_generation, recovery_wrapped_master, security_epoch,
                  hello_key_credential_name, hello_key_credential_public_key,
                  ui_language, enable_health_check, enable_password_history,
                  enable_generator, last_op_id, pin_last_failure,
                  recovery_state,
                  data_rebase_pending, pin_change_request_id,
                  import_records_sha256, import_web_sha256
           FROM vault_meta WHERE id = 1"#,
        [],
        |r| {
            Ok(MetaForMac {
                failed_pin_attempts: r.get::<_, i64>(0)? as u32,
                pin_next_allowed: r.get(1)?,
                pin_last_failure: r.get(25)?,
                autolock_seconds: r.get::<_, i64>(2)? as u32,
                clipboard_clear_seconds: r.get::<_, i64>(3)? as u32,
                require_auth_for_copy: r.get::<_, i64>(4)? != 0,
                use_windows_hello: r.get::<_, i64>(5)? != 0,
                created_at: r.get(6)?,
                wrapped_master: r.get(7)?,
                device_secret_tpm_name: r.get(8)?,
                device_secret_tpm_blob: r.get(9)?,
                crypto_version: r.get::<_, i64>(10)? as u32,
                argon2_m_cost: r.get::<_, i64>(11)? as u32,
                argon2_t_cost: r.get::<_, i64>(12)? as u32,
                argon2_p_cost: r.get::<_, i64>(13)? as u32,
                dpapi_entropy: r.get(14)?,
                fido2_keys_digest,
                recovery_generation: r.get::<_, i64>(15)?.max(0) as u64,
                recovery_wrapped_master: r.get(16)?,
                recovery_state: r.get(26)?,
                data_rebase_pending: r.get::<_, i64>(27)? != 0,
                pin_change_request_id: r.get(28)?,
                import_records_sha256: r.get(29)?,
                import_web_sha256: r.get(30)?,
                security_epoch: r.get::<_, i64>(17)?.max(0) as u64,
                hello_key_credential_name: r.get(18)?,
                hello_key_credential_public_key: r.get(19)?,
                ui_language: r.get(20)?,
                enable_health_check: r.get::<_, i64>(21)? != 0,
                enable_password_history: r.get::<_, i64>(22)? != 0,
                enable_generator: r.get::<_, i64>(23)? != 0,
                last_op_id: r.get(24)?,
            })
        },
    )?;
    Ok(row)
}

fn mac_inputs_from(row: &MetaForMac) -> MacInputs<'_> {
    MacInputs {
        failed_pin_attempts: row.failed_pin_attempts,
        pin_next_allowed: row.pin_next_allowed,
        pin_last_failure: row.pin_last_failure,
        autolock_seconds: row.autolock_seconds,
        clipboard_clear_seconds: row.clipboard_clear_seconds,
        require_auth_for_copy: row.require_auth_for_copy,
        use_windows_hello: row.use_windows_hello,
        created_at: &row.created_at,
        wrapped_master: &row.wrapped_master,
        device_secret_tpm_name: row.device_secret_tpm_name.as_deref(),
        device_secret_tpm_blob: row.device_secret_tpm_blob.as_deref(),
        crypto_version: row.crypto_version,
        argon2_m_cost: row.argon2_m_cost,
        argon2_t_cost: row.argon2_t_cost,
        argon2_p_cost: row.argon2_p_cost,
        dpapi_entropy: &row.dpapi_entropy,
        fido2_keys_digest: row.fido2_keys_digest.as_ref().map(|d| &d[..]),
        recovery_generation: row.recovery_generation,
        recovery_wrapped_master: row.recovery_wrapped_master.as_deref(),
        recovery_state: &row.recovery_state,
        data_rebase_pending: row.data_rebase_pending,
        pin_change_request_id: row.pin_change_request_id.as_deref(),
        import_records_sha256: row.import_records_sha256.as_deref(),
        import_web_sha256: row.import_web_sha256.as_deref(),
        security_epoch: row.security_epoch,
        hello_key_credential_name: row.hello_key_credential_name.as_deref(),
        hello_key_credential_public_key: row.hello_key_credential_public_key.as_deref(),
        ui_language: &row.ui_language,
        enable_health_check: row.enable_health_check,
        enable_password_history: row.enable_password_history,
        enable_generator: row.enable_generator,
        last_op_id: row.last_op_id.as_deref(),
    }
}

fn update_meta_mac(c: &Connection, integrity_key: &[u8; 32]) -> Result<()> {
    let row = read_meta_for_mac(c)?;
    let mac = compute_meta_mac(integrity_key, &mac_inputs_from(&row));
    c.execute(
        "UPDATE vault_meta SET meta_mac = ?1 WHERE id = 1",
        params![&mac[..]],
    )?;
    Ok(())
}

fn commit_or_rollback(c: &Connection, res: Result<()>) -> Result<()> {
    match res {
        Ok(()) => {
            if let Err(error) = crate::failpoint::hit("meta.commit") {
                let _ = c.execute_batch("ROLLBACK");
                return Err(error);
            }
            c.execute_batch("COMMIT")?;
            Ok(())
        }
        Err(e) => {
            let _ = c.execute_batch("ROLLBACK");
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTROPY: &[u8] = b"per-vault-entropy-32-bytes-long!";

    fn sealed_vault(dir: &std::path::Path, key: &[u8; 32]) -> MetaDb {
        let db = MetaDb::open(&dir.join("vault.meta.db")).unwrap();
        db.vault_create(b"wrapped", 300, 10, b"dpapi", key, ENTROPY, None)
            .unwrap();
        db
    }

    #[test]
    fn create_load_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x33u8; 32];
        let db = sealed_vault(dir.path(), &key);

        assert!(db.vault_initialized().unwrap());
        let row = db.vault_load().unwrap().unwrap();
        assert_eq!(row.autolock_seconds, 300);
        assert_eq!(row.backoff, crate::auth::backoff::BackoffState::default());
        assert_eq!(row.dpapi_entropy, ENTROPY);

        db.verify_meta_integrity(&key).unwrap();
        assert!(db.verify_meta_integrity(&[0x44u8; 32]).is_err());

        db.update_settings(&key, 60, 30).unwrap();
        db.verify_meta_integrity(&key).unwrap();
        let row = db.vault_load().unwrap().unwrap();
        assert_eq!(row.autolock_seconds, 60);
    }

    #[test]
    fn every_protected_mutation_advances_the_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x55u8; 32];
        let db = sealed_vault(dir.path(), &key);
        assert_eq!(db.vault_load().unwrap().unwrap().security_epoch, 0);

        let row = db
            .add_fido2_key(
                &key,
                "test",
                b"credential",
                b"public",
                b"wrapped",
                None,
                true,
                None,
            )
            .unwrap();
        assert_eq!(db.vault_load().unwrap().unwrap().security_epoch, 1);
        db.verify_meta_integrity(&key).unwrap();

        db.delete_fido2_key(&key, &row.id).unwrap();
        assert_eq!(db.vault_load().unwrap().unwrap().security_epoch, 2);
        db.verify_meta_integrity(&key).unwrap();
    }

    #[test]
    fn tampering_with_protected_fields_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x63u8; 32];
        let db = sealed_vault(dir.path(), &key);
        db.verify_meta_integrity(&key).unwrap();

        for statement in [
            "UPDATE vault_meta SET failed_pin_attempts = 0 WHERE id = 1",
            "UPDATE vault_meta SET pin_next_allowed = 0 WHERE id = 1",
            "UPDATE vault_meta SET pin_last_failure = 0 WHERE id = 1",
            "UPDATE vault_meta SET hello_key_credential_name = 'evil' WHERE id = 1",
            "UPDATE vault_meta SET enable_password_history = 0 WHERE id = 1",
            "UPDATE vault_meta SET ui_language = 'en' WHERE id = 1",
            "UPDATE vault_meta SET dpapi_entropy = X'00' WHERE id = 1",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let db = sealed_vault(dir.path(), &key);
            db.set_backoff(
                &key,
                crate::auth::backoff::BackoffState {
                    failures: 7,
                    next_allowed: 1_800_000_060,
                    last_failure: 1_800_000_000,
                },
            )
            .unwrap();
            db.with_conn(|c| {
                c.execute(statement, [])?;
                Ok(())
            })
            .unwrap();
            assert!(
                matches!(
                    db.verify_meta_integrity(&key),
                    Err(VaultError::MetaTampered)
                ),
                "правка не обнаружена: {statement}"
            );
        }
    }

    /// Добавление FIDO2-ключа мимо приложения обязано ломать подпись: сама
    /// таблица не подписывается, но её дайджест входит в MAC.
    #[test]
    fn injecting_a_fido_key_directly_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x66u8; 32];
        let db = sealed_vault(dir.path(), &key);
        db.with_conn(|c| {
            c.execute(
                "INSERT INTO fido2_keys (id, name, credential_id, public_key, fido2_wrapped_key, created_at, aaguid, require_pin) \
                 VALUES ('evil', 'evil', X'01', X'02', X'03', '2026-01-01T00:00:00Z', NULL, 1)",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            db.verify_meta_integrity(&key),
            Err(VaultError::MetaTampered)
        ));
    }

    fn external(dir: &std::path::Path, key: &[u8; 32]) -> std::path::PathBuf {
        crate::storage::machine_checkpoint::path(dir, &checkpoint_id(key)).unwrap()
    }

    #[test]
    fn deleted_checkpoint_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x79u8; 32];
        let db = sealed_vault(dir.path(), &key);
        db.verify_meta_integrity(&key).unwrap();
        std::fs::remove_file(external(dir.path(), &key)).unwrap();
        assert!(matches!(
            db.verify_meta_integrity(&key),
            Err(VaultError::MetaTampered)
        ));
    }

    #[test]
    fn corrupted_external_checkpoint_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x77u8; 32];
        let db = sealed_vault(dir.path(), &key);
        std::fs::write(external(dir.path(), &key), b"corrupted DPAPI state").unwrap();
        assert!(matches!(
            db.verify_meta_integrity(&key),
            Err(VaultError::MetaTampered)
        ));
    }

    /// Checkpoint привязан к integrity-ключу: у другого ключа свой файл.
    #[test]
    fn checkpoint_id_depends_on_the_key_and_hides_it() {
        let a = checkpoint_id(&[1u8; 32]);
        assert_eq!(a, checkpoint_id(&[1u8; 32]));
        assert_ne!(a, checkpoint_id(&[2u8; 32]));
        assert!(!a.contains(&hex::encode([1u8; 32])));
    }

    /// Подмена живой базы более старым, но корректно подписанным снимком
    /// обнаруживается по эпохе в checkpoint'е.
    #[test]
    fn rolling_the_database_back_to_an_older_snapshot_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.meta.db");
        let snapshot = dir.path().join("snapshot.db");
        let key = [0x71u8; 32];
        let db = sealed_vault(dir.path(), &key);

        for _ in 0..5 {
            db.update_meta_secure(&key, |_| Ok(())).unwrap();
        }
        db.backup_to(&snapshot).unwrap();
        for _ in 0..5 {
            db.update_meta_secure(&key, |_| Ok(())).unwrap();
        }
        drop(db);

        std::fs::copy(&snapshot, &path).unwrap();
        let rolled_back = MetaDb::open(&path).unwrap();
        // Подпись снимка корректна сама по себе...
        rolled_back.verify_meta_mac_only(&key).unwrap();
        // ...но checkpoint помнит более новую эпоху.
        assert!(matches!(
            rolled_back.verify_meta_integrity(&key),
            Err(VaultError::MetaTampered)
        ));
    }

    /// Сбой между commit метаданных и записью checkpoint'а: checkpoint
    /// отстаёт, это не подмена — он догоняется при проверке.
    #[test]
    fn lagging_checkpoint_catches_up() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x73u8; 32];
        let db = sealed_vault(dir.path(), &key);
        let before = std::fs::read(external(dir.path(), &key)).unwrap();
        db.update_meta_secure(&key, |_| Ok(())).unwrap();
        std::fs::write(external(dir.path(), &key), before).unwrap();
        db.verify_meta_integrity(&key).unwrap();
        assert_eq!(db.read_checkpoint(&key).unwrap().unwrap().epoch, 1);
    }

    /// Ревизии баз в checkpoint'е только растут и переживают мутации
    /// метаданных.
    #[test]
    fn data_revisions_are_monotonic_and_survive_meta_mutations() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x74u8; 32];
        let db = sealed_vault(dir.path(), &key);
        let state = |revision, byte| DataState {
            revision,
            digest: [byte; 32],
        };
        assert_eq!(
            db.data_state(&key).unwrap(),
            (DataState::default(), DataState::default())
        );
        db.advance_data_state(&key, Some(state(5, 1)), None)
            .unwrap();
        db.advance_data_state(&key, Some(state(3, 9)), Some(state(2, 2)))
            .unwrap();
        assert_eq!(db.data_state(&key).unwrap(), (state(5, 1), state(2, 2)));
        // Та же ревизия с другим файлом зафиксированное состояние не меняет.
        db.advance_data_state(&key, Some(state(5, 7)), None)
            .unwrap();
        assert_eq!(db.data_state(&key).unwrap().0, state(5, 1));
        db.update_settings(&key, 60, 30).unwrap();
        assert_eq!(db.data_state(&key).unwrap(), (state(5, 1), state(2, 2)));
        db.verify_meta_integrity(&key).unwrap();
    }

    /// Смена ключа: checkpoint нового ключа пишется до commit, старый не
    /// трогается; после commit метаданные проверяются новым ключом.
    #[test]
    fn reseed_moves_the_vault_to_a_new_checkpoint_in_one_commit() {
        let dir = tempfile::tempdir().unwrap();
        let old_key = [0x75u8; 32];
        let db = sealed_vault(dir.path(), &old_key);
        db.replace_recovery(&old_key, 1, b"envelope").unwrap();
        db.set_backoff(
            &old_key,
            crate::auth::backoff::BackoffState {
                failures: 9,
                next_allowed: 1_800_000_900,
                last_failure: 1_800_000_000,
            },
        )
        .unwrap();
        let old_checkpoint = std::fs::read(external(dir.path(), &old_key)).unwrap();

        let new_key = [0x76u8; 32];
        db.reseed(&Reseed {
            integrity_key: &new_key,
            integrity_key_dpapi: b"new-dpapi",
            dpapi_entropy: b"new-entropy",
            wrapped_master_dpapi: b"new-wrapped",
            params: crate::crypto::kdf::Argon2Params::default(),
            device_secret: Some(("tpm-new", b"ds-new")),
            op_id: "op-reseed",
            records: DataState {
                revision: 11,
                digest: [1; 32],
            },
            web: DataState {
                revision: 12,
                digest: [2; 32],
            },
        })
        .unwrap();

        db.verify_meta_integrity(&new_key).unwrap();
        assert!(db.verify_meta_mac_only(&old_key).is_err());
        let (records, web) = db.data_state(&new_key).unwrap();
        assert_eq!((records.revision, web.revision), (11, 12));
        assert_eq!(
            std::fs::read(external(dir.path(), &old_key)).unwrap(),
            old_checkpoint,
            "старый checkpoint удаляет журнал после commit, не reseed"
        );
        let meta = db.vault_load().unwrap().unwrap();
        assert_eq!(meta.recovery_state, super::super::RecoveryState::Pending);
        assert!(meta.recovery_wrapped_master.is_none());
        assert_eq!(
            meta.recovery_generation, 2,
            "израсходованное поколение отозвано"
        );
        assert_eq!(meta.backoff, crate::auth::backoff::BackoffState::default());
        assert_eq!(meta.device_secret_tpm_name.as_deref(), Some("tpm-new"));
        assert_eq!(meta.crypto_version, 2);
        assert_eq!(meta.last_op_id.as_deref(), Some("op-reseed"));
    }

    /// Импорт на том же устройстве: эпоха выше checkpoint'а, задержки PIN —
    /// строжайшие из снимка и checkpoint'а, восстановление ждёт нового
    /// комплекта частей.
    #[test]
    fn import_reseal_never_weakens_the_checkpoint_state() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x78u8; 32];
        let live = sealed_vault(dir.path(), &key);
        live.replace_recovery(&key, 1, b"envelope").unwrap();
        let snapshot = dir.path().join("snapshot.db");
        live.backup_to(&snapshot).unwrap();
        for failures in 1..=8 {
            live.set_backoff(
                &key,
                crate::auth::backoff::BackoffState {
                    failures,
                    next_allowed: 1_800_000_000 + failures as i64 * 60,
                    last_failure: 1_800_000_000,
                },
            )
            .unwrap();
        }
        let live_epoch = live.vault_load().unwrap().unwrap().security_epoch;
        drop(live);
        std::fs::remove_file(dir.path().join("vault.meta.db")).unwrap();

        let imported = MetaDb::open_staged(&snapshot, dir.path()).unwrap();
        imported
            .reseal_import(&key, "op-import", ([1; 32], [2; 32]))
            .unwrap();
        let meta = imported.vault_load().unwrap().unwrap();
        assert!(meta.security_epoch > live_epoch);
        assert_eq!(meta.backoff.failures, 8, "задержки не уменьшились");
        assert_eq!(meta.recovery_state, super::super::RecoveryState::Pending);
        imported.verify_meta_integrity(&key).unwrap();
        assert!(meta.data_rebase_pending, "ревизии баз поднимет первый вход");
        assert_eq!(meta.imported_snapshot, Some(([1; 32], [2; 32])));
    }

    #[test]
    fn tampered_import_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x7Au8; 32];
        let db = sealed_vault(dir.path(), &key);
        db.with_conn(|c| {
            c.execute(
                "UPDATE vault_meta SET failed_pin_attempts = 0, autolock_seconds = 1 WHERE id = 1",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            db.reseal_import(&key, "op", ([0; 32], [0; 32])),
            Err(VaultError::MetaTampered)
        ));
    }

    #[test]
    fn device_secret_switches_crypto_version() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x68u8; 32];
        let db = sealed_vault(dir.path(), &key);
        assert_eq!(db.vault_load().unwrap().unwrap().crypto_version, 1);

        db.save_device_secret(&key, "cng-platform-rsa-v1:x", b"blob")
            .unwrap();
        let meta = db.vault_load().unwrap().unwrap();
        assert_eq!(meta.crypto_version, 2);
        assert_eq!(
            meta.device_secret_tpm_name.as_deref(),
            Some("cng-platform-rsa-v1:x")
        );
        db.verify_meta_integrity(&key).unwrap();
    }

    #[test]
    fn recovery_generation_is_replaced_acknowledged_and_revoked_atomically() {
        use super::super::RecoveryState;
        let dir = tempfile::tempdir().unwrap();
        let key = [0x69u8; 32];
        let db = sealed_vault(dir.path(), &key);
        assert_eq!(
            db.vault_load().unwrap().unwrap().recovery_state,
            RecoveryState::Disabled
        );

        db.replace_recovery(&key, 1, b"envelope-1").unwrap();
        let meta = db.vault_load().unwrap().unwrap();
        assert_eq!(meta.recovery_generation, 1);
        assert_eq!(meta.recovery_state, RecoveryState::Pending);
        assert_eq!(
            meta.recovery_wrapped_master.as_deref(),
            Some(&b"envelope-1"[..])
        );
        db.verify_meta_integrity(&key).unwrap();

        // Подтверждается только текущее поколение.
        assert!(db.acknowledge_recovery(&key, 2).is_err());
        db.acknowledge_recovery(&key, 1).unwrap();
        assert_eq!(
            db.vault_load().unwrap().unwrap().recovery_state,
            RecoveryState::Active
        );
        // Повтор подтверждения того же поколения — успех без мутации.
        let epoch = db.vault_load().unwrap().unwrap().security_epoch;
        db.acknowledge_recovery(&key, 1).unwrap();
        assert_eq!(db.vault_load().unwrap().unwrap().security_epoch, epoch);
        assert!(db.acknowledge_recovery(&key, 2).is_err(), "чужое поколение");

        db.clear_recovery(&key).unwrap();
        let meta = db.vault_load().unwrap().unwrap();
        assert_eq!(meta.recovery_generation, 2, "поколение обязано вырасти");
        assert_eq!(meta.recovery_state, RecoveryState::Disabled);
        assert!(meta.recovery_wrapped_master.is_none());
        db.verify_meta_integrity(&key).unwrap();
    }

    /// Конверт восстановления под MAC: подмена его мимо приложения
    /// обнаруживается.
    #[test]
    fn recovery_envelope_is_authenticated() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x6Au8; 32];
        let db = sealed_vault(dir.path(), &key);
        db.replace_recovery(&key, 1, b"envelope-1").unwrap();
        db.with_conn(|c| {
            c.execute(
                "UPDATE vault_meta SET recovery_wrapped_master = x'00' WHERE id = 1",
                [],
            )?;
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            db.verify_meta_integrity(&key),
            Err(VaultError::MetaTampered)
        ));
    }

    /// Подложенный в файл триггер не дожидается первой защищённой записи:
    /// метаданные с чужим объектом схемы не открываются вовсе, а значения,
    /// которые он менял бы, остаются нетронутыми.
    #[test]
    fn planted_schema_objects_are_rejected_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let key = [0x6Bu8; 32];
        let path = dir.path().join("vault.meta.db");
        drop(sealed_vault(dir.path(), &key));
        for planted in [
            "CREATE TRIGGER t AFTER UPDATE ON vault_meta BEGIN \
             UPDATE vault_meta SET use_windows_hello = 0, failed_pin_attempts = 0; END",
            "CREATE VIEW v AS SELECT * FROM vault_meta",
            "CREATE INDEX i ON fido2_keys(name)",
            "CREATE TABLE extra (x INTEGER)",
        ] {
            let attacker = Connection::open(&path).unwrap();
            attacker.execute_batch(planted).unwrap();
            drop(attacker);
            assert!(
                matches!(MetaDb::open(&path), Err(VaultError::MetaTampered)),
                "{planted}"
            );
            let attacker = Connection::open(&path).unwrap();
            let (kind, name): (String, String) = attacker
                .query_row(
                    "SELECT type, name FROM sqlite_master WHERE name IN ('t', 'v', 'i', 'extra')",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            attacker
                .execute_batch(&format!("DROP {} {name}", kind.to_uppercase()))
                .unwrap();
        }
        // Чистая схема снова открывается, и MAC сходится.
        MetaDb::open(&path)
            .unwrap()
            .verify_meta_integrity(&key)
            .unwrap();
    }
}
