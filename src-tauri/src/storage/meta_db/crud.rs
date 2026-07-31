use rusqlite::{params, Connection, OptionalExtension};
use crate::error::{Result, VaultError};
#[allow(deprecated)] // Legacy MAC functions used intentionally for migration verification
use crate::storage::integrity::{
    compute_meta_mac_v4, verify_meta_mac_v1, verify_meta_mac_v2, verify_meta_mac_v4, MacInputs,
};

use super::MetaDb;
use super::schema::VaultMetaRow;

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

    #[allow(clippy::too_many_arguments)]
    pub fn vault_create(
        &self,
        wrapped_master_dpapi: &[u8],
        pin_phc: &str,
        autolock: u32,
        clipboard_clear: u32,
        require_auth_for_copy: bool,
        use_windows_hello: bool,
        max_pin_attempts: u32,
        integrity_key_dpapi: &[u8],
        integrity_key: &[u8; 32],
    ) -> Result<()> {
        self.with_conn(|c| {
            c.execute_batch("BEGIN IMMEDIATE")?;
            let res: Result<()> = (|| {
                let now = chrono::Utc::now().to_rfc3339();
                c.execute(
                    r#"INSERT INTO vault_meta
                        (id, version, created_at, wrapped_master_key, pin_hash,
                         autolock_seconds, clipboard_clear_seconds,
                         require_auth_for_copy, use_windows_hello, max_pin_attempts,
                         integrity_key_dpapi, failed_pin_attempts)
                       VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)"#,
                    params![
                        now,
                        wrapped_master_dpapi,
                        pin_phc,
                        autolock as i64,
                        clipboard_clear as i64,
                        require_auth_for_copy as i64,
                        use_windows_hello as i64,
                        max_pin_attempts as i64,
                        integrity_key_dpapi,
                    ],
                )?;
                update_meta_mac(c, integrity_key)?;
                Ok(())
            })();
            commit_or_rollback(c, res)
        })
    }

    pub fn vault_load(&self) -> Result<Option<VaultMetaRow>> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    r#"SELECT version, created_at, wrapped_master_key, pin_hash,
                              autolock_seconds, clipboard_clear_seconds,
                              require_auth_for_copy, use_windows_hello,
                              hello_wrapped_key, max_pin_attempts,
                              failed_pin_attempts,
                              tpm_credential_name, tpm_wrapped_key,
                              crypto_version,
                              device_secret_tpm_name, device_secret_tpm_blob,
                              pq_encapsulation_key, pq_ciphertext, pq_dk_encrypted,
                              argon2_m_cost, argon2_t_cost, argon2_p_cost
                       FROM vault_meta WHERE id = 1"#,
                    [],
                    |row| {
                        Ok(VaultMetaRow {
                            version: row.get(0)?,
                            created_at: row.get(1)?,
                            wrapped_master_dpapi: row.get(2)?,
                            pin_hash: row.get(3)?,
                            autolock_seconds: row.get::<_, i64>(4)? as u32,
                            clipboard_clear_seconds: row.get::<_, i64>(5)? as u32,
                            require_auth_for_copy: row.get::<_, i64>(6)? != 0,
                            use_windows_hello: row.get::<_, i64>(7)? != 0,
                            hello_wrapped_key: row.get(8)?,
                            max_pin_attempts: row.get::<_, i64>(9)? as u32,
                            failed_pin_attempts: row.get::<_, i64>(10)? as u32,
                            tpm_credential_name: row.get(11)?,
                            tpm_wrapped_key: row.get(12)?,
                            crypto_version: row.get::<_, i64>(13)? as u32,
                            device_secret_tpm_name: row.get(14)?,
                            device_secret_tpm_blob: row.get(15)?,
                            pq_encapsulation_key: row.get(16)?,
                            pq_ciphertext: row.get(17)?,
                            pq_dk_encrypted: row.get(18)?,
                            argon2_m_cost: row.get::<_, i64>(19)? as u32,
                            argon2_t_cost: row.get::<_, i64>(20)? as u32,
                            argon2_p_cost: row.get::<_, i64>(21)? as u32,
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

    pub fn set_integrity_key_and_seal(
        &self,
        integrity_key_dpapi: &[u8],
        integrity_key: &[u8; 32],
    ) -> Result<()> {
        self.with_conn(|c| {
            c.execute_batch("BEGIN IMMEDIATE")?;
            let res: Result<()> = (|| {
                c.execute(
                    "UPDATE vault_meta SET integrity_key_dpapi = ?1 WHERE id = 1",
                    params![integrity_key_dpapi],
                )?;
                update_meta_mac(c, integrity_key)?;
                Ok(())
            })();
            commit_or_rollback(c, res)
        })
    }

    pub fn verify_meta_integrity(&self, integrity_key: &[u8; 32]) -> Result<()> {
        self.with_conn(|c| {
            let row = read_meta_for_mac(c)?;
            let stored_mac: Option<Vec<u8>> = c
                .query_row("SELECT meta_mac FROM vault_meta WHERE id = 1", [], |r| {
                    r.get(0)
                })
                .optional()?
                .flatten();
            let stored_mac = stored_mac.ok_or(VaultError::MetaTampered)?;
            let inputs = mac_inputs_from(&row);

            // Канонический формат — v4 (включает pq-поля).
            if verify_meta_mac_v4(integrity_key, &inputs, &stored_mac) {
                return Ok(());
            }

            // Fallback на старые форматы для бесшовной миграции без lockout
            // существующих vault'ов. Старые форматы не покрывают pq-поля.
            #[allow(deprecated)]
            let accepted_legacy = verify_meta_mac_v2(integrity_key, &inputs, &stored_mac)        // v2
                || verify_meta_mac_v1(integrity_key, &inputs, &stored_mac);                      // v1
            if !accepted_legacy {
                return Err(VaultError::MetaTampered);
            }
            // Принят старый формат → пере-запечатываем в v4.
            update_meta_mac(c, integrity_key)?;
            Ok(())
        })
    }

    pub fn update_meta_secure<F>(&self, integrity_key: &[u8; 32], f: F) -> Result<()>
    where
        F: FnOnce(&Connection) -> Result<()>,
    {
        self.with_conn(|c| {
            c.execute_batch("BEGIN IMMEDIATE")?;
            let res: Result<()> = (|| {
                f(c)?;
                update_meta_mac(c, integrity_key)?;
                Ok(())
            })();
            commit_or_rollback(c, res)
        })
    }

    pub fn update_wrapped_master(
        &self,
        integrity_key: &[u8; 32],
        wrapped_dpapi: &[u8],
        pin_phc: &str,
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET wrapped_master_key = ?1, pin_hash = ?2 WHERE id = 1",
                params![wrapped_dpapi, pin_phc],
            )?;
            Ok(())
        })
    }

    pub fn update_settings(
        &self,
        integrity_key: &[u8; 32],
        autolock: u32,
        clipboard_clear: u32,
        require_auth_for_copy: bool,
        use_windows_hello: bool,
        max_pin_attempts: u32,
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                r#"UPDATE vault_meta
                   SET autolock_seconds = ?1,
                       clipboard_clear_seconds = ?2,
                       require_auth_for_copy = ?3,
                       use_windows_hello = ?4,
                       max_pin_attempts = ?5
                   WHERE id = 1"#,
                params![
                    autolock as i64,
                    clipboard_clear as i64,
                    require_auth_for_copy as i64,
                    use_windows_hello as i64,
                    max_pin_attempts as i64,
                ],
            )?;
            Ok(())
        })
    }

    pub fn save_recovery_local(&self, x: u8, y_dpapi: &[u8]) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                r#"INSERT INTO recovery_local (id, share_x, share_y_dpapi) VALUES (1, ?1, ?2)
                   ON CONFLICT(id) DO UPDATE SET share_x = excluded.share_x,
                                                  share_y_dpapi = excluded.share_y_dpapi"#,
                params![x as i64, y_dpapi],
            )?;
            Ok(())
        })
    }

    pub fn load_recovery_local(&self) -> Result<Option<(u8, Vec<u8>)>> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT share_x, share_y_dpapi FROM recovery_local WHERE id = 1",
                    [],
                    |row| {
                        let x: i64 = row.get(0)?;
                        let y: Vec<u8> = row.get(1)?;
                        Ok((x as u8, y))
                    },
                )
                .optional()?;
            Ok(row)
        })
    }

    pub fn get_failed_attempts(&self) -> Result<u32> {
        self.with_conn(|c| {
            let n: i64 = c
                .query_row(
                    "SELECT failed_pin_attempts FROM vault_meta WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            Ok(n as u32)
        })
    }

    pub fn set_failed_attempts(&self, integrity_key: &[u8; 32], n: u32) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET failed_pin_attempts = ?1 WHERE id = 1",
                params![n as i64],
            )?;
            Ok(())
        })
    }

    pub fn save_hello_wrapped(&self, integrity_key: &[u8; 32], blob: &[u8]) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET hello_wrapped_key = ?1 WHERE id = 1",
                params![blob],
            )?;
            Ok(())
        })
    }

    pub fn clear_hello_wrapped(&self, integrity_key: &[u8; 32]) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET hello_wrapped_key = NULL WHERE id = 1",
                [],
            )?;
            Ok(())
        })
    }

    pub fn save_tpm_wrap(
        &self,
        integrity_key: &[u8; 32],
        cred_name: &str,
        tpm_blob: &[u8],
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET tpm_credential_name = ?1, tpm_wrapped_key = ?2 WHERE id = 1",
                params![cred_name, tpm_blob],
            )?;
            Ok(())
        })
    }

    pub fn clear_tpm_wrap(&self, integrity_key: &[u8; 32]) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                "UPDATE vault_meta SET tpm_credential_name = NULL, tpm_wrapped_key = NULL WHERE id = 1",
                [],
            )?;
            Ok(())
        })
    }

    // --- v0.2: Device Secret (TPM-only) ---

    /// Сохранить данные Device Secret: имя TPM-ключа и зашифрованный blob.
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

    /// Перевести хранилище в режим мастер-пароля (crypto_version = 1) и очистить
    /// Device Secret / PQ-Hello поля. Используется при восстановлении бэкапа
    /// с TPM-2.0-машины на машине без TPM 2.0: master уже собран из Shamir, но
    /// новый Device Secret создать нечем → перезапечатываем под мастер-пароль (v1).
    pub fn set_passphrase_v1(&self, integrity_key: &[u8; 32]) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                r#"UPDATE vault_meta
                   SET crypto_version = 1,
                       device_secret_tpm_name = NULL,
                       device_secret_tpm_blob = NULL,
                       pq_encapsulation_key = NULL,
                       pq_ciphertext = NULL,
                       pq_dk_encrypted = NULL
                   WHERE id = 1"#,
                [],
            )?;
            Ok(())
        })
    }

    /// Загрузить данные Device Secret.
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

    // AUDIT L9: clear_device_secret удалён — мёртвый метод-footgun. Он обнулял
    // device_secret, но НЕ сбрасывал crypto_version=1, из-за чего следующий
    // unlock уходил в v2-путь и падал ("Device Secret missing"). Вызовов не было.

    // --- v0.2: ML-KEM Post-Quantum Hello ---

    /// Сохранить ML-KEM данные для гибридного Hello-пути.
    pub fn save_pq_hello(
        &self,
        integrity_key: &[u8; 32],
        ek: &[u8],
        ct: &[u8],
        dk_encrypted: &[u8],
    ) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                r#"UPDATE vault_meta
                   SET pq_encapsulation_key = ?1,
                       pq_ciphertext = ?2,
                       pq_dk_encrypted = ?3
                   WHERE id = 1"#,
                params![ek, ct, dk_encrypted],
            )?;
            Ok(())
        })
    }

    /// Загрузить ML-KEM данные.
    pub fn get_pq_hello(&self) -> Result<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT pq_encapsulation_key, pq_ciphertext, pq_dk_encrypted FROM vault_meta WHERE id = 1",
                    [],
                    |r| {
                        let ek: Option<Vec<u8>> = r.get(0)?;
                        let ct: Option<Vec<u8>> = r.get(1)?;
                        let dk: Option<Vec<u8>> = r.get(2)?;
                        Ok((ek, ct, dk))
                    },
                )
                .optional()?;
            match row {
                Some((Some(ek), Some(ct), Some(dk))) => Ok(Some((ek, ct, dk))),
                _ => Ok(None),
            }
        })
    }

    /// Очистить ML-KEM данные.
    pub fn clear_pq_hello(&self, integrity_key: &[u8; 32]) -> Result<()> {
        self.update_meta_secure(integrity_key, |c| {
            c.execute(
                r#"UPDATE vault_meta
                   SET pq_encapsulation_key = NULL,
                       pq_ciphertext = NULL,
                       pq_dk_encrypted = NULL
                   WHERE id = 1"#,
                [],
            )?;
            Ok(())
        })
    }

    /// Сохранить параметры Argon2id в БД.
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
                .query_row(
                    "SELECT ui_language FROM vault_meta WHERE id = 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap_or_else(|_| "ru".to_string());
            Ok(lang)
        })
    }

    pub fn set_ui_language(&self, lang: &str) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                "UPDATE vault_meta SET ui_language = ?1 WHERE id = 1",
                params![lang],
            )?;
            Ok(())
        })
    }
}

struct MetaForMac {
    failed_pin_attempts: u32,
    max_pin_attempts: u32,
    pin_hash: String,
    autolock_seconds: u32,
    clipboard_clear_seconds: u32,
    require_auth_for_copy: bool,
    use_windows_hello: bool,
    created_at: String,
    wrapped_master: Vec<u8>,
    hello_wrapped_key: Option<Vec<u8>>,
    tpm_credential_name: Option<String>,
    tpm_wrapped_key: Option<Vec<u8>>,
    // v0.2: дополнительные поля включаются в MAC
    device_secret_tpm_name: Option<String>,
    device_secret_tpm_blob: Option<Vec<u8>>,
    // v0.5: ML-KEM поля включаются в MAC
    pq_encapsulation_key: Option<Vec<u8>>,
    pq_ciphertext: Option<Vec<u8>>,
    pq_dk_encrypted: Option<Vec<u8>>,
    // v0.6 (AUDIT L8)
    crypto_version: u32,
    argon2_m_cost: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
}

fn read_meta_for_mac(c: &Connection) -> Result<MetaForMac> {
    let row = c.query_row(
        r#"SELECT failed_pin_attempts, max_pin_attempts, pin_hash,
                  autolock_seconds, clipboard_clear_seconds,
                  require_auth_for_copy, use_windows_hello,
                  created_at, wrapped_master_key, hello_wrapped_key,
                  tpm_credential_name, tpm_wrapped_key,
                  device_secret_tpm_name, device_secret_tpm_blob,
                  pq_encapsulation_key, pq_ciphertext, pq_dk_encrypted,
                  crypto_version, argon2_m_cost, argon2_t_cost, argon2_p_cost
           FROM vault_meta WHERE id = 1"#,
        [],
        |r| {
            Ok(MetaForMac {
                failed_pin_attempts: r.get::<_, i64>(0)? as u32,
                max_pin_attempts: r.get::<_, i64>(1)? as u32,
                pin_hash: r.get(2)?,
                autolock_seconds: r.get::<_, i64>(3)? as u32,
                clipboard_clear_seconds: r.get::<_, i64>(4)? as u32,
                require_auth_for_copy: r.get::<_, i64>(5)? != 0,
                use_windows_hello: r.get::<_, i64>(6)? != 0,
                created_at: r.get(7)?,
                wrapped_master: r.get(8)?,
                hello_wrapped_key: r.get(9)?,
                tpm_credential_name: r.get(10)?,
                tpm_wrapped_key: r.get(11)?,
                device_secret_tpm_name: r.get(12)?,
                device_secret_tpm_blob: r.get(13)?,
                pq_encapsulation_key: r.get(14)?,
                pq_ciphertext: r.get(15)?,
                pq_dk_encrypted: r.get(16)?,
                crypto_version: r.get::<_, i64>(17)? as u32,
                argon2_m_cost: r.get::<_, i64>(18)? as u32,
                argon2_t_cost: r.get::<_, i64>(19)? as u32,
                argon2_p_cost: r.get::<_, i64>(20)? as u32,
            })
        },
    )?;
    Ok(row)
}

fn mac_inputs_from<'a>(row: &'a MetaForMac) -> MacInputs<'a> {
    MacInputs {
        failed_pin_attempts: row.failed_pin_attempts,
        max_pin_attempts: row.max_pin_attempts,
        pin_hash: &row.pin_hash,
        autolock_seconds: row.autolock_seconds,
        clipboard_clear_seconds: row.clipboard_clear_seconds,
        require_auth_for_copy: row.require_auth_for_copy,
        use_windows_hello: row.use_windows_hello,
        created_at: &row.created_at,
        wrapped_master: &row.wrapped_master,
        hello_wrapped_key: row.hello_wrapped_key.as_deref(),
        tpm_credential_name: row.tpm_credential_name.as_deref(),
        tpm_wrapped_key: row.tpm_wrapped_key.as_deref(),
        device_secret_tpm_name: row.device_secret_tpm_name.as_deref(),
        device_secret_tpm_blob: row.device_secret_tpm_blob.as_deref(),
        pq_encapsulation_key: row.pq_encapsulation_key.as_deref(),
        pq_ciphertext: row.pq_ciphertext.as_deref(),
        pq_dk_encrypted: row.pq_dk_encrypted.as_deref(),
        crypto_version: row.crypto_version,
        argon2_m_cost: row.argon2_m_cost,
        argon2_t_cost: row.argon2_t_cost,
        argon2_p_cost: row.argon2_p_cost,
    }
}

fn update_meta_mac(c: &Connection, integrity_key: &[u8; 32]) -> Result<()> {
    let row = read_meta_for_mac(c)?;
    let inputs = mac_inputs_from(&row);
    // v0.5: канонический формат — v4 (включает pq-поля).
    let mac = compute_meta_mac_v4(integrity_key, &inputs);
    c.execute(
        "UPDATE vault_meta SET meta_mac = ?1 WHERE id = 1",
        params![&mac[..]],
    )?;
    Ok(())
}

fn commit_or_rollback(c: &Connection, res: Result<()>) -> Result<()> {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // AUDIT (test-coverage): create → load → verify_meta_integrity roundtrip
    // без TPM/DPAPI (verify_meta_integrity работает по raw integrity_key).
    // Страхует позиционные индексы колонок и MAC после удаления
    // sync_projects_to_mobile (перенумерация pq-полей в read_meta_for_mac).
    #[test]
    fn meta_create_load_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let db = MetaDb::open(&dir.path().join("t.meta.db")).unwrap();
        let integrity_key = [0x33u8; 32];
        let dpapi_blob = b"dummy-dpapi-blob-not-used-in-mac";

        db.vault_create(
            b"wrapped-master-blob",
            "$argon2id$v=19$test",
            300,
            10,
            false,
            false,
            10,
            dpapi_blob,
            &integrity_key,
        )
        .unwrap();

        assert!(db.vault_initialized().unwrap());
        let row = db.vault_load().unwrap().unwrap();
        assert_eq!(row.autolock_seconds, 300);
        assert_eq!(row.max_pin_attempts, 10);

        // MAC-целостность сходится сразу после создания.
        db.verify_meta_integrity(&integrity_key).unwrap();

        // Неверный integrity_key — MAC не сходится (tamper).
        assert!(db.verify_meta_integrity(&[0x44u8; 32]).is_err());

        // update_settings пере-считывает MAC → по-прежнему валиден.
        db.update_settings(&integrity_key, 60, 30, true, false, 5).unwrap();
        db.verify_meta_integrity(&integrity_key).unwrap();
        let row2 = db.vault_load().unwrap().unwrap();
        assert_eq!(row2.autolock_seconds, 60);
        assert_eq!(row2.max_pin_attempts, 5);
    }
}
