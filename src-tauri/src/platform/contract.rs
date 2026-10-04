//! Контракт ОС: одинаковая семантика для `FakePlatform` и `WindowsPlatform`.
//!
//! Сценарные тесты доверяют тестовой ОС. Это доверие обосновано, только если
//! она ведёт себя как настоящая в том, на что опирается журнал операций:
//! удаление идемпотентно, `exists` отражает создание и удаление, подпись
//! детерминирована, поиск по user.id находит ровно созданный ключ.
//!
//! Тестовая ОС проходит контракт в каждом прогоне. Настоящая — вручную на
//! машине с TPM 2.0 и Windows Hello (тесты с `#[ignore]`), как часть
//! аппаратного чек-листа релиза.

use super::Platform;

/// TPM: create → exists → sign (детерминированно) → delete → !exists →
/// повторное delete без ошибки → sign невозможен.
pub fn tpm_lifecycle(platform: &dyn Platform) {
    assert!(platform.tpm_supported(), "контракт требует TPM 2.0");
    let name = platform.tpm_new_key_name();
    assert!(!platform.tpm_exists(&name).unwrap(), "новое имя уже занято");

    let created = platform.tpm_create_device_key(&name).expect("create");
    assert_eq!(created.name, name, "ключ создан под выданным именем");
    assert!(platform.tpm_exists(&name).unwrap());
    assert!(
        platform.tpm_create_device_key(&name).is_err(),
        "повторное создание под тем же именем не перезаписывает ключ"
    );

    let again = platform.tpm_sign_device_challenge(&name).expect("sign");
    assert_eq!(*again, *created.signature, "подпись детерминирована");

    platform.tpm_delete(&name).expect("delete");
    assert!(!platform.tpm_exists(&name).unwrap());
    platform
        .tpm_delete(&name)
        .expect("повторное удаление — не ошибка");
    assert!(platform.tpm_sign_device_challenge(&name).is_err());
}

/// Hello: create(user) → exists → find(user) == [name] → delete → !exists →
/// find(user) пуст → повторное delete без ошибки.
pub fn hello_lifecycle(platform: &dyn Platform) {
    assert!(platform.hello_supported(), "контракт требует Windows Hello");
    let user: [u8; 16] = crate::crypto::rng::random_array();
    assert!(platform.hello_find(&user).unwrap().is_empty());

    let created = platform.hello_create(&user).expect("create");
    assert!(platform.hello_exists(&created.name).unwrap());
    assert_eq!(
        platform.hello_find(&user).unwrap(),
        vec![created.name.clone()]
    );
    platform
        .hello_verify(&created.name, &created.public_key)
        .expect("verify");

    platform.hello_delete(&created.name).expect("delete");
    assert!(!platform.hello_exists(&created.name).unwrap());
    assert!(platform.hello_find(&user).unwrap().is_empty());
    platform
        .hello_delete(&created.name)
        .expect("повторное удаление — не ошибка");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_platform_honours_the_tpm_contract() {
        tpm_lifecycle(&super::super::fake::FakePlatform::default());
    }

    #[test]
    fn fake_platform_honours_the_hello_contract() {
        hello_lifecycle(&super::super::fake::FakePlatform::default());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires a provisioned Windows TPM 2.0"]
    fn windows_platform_honours_the_tpm_contract() {
        tpm_lifecycle(&super::super::windows::WindowsPlatform::detached());
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires Windows Hello and an interactive session"]
    fn windows_platform_honours_the_hello_contract() {
        hello_lifecycle(&super::super::windows::WindowsPlatform::detached());
    }
}
