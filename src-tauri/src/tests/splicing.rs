//! Adversarial: подмена отдельных страниц SQLCipher старыми версиями.
//!
//! SQLCipher аутентифицирует каждую страницу отдельно (HMAC с номером
//! страницы), но не базу целиком: старая версия страницы N того же файла
//! проходит проверку на месте страницы N. Если при этом страница с
//! `db_state.revision` остаётся текущей, проверка ревизии откат не видит.

use super::harness::{Env, CANARY, PIN};
use crate::storage::records::{FieldInput, FieldType, RecordInput};

const PAGE: usize = 4096;
/// Той же длины, что и `CANARY`: структура B-дерева не меняется, меняются
/// только байты значения — худший для защиты случай.
const CHANGED: &str = "sk-live-CHANGED-7f3";

fn set_canary(env: &Env, value: &str) {
    let (record_id, field_id, _, _) = env.canary().expect("canary");
    env.with_session(|master, records, _| {
        crate::storage::records::update_record(
            records,
            master,
            &record_id,
            &RecordInput {
                name: "canary".into(),
                project: None,
                icon: None,
                color: None,
                category: Some("work".into()),
                fields: vec![FieldInput {
                    id: Some(field_id.clone()),
                    field_type: FieldType::Secret,
                    label: "token".into(),
                    is_secret: true,
                    sort_order: 0,
                    value: Some(value.into()),
                }],
            },
            false,
        )
    })
    .unwrap()
    .unwrap();
}

#[tokio::test]
async fn spliced_old_pages_do_not_bring_back_old_data() {
    assert_eq!(CHANGED.len(), CANARY.len());
    let mut env = Env::new();
    env.create().await;
    env.add_canary();
    env.state.lock();
    let old = std::fs::read(env.state.records_path()).unwrap();

    env.unlock(PIN).await.unwrap();
    set_canary(&env, CHANGED);
    env.state.lock();
    let new = std::fs::read(env.state.records_path()).unwrap();
    assert_eq!(old.len(), new.len(), "структура файла не изменилась");

    let mut differing = Vec::new();
    for page in 1..new.len() / PAGE {
        let range = page * PAGE..(page + 1) * PAGE;
        if old[range.clone()] != new[range] {
            differing.push(page);
        }
    }
    assert!(
        differing.len() >= 2,
        "изменились страница данных и страница ревизии"
    );

    let mut accepted = Vec::new();
    for &page in &differing {
        let mut spliced = new.clone();
        spliced[page * PAGE..(page + 1) * PAGE]
            .copy_from_slice(&old[page * PAGE..(page + 1) * PAGE]);
        std::fs::write(env.state.records_path(), &spliced).unwrap();
        env.restart();
        let outcome = match env.unlock(PIN).await {
            Err(error) => format!("вход отклонён: {error}"),
            Ok(()) => {
                let value = env.read_canary();
                if value.as_deref() == Some(CANARY) {
                    accepted.push(page);
                }
                format!("вход принят, значение {value:?}")
            }
        };
        eprintln!("страница {} ← старая: {outcome}", page + 1);
        env.state.lock();
        std::fs::write(env.state.records_path(), &new).unwrap();
    }
    assert!(
        accepted.is_empty(),
        "подмена страниц {:?} вернула старое значение незамеченной",
        accepted.iter().map(|p| p + 1).collect::<Vec<_>>()
    );
}
