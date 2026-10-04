//! Идентификаторы запросов для идемпотентных повторов.
//!
//! Ответ на команду может потеряться уже после commit (сбой процесса, обрыв
//! IPC). Пользователь повторяет действие — и неидемпотентная по природе
//! операция (новая запись, привязка ключа, резервная копия, смена PIN)
//! выполнилась бы дважды. Фронтенд создаёт идентификатор один раз на
//! намерение пользователя и передаёт его во всех повторах; backend хранит его
//! вместе с результатом той же транзакцией и на повтор возвращает уже
//! сделанное.

use crate::error::{Result, VaultError};

/// Проверить идентификатор запроса: UUID в каноническом виде. Он попадает в
/// базы и в имя файла копии, поэтому произвольная строка не принимается.
pub(crate) fn parse(id: &str) -> Result<String> {
    uuid::Uuid::parse_str(id)
        .map(|uuid| uuid.hyphenated().to_string())
        .map_err(|_| VaultError::BadInput("Некорректный идентификатор запроса".into()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_uuids_are_accepted() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(super::parse(&id).unwrap(), id);
        assert_eq!(super::parse(&id.to_uppercase()).unwrap(), id);
        for bad in ["", "../x", "1; DROP TABLE records", "not-a-uuid"] {
            assert!(super::parse(bad).is_err(), "{bad}");
        }
    }
}
