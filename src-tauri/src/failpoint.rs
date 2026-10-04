//! Точки отказа для проверки атомарности.
//!
//! Каждый шаг, который меняет состояние на диске или в ОС (commit SQLite,
//! запись якоря, переименование файла, создание и удаление TPM- или
//! Hello-ключа), начинается с `hit("имя")`. В релизной сборке это пустая
//! функция. В тестах план может «уронить» N-й по счёту шаг.
//!
//! Два режима отказа:
//! - `Error` — шаг возвращает ошибку, код дальше работает как при обычном сбое
//!   ввода-вывода, включая свою обработку ошибок;
//! - `Crash` — шаг и **все последующие** шаги возвращают ошибку. Так
//!   моделируется смерть процесса: никакой код отката уже ничего не запишет,
//!   на диске остаётся ровно то, что было до шага N. Тест затем «перезапускает»
//!   приложение и проверяет инвариант.
//!
//! План живёт в потоке теста. Чтобы шаги не уходили в другие потоки, блокирующая
//! работа в тестах выполняется на месте (см. [`crate::blocking`]), а тесты
//! запускаются на однопоточном рантайме. Поэтому параллельные тесты друг другу
//! счёт не портят.

use crate::error::Result;

#[cfg(test)]
pub use imp::{arm, disarm, steps, trace, Mode};

/// Отметить начало шага, меняющего постоянное состояние.
#[cfg(test)]
pub fn hit(point: &'static str) -> Result<()> {
    imp::hit(point)
}

/// В рабочей сборке точек отказа нет.
#[cfg(not(test))]
#[inline(always)]
pub fn hit(_point: &'static str) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod imp {
    use crate::error::{Result, VaultError};
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Mode {
        Error,
        Crash,
    }

    #[derive(Default)]
    struct Plan {
        armed: Option<(usize, Mode)>,
        count: usize,
        crashed: bool,
        trace: Vec<&'static str>,
    }

    thread_local! {
        static PLAN: RefCell<Plan> = RefCell::new(Plan::default());
    }

    /// Уронить шаг номер `step` (с единицы) в режиме `mode`.
    pub fn arm(step: usize, mode: Mode) {
        PLAN.with(|plan| {
            *plan.borrow_mut() = Plan {
                armed: Some((step, mode)),
                ..Plan::default()
            }
        });
    }

    /// Снять план и сбросить счётчик. Трасса начинается заново.
    pub fn disarm() {
        PLAN.with(|plan| *plan.borrow_mut() = Plan::default());
    }

    /// Сколько шагов пройдено с последнего `arm`/`disarm`.
    pub fn steps() -> usize {
        PLAN.with(|plan| plan.borrow().count)
    }

    /// Имена пройденных шагов по порядку — для сообщений об ошибках тестов.
    pub fn trace() -> Vec<&'static str> {
        PLAN.with(|plan| plan.borrow().trace.clone())
    }

    pub fn hit(point: &'static str) -> Result<()> {
        PLAN.with(|plan| {
            let mut plan = plan.borrow_mut();
            if plan.crashed {
                return Err(VaultError::Injected(point));
            }
            plan.count += 1;
            plan.trace.push(point);
            if let Some((step, mode)) = plan.armed {
                if plan.count == step {
                    if mode == Mode::Crash {
                        plan.crashed = true;
                    }
                    return Err(VaultError::Injected(point));
                }
            }
            Ok(())
        })
    }
}
