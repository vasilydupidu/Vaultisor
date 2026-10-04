//! Задержки после неверного PIN вместо безвозвратной блокировки.
//!
//! График (после N-й подряд ошибки следующая попытка разрешена через):
//!
//! | ошибок | задержка |
//! |---|---|
//! | 1–5 | нет |
//! | 6 | 30 с |
//! | 7 | 1 мин |
//! | 8 | 5 мин |
//! | 9 | 15 мин |
//! | 10 и больше | 1 час |
//!
//! Постоянной блокировки нет: при выключенном восстановлении она превращала
//! чужие неверные попытки в необратимую потерю данных. Последовательный
//! перебор 11-значного PIN при часовой задержке после десятой ошибки занимает
//! миллионы лет.
//!
//! Состояние (`failures`, `next_allowed`, `last_failure`) хранится под MAC
//! метаданных и дублируется во внешнем checkpoint. Время — UTC в секундах.
//! Если часы ушли назад относительно последней ошибки, это трактуется в
//! безопасную сторону: назначается максимальная задержка от текущего
//! момента. Перевод часов вперёд задержку обходит — для этого нужны права
//! менять системное время, а такой противник и так перебирает PIN офлайн.

/// Максимальная задержка — она же при обнаружении отката часов.
pub const MAX_DELAY_SECS: i64 = 60 * 60;

/// Задержка после `failures` ошибок подряд.
pub fn delay_after(failures: u32) -> i64 {
    match failures {
        0..=5 => 0,
        6 => 30,
        7 => 60,
        8 => 5 * 60,
        9 => 15 * 60,
        _ => MAX_DELAY_SECS,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BackoffState {
    pub failures: u32,
    /// Раньше этого момента попытка PIN не принимается.
    pub next_allowed: i64,
    /// Момент последней ошибки — для обнаружения отката часов.
    pub last_failure: i64,
}

/// Можно ли сейчас проверять PIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Open,
    /// Подождать столько секунд.
    Wait(i64),
    /// Часы ушли назад: состояние нужно заменить на это и отказать.
    ClockRewound(BackoffState),
}

impl BackoffState {
    pub fn gate(&self, now: i64) -> Gate {
        if self.failures == 0 {
            return Gate::Open;
        }
        if now < self.last_failure {
            return Gate::ClockRewound(BackoffState {
                failures: self.failures,
                next_allowed: now + MAX_DELAY_SECS,
                last_failure: now,
            });
        }
        if now < self.next_allowed {
            Gate::Wait(self.next_allowed - now)
        } else {
            Gate::Open
        }
    }

    /// Состояние после очередной ошибки.
    pub fn after_failure(&self, now: i64) -> BackoffState {
        let failures = self.failures.saturating_add(1);
        BackoffState {
            failures,
            next_allowed: now + delay_after(failures),
            last_failure: now,
        }
    }

    /// Более строгое из двух: больше ошибок и более поздний допуск. Нужна при
    /// сведении метаданных с внешним checkpoint — откат файлов не должен
    /// уменьшать ни счётчик, ни задержку.
    pub fn strictest(self, other: BackoffState) -> BackoffState {
        BackoffState {
            failures: self.failures.max(other.failures),
            next_allowed: self.next_allowed.max(other.next_allowed),
            last_failure: self.last_failure.max(other.last_failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_800_000_000;

    #[test]
    fn schedule_matches_the_accepted_policy() {
        let expected = [
            (1, 0),
            (5, 0),
            (6, 30),
            (7, 60),
            (8, 300),
            (9, 900),
            (10, 3600),
            (1000, 3600),
        ];
        for (failures, delay) in expected {
            assert_eq!(delay_after(failures), delay, "после {failures} ошибок");
        }
    }

    #[test]
    fn delay_blocks_until_it_expires_and_never_becomes_permanent() {
        let mut state = BackoffState::default();
        for i in 0..6 {
            assert_eq!(state.gate(T0), Gate::Open, "попытка {} без задержки", i + 1);
            state = state.after_failure(T0);
        }
        assert_eq!(state.gate(T0), Gate::Wait(30));
        assert_eq!(state.gate(T0 + 29), Gate::Wait(1));
        assert_eq!(state.gate(T0 + 30), Gate::Open);

        for _ in 0..100 {
            state = state.after_failure(state.next_allowed);
        }
        assert_eq!(state.gate(state.next_allowed - 1), Gate::Wait(1));
        assert_eq!(
            state.gate(state.next_allowed),
            Gate::Open,
            "после часа — снова можно"
        );
    }

    #[test]
    fn rewound_clock_imposes_the_maximum_delay_from_now() {
        let state = BackoffState::default().after_failure(T0);
        match state.gate(T0 - 10_000) {
            Gate::ClockRewound(next) => {
                assert_eq!(next.failures, 1);
                assert_eq!(next.next_allowed, T0 - 10_000 + MAX_DELAY_SECS);
                assert_eq!(next.gate(T0 - 10_000), Gate::Wait(MAX_DELAY_SECS));
                assert_eq!(next.gate(next.next_allowed), Gate::Open);
            }
            other => panic!("ожидался откат часов, получено {other:?}"),
        }
    }

    #[test]
    fn strictest_never_loosens() {
        let a = BackoffState {
            failures: 7,
            next_allowed: T0 + 60,
            last_failure: T0,
        };
        let b = BackoffState {
            failures: 2,
            next_allowed: T0 + 900,
            last_failure: T0 + 5,
        };
        let merged = a.strictest(b);
        assert_eq!(merged.failures, 7);
        assert_eq!(merged.next_allowed, T0 + 900);
        assert_eq!(merged, b.strictest(a));
    }
}
