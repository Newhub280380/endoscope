//! Какой глаз сейчас пишет журнал: ETW или опрос.
//!
//! Экран читает это из /health, каждое событие пишет то же значение в `source`.

use std::sync::atomic::{AtomicU8, Ordering};

const POLL: u8 = 0;
const ETW: u8 = 1;

static MODE: AtomicU8 = AtomicU8::new(POLL);

pub fn set_poll() {
    MODE.store(POLL, Ordering::Relaxed);
}

#[cfg_attr(not(windows), allow(dead_code))]
pub fn set_etw() {
    MODE.store(ETW, Ordering::Relaxed);
}

pub fn name() -> &'static str {
    if MODE.load(Ordering::Relaxed) == ETW {
        "etw"
    } else {
        "poll"
    }
}
