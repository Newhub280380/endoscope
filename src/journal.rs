//! Журнал правды: JSONL, одна строка — один факт.
//! Формат события общий для Linux и Windows — экран и детектор лжи
//! читают один и тот же файл.

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub ts: u64,
    pub kind: String,
    pub pid: u32,
    pub agent: String,
    pub detail: String,
}

impl Event {
    pub fn now(kind: &str, pid: u32, agent: &str, detail: String) -> Self {
        Self { ts: now_ms(), kind: kind.into(), pid, agent: agent.into(), detail }
    }
}

pub struct Journal {
    pub file: std::fs::File,
    pub count: u64,
}

impl Journal {
    pub fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file, count: 0 })
    }

    pub fn write_event(&mut self, ev: &Event) -> std::io::Result<()> {
        let line = serde_json::to_string(ev).expect("serialize event");
        writeln!(self.file, "{}", line)?;
        self.count += 1;
        Ok(())
    }
}
