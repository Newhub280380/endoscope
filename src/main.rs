//! Эндоскоп — рентген-камера для ИИ-агентов. Продукт №1 рембазы.
//! Отдельно от pc-agent. Строка 1: фундамент — журнал правды (JSONL).

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    ts: u64,
    kind: String,
    pid: u32,
    agent: String,
    detail: String,
}

impl Event {
    fn now(kind: &str, pid: u32, agent: &str, detail: String) -> Self {
        Self {
            ts: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
            kind: kind.into(),
            pid,
            agent: agent.into(),
            detail,
        }
    }
}

struct Journal {
    file: std::fs::File,
    count: u64,
}

impl Journal {
    fn open(path: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self { file, count: 0 })
    }

    fn write_event(&mut self, ev: &Event) -> std::io::Result<()> {
        let line = serde_json::to_string(ev).expect("serialize event");
        writeln!(self.file, "{}", line)?;
        self.count += 1;
        Ok(())
    }
}

fn main() -> std::io::Result<()> {
    let journal_path = std::env::var("ENDOSCOPE_JOURNAL")
        .unwrap_or_else(|_| "endoscope.jsonl".into());
    let mut journal = Journal::open(&journal_path)?;

    // Пульс: heartbeat каждые 5 секунд — доказательство, что камера жива.
    let pid = std::process::id();
    println!("Эндоскоп запущен. pid={}, журнал={}", pid, journal_path);
    loop {
        let ev = Event::now("heartbeat", pid, "endoscope", "alive".into());
        journal.write_event(&ev)?;
        println!("[{}] heartbeat -> {}", ev.ts, journal.count);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
