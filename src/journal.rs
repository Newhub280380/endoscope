//! Журнал правды: JSONL, одна строка — один факт.
//! Формат события общий для Linux и Windows — экран и детектор лжи
//! читают один и тот же файл.
//!
//! Поля `ts`, `kind`, `pid`, `agent`, `detail` остаются. К ним добавлены
//! `image`, `ppid`, `cmdline`, `class`, `source` — XRAY может их не читать.

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub ts: u64,
    pub kind: String,
    pub pid: u32,
    pub agent: String,
    pub detail: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub ppid: u32,
    #[serde(default)]
    pub cmdline: String,
    /// Прежний класс: process / tool / ai-agent / unknown.
    #[serde(default)]
    pub class: String,
    /// `etw` или `poll` — какой глаз записал строку.
    #[serde(default)]
    pub source: String,
}

impl Event {
    pub fn now(kind: &str, pid: u32, agent: &str, detail: String) -> Self {
        Self::full(kind, pid, agent, detail, "", 0, "", agent)
    }

    pub fn full(
        kind: &str,
        pid: u32,
        agent: &str,
        detail: String,
        image: &str,
        ppid: u32,
        cmdline: &str,
        class: &str,
    ) -> Self {
        Self {
            ts: now_ms(),
            kind: kind.into(),
            pid,
            agent: agent.into(),
            detail,
            image: image.into(),
            ppid,
            cmdline: cmdline.into(),
            class: class.into(),
            source: crate::mode::name().into(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_event_json_still_parses() {
        let raw = r#"{"ts":1,"kind":"spawn","pid":2,"agent":"process","detail":"cmd"}"#;
        let ev: Event = serde_json::from_str(raw).unwrap();
        assert_eq!(ev.kind, "spawn");
        assert_eq!(ev.agent, "process");
        assert_eq!(ev.detail, "cmd");
        assert_eq!(ev.pid, 2);
        assert_eq!(ev.image, "");
        assert_eq!(ev.ppid, 0);
        assert_eq!(ev.cmdline, "");
    }

    #[test]
    fn new_fields_are_added_not_renamed() {
        let ev = Event {
            ts: 5,
            kind: "spawn".into(),
            pid: 9,
            agent: "notepad.exe".into(),
            detail: r"C:\Windows\notepad.exe".into(),
            image: "notepad.exe".into(),
            ppid: 4,
            cmdline: r"C:\Windows\notepad.exe".into(),
            class: "process".into(),
            source: "etw".into(),
        };
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        for key in ["ts", "kind", "pid", "agent", "detail", "image", "ppid", "cmdline", "class", "source"] {
            assert!(v.get(key).is_some(), "missing {key}");
        }
        assert_eq!(v["agent"], "notepad.exe");
        assert_eq!(v["class"], "process");
        assert_eq!(v["ppid"], 4);
        assert_eq!(v["kind"], "spawn");
    }
}
