//! Журнал правды: JSONL, одна строка — один факт.
//! Поля `ts`, `kind`, `pid`, `agent`, `detail` остаются. Остальное добавлено
//! и читается по умолчанию, чтобы старые строки и XRAY не ломались.
//!
//! Каждая новая строка — звено хеш-цепочки (`prev_hash` + `hash`).

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::chain::{self, Signer};
use crate::fdir::{self, Noted, Planned, Tick};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub votes: String,
    #[serde(default)]
    pub level: String,
    #[serde(default)]
    pub indicators: String,
    #[serde(default)]
    pub freeze: String,
    #[serde(default)]
    pub freeze_hash: String,
    #[serde(default)]
    pub ttf_s: Option<u64>,
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
            prev_hash: String::new(),
            hash: String::new(),
            code: String::new(),
            status: String::new(),
            votes: String::new(),
            level: String::new(),
            indicators: String::new(),
            freeze: String::new(),
            freeze_hash: String::new(),
            ttf_s: None,
        }
    }
}

pub struct Journal {
    file: std::fs::File,
    pub count: u64,
    path: PathBuf,
    head: String,
    signer: Signer,
    watch: fdir::Watchman,
}

impl Journal {
    pub fn open(path: &str) -> std::io::Result<Self> {
        Self::open_with(path, &chain::default_key_path())
    }

    pub fn open_with(path: &str, key_path: &Path) -> std::io::Result<Self> {
        let signer = Signer::load_or_create(key_path)?;
        let journal_path = PathBuf::from(path);
        let head = chain::last_head(&journal_path);
        let file = OpenOptions::new().create(true).append(true).open(&journal_path)?;
        println!("самописец: цепочка включена, подпись головы журнала");
        Ok(Self {
            file,
            count: 0,
            path: journal_path,
            head,
            signer,
            watch: fdir::Watchman::new(),
        })
    }

    pub fn set_watch_roots(&mut self, roots: &[PathBuf]) {
        self.watch.set_roots(roots);
    }

    pub fn set_self_pid(&mut self, pid: u32) {
        self.watch.set_self_pid(pid);
    }

    pub fn armed_pids(&self) -> Vec<u32> {
        self.watch.armed_pids()
    }

    pub fn due_pids(&self, now: u64, alive: &std::collections::HashSet<u32>) -> Vec<u32> {
        self.watch.due_pids(now, alive)
    }

    pub fn flood_blocked(&self, root: &str) -> bool {
        self.watch.flood.is_excluded(root)
    }

    pub fn force_flood(&mut self, root: &str) -> std::io::Result<()> {
        if self.watch.flood.is_excluded(root) {
            return Ok(());
        }
        self.watch.flood.exclude(root);
        let ev = flood_event(root);
        self.write_plain(&ev)
    }

    pub fn write_event(&mut self, ev: &Event) -> std::io::Result<()> {
        if let Some(root) = self.watch.file_root(&ev.kind, &ev.detail) {
            if self.watch.flood.is_excluded(&root) {
                return Ok(());
            }
            if self.watch.flood.hit(&root, now_ms()) {
                let incident = flood_event(&root);
                return self.write_plain(&incident);
            }
        }
        self.write_plain(ev)
    }

    pub fn tick_watch(&mut self, tick: &Tick<'_>) -> std::io::Result<()> {
        let plans = self.watch.tick(tick);
        for plan in plans {
            self.commit_plan(plan)?;
        }
        Ok(())
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn sensor_lost(&mut self) -> std::io::Result<()> {
        let mut ev = Event::now(
            "incident",
            std::process::id(),
            "endoscope",
            "S0001 канал ETW оборвался, дальше один опрос без повторов".into(),
        );
        ev.code = "S0001".into();
        ev.status = "permanent".into();
        ev.class = "sensor".into();
        self.write_plain(&ev)
    }

    fn commit_plan(&mut self, plan: Planned) -> std::io::Result<()> {
        let mut ev = Event::full(
            plan.kind,
            plan.pid,
            &plan.agent,
            plan.detail,
            &plan.image,
            plan.ppid,
            &plan.cmdline,
            &plan.class,
        );
        ev.code = plan.code.into();
        ev.status = plan.status.into();
        ev.votes = plan.votes;
        ev.level = plan.level;
        ev.indicators = plan.indicators;
        ev.ttf_s = plan.ttf_s;
        if let Some(body) = plan.seal {
            let (path, hash) = self.write_freeze(&plan.seal_id, &body)?;
            ev.freeze = path;
            ev.freeze_hash = hash;
            ev.status = "permanent".into();
        }
        self.write_plain(&ev)
    }

    fn write_freeze(&self, id: &str, body: &serde_json::Value) -> std::io::Result<(String, String)> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        let stem = self
            .path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("endoscope");
        let name = format!("{stem}.freeze.{}.{id}.jsonl", now_ms());
        let path = parent.join(name);
        let bytes = serde_json::to_vec(body)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;
        let hash = chain::sha256_hex(&bytes);
        {
            let mut file = OpenOptions::new().create_new(true).write(true).open(&path)?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.flush()?;
        }
        Ok((path.display().to_string(), hash))
    }

    fn write_plain(&mut self, ev: &Event) -> std::io::Result<()> {
        let _guard = chain::io_lock();
        let (line, hash) = chain::stamp(ev, &self.head);
        writeln!(self.file, "{line}")?;
        self.file.flush()?;
        self.head = hash;
        self.count += 1;
        let sig = self.signer.sign_hex(&self.head);
        chain::write_sig(&chain::sig_path_for(&self.path), &self.head, &sig)?;
        if let Ok(stamped) = serde_json::from_str::<Event>(&line) {
            self.watch.note(&noted(&stamped));
        }
        Ok(())
    }
}

fn noted(ev: &Event) -> Noted {
    Noted {
        ts: ev.ts,
        kind: ev.kind.clone(),
        pid: ev.pid,
        ppid: ev.ppid,
        agent: ev.agent.clone(),
        detail: ev.detail.clone(),
        image: ev.image.clone(),
        cmdline: ev.cmdline.clone(),
        class: ev.class.clone(),
    }
}

fn flood_event(root: &str) -> Event {
    let mut ev = Event::now(
        "incident",
        std::process::id(),
        "endoscope",
        format!("F0301 каталог исключён из наблюдения: {root}"),
    );
    ev.code = "F0301".into();
    ev.status = "permanent".into();
    ev.class = "sensor".into();
    ev.image = "endoscope".into();
    ev
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
        assert_eq!(ev.hash, "");
        assert_eq!(ev.code, "");
        assert_eq!(ev.ttf_s, None);
    }

    #[test]
    fn new_fields_are_added_not_renamed() {
        let ev = Event::full("spawn", 9, "notepad.exe", r"C:\Windows\notepad.exe".into(), "notepad.exe", 4, r"C:\Windows\notepad.exe", "process");
        let v = serde_json::to_value(&ev).unwrap();
        for key in [
            "ts", "kind", "pid", "agent", "detail", "image", "ppid", "cmdline", "class", "source",
            "prev_hash", "hash", "code", "status", "votes", "level", "indicators", "freeze",
            "freeze_hash", "ttf_s",
        ] {
            assert!(v.get(key).is_some(), "missing {key}");
        }
        assert_eq!(v["agent"], "notepad.exe");
        assert_eq!(v["class"], "process");
        assert_eq!(v["ppid"], 4);
        assert_eq!(v["kind"], "spawn");
    }

    #[test]
    fn chained_journal_verifies_and_catches_tamper() {
        let dir = std::env::temp_dir().join(format!(
            "endo-journal-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let journal = dir.join("endoscope.jsonl");
        let key = dir.join("endoscope.key");
        {
            let mut j = Journal::open_with(journal.to_str().unwrap(), &key).unwrap();
            j.write_event(&Event::now("spawn", 1, "tool", "cmd".into())).unwrap();
            j.write_event(&Event::now("exit", 1, "tool", "exit=1 tool".into())).unwrap();
        }
        let report = chain::verify(&journal, &key);
        assert!(report.ok, "{}", report.reason);
        assert!(report.signed);
        assert_eq!(report.chained, 2);
        let mut text = fs::read_to_string(&journal).unwrap();
        text = text.replace("spawn", "nope!");
        fs::write(&journal, text).unwrap();
        let broken = chain::verify(&journal, &key);
        assert!(!broken.ok);
        let _ = fs::remove_dir_all(&dir);
    }
}
