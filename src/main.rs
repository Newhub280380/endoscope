//! Эндоскоп — рентген-камера для ИИ-агентов. Продукт №1 рембазы.
//! v0.2: журнал правды JSONL + пульс + глаз №1 — сканер процессов.
//! Камера видит каждый НОВЫЙ запуск в системе и пишет факт (не слова агента).

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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

/// Кто перед нами: простая классификация процесса по cmdline.
fn classify(cmd: &str) -> &'static str {
    let c = cmd.to_lowercase();
    if c.contains("claude") || c.contains("devin") || c.contains("copilot")
        || c.contains("cursor") || c.contains("pcagent") || c.contains("spynel")
    {
        "ai-agent"
    } else if c.contains("python") || c.contains("node") || c.contains("cargo") {
        "tool"
    } else {
        "process"
    }
}

fn scan_procs(seen: &mut HashSet<u32>, journal: &mut Journal) {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = match name.to_str() {
                Some(n) => n,
                None => continue,
            };
            let pid: u32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if seen.contains(&pid) {
                continue;
            }
            seen.insert(pid);
            let cmd = std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
                .unwrap_or_default()
                .replace('\0', " ");
            let cmd = cmd.trim().to_string();
            if cmd.is_empty() {
                continue; // процессы ядра не считаем
            }
            let agent = classify(&cmd);
            let ev = Event::now("spawn", pid, agent, cmd.chars().take(200).collect());
            let _ = journal.write_event(&ev);
        }
    }
}

fn main() -> std::io::Result<()> {
    let journal_path = std::env::var("ENDOSCOPE_JOURNAL")
        .unwrap_or_else(|_| "endoscope.jsonl".into());
    let mut journal = Journal::open(&journal_path)?;
    let mut seen: HashSet<u32> = HashSet::new();

    // Первый проход — фиксируем тех, кто уже живёт (без них — только новое).
    scan_procs(&mut seen, &mut journal);

    let pid = std::process::id();
    println!(
        "Эндоскоп v0.2 запущен. pid={}, журнал={}",
        pid, journal_path
    );
    loop {
        let before = journal.count;
        scan_procs(&mut seen, &mut journal);
        let spawned = journal.count - before;
        let ev = Event::now("heartbeat", pid, "endoscope", "alive".into());
        journal.write_event(&ev)?;
        println!("[{}] жива, новых процессов: {}", ev.ts, spawned);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
