//! Эндоскоп — рентген-камера для ИИ-агентов. Продукт №1 рембазы.
//! v0.3: журнал правды JSONL + пульс + глаз №1 (запуски) + глаз №2 (сеть).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
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

fn pid_cmdline(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string()
}

/// Глаз №1: каждый новый запуск в системе.
fn scan_procs(seen: &mut HashSet<u32>, journal: &mut Journal) {
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = match e.file_name().to_str() {
                Some(n) => n.to_string(),
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
            let cmd = pid_cmdline(pid);
            if cmd.is_empty() {
                continue;
            }
            let agent = classify(&cmd);
            let ev = Event::now("spawn", pid, agent, cmd.chars().take(200).collect());
            let _ = journal.write_event(&ev);
        }
    }
}

/// Расшифровка адреса из /proc/net/tcp (hex) в читаемый IP:PORT.
fn decode_addr(hex: &str) -> String {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return hex.to_string();
    }
    let ip = u32::from_str_radix(parts[0], 16).unwrap_or(0);
    let port = u16::from_str_radix(parts[1], 16).unwrap_or(0);
    format!(
        "{}.{}.{}.{}:{}",
        ip & 0xff,
        (ip >> 8) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 24) & 0xff,
        port
    )
}

/// Глаз №2: живые сетевые соединения — кто с кем разговаривает.
fn scan_net(seen_conn: &mut HashSet<(u32, u64)>, journal: &mut Journal) {
    // карта сокет-inode -> pid
    let mut inode_pid: HashMap<u64, u32> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let name = match e.file_name().to_str() {
                Some(n) => n.to_string(),
                None => continue,
            };
            let pid: u32 = match name.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };
            if let Ok(fds) = std::fs::read_dir(format!("/proc/{}/fd", pid)) {
                for fd in fds.flatten() {
                    if let Ok(link) = fd.path().read_link() {
                        let s = link.to_string_lossy().to_string();
                        if let Some(rest) = s.strip_prefix("socket:[") {
                            if let Ok(ino) = rest.trim_end_matches(']').parse::<u64>() {
                                inode_pid.insert(ino, pid);
                            }
                        }
                    }
                }
            }
        }
    }
    if let Ok(tcp) = std::fs::read_to_string("/proc/net/tcp") {
        for line in tcp.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || cols[3] != "01" {
                continue; // только ESTABLISHED
            }
            let inode: u64 = match cols[9].parse() {
                Ok(i) => i,
                Err(_) => continue,
            };
            let pid = match inode_pid.get(&inode) {
                Some(p) => *p,
                None => continue,
            };
            let key = (pid, inode);
            if seen_conn.contains(&key) {
                continue;
            }
            seen_conn.insert(key);
            let detail = format!("-> {}", decode_addr(cols[2]));
            let cmd = pid_cmdline(pid);
            let agent = classify(&cmd);
            let ev = Event::now("connect", pid, agent, detail);
            let _ = journal.write_event(&ev);
        }
    }
}

fn main() -> std::io::Result<()> {
    let journal_path = std::env::var("ENDOSCOPE_JOURNAL")
        .unwrap_or_else(|_| "endoscope.jsonl".into());
    let mut journal = Journal::open(&journal_path)?;
    let mut seen: HashSet<u32> = HashSet::new();
    let mut seen_conn: HashSet<(u32, u64)> = HashSet::new();

    // Первый проход — фиксируем тех, кто уже живёт.
    scan_procs(&mut seen, &mut journal);
    scan_net(&mut seen_conn, &mut journal);

    let pid = std::process::id();
    println!(
        "Эндоскоп v0.3 запущен. pid={}, журнал={}",
        pid, journal_path
    );
    loop {
        let before = journal.count;
        scan_procs(&mut seen, &mut journal);
        scan_net(&mut seen_conn, &mut journal);
        let new_events = journal.count - before;
        let ev = Event::now("heartbeat", pid, "endoscope", "alive".into());
        journal.write_event(&ev)?;
        println!("[{}] жива, новых фактов: {}", ev.ts, new_events);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
