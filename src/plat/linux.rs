//! Linux: три глаза через `/proc`.
//! Логика v0.7 перенесена как есть — теперь это один из двух вариантов
//! платформенного слоя, а не единственный.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use crate::journal::{now_ms, Event, Journal};

use super::{classify, ConnKey, Spawn};

/// Какие папки смотрим. Перекрывается переменной ENDOSCOPE_WATCH_DIRS
/// (список через двоеточие) — так же, как на Windows.
pub fn watch_dirs() -> Vec<PathBuf> {
    if let Ok(custom) = std::env::var("ENDOSCOPE_WATCH_DIRS") {
        let v: Vec<PathBuf> = custom
            .split(':')
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .collect();
        if !v.is_empty() {
            return v;
        }
    }
    vec![
        "/home/alexandr/pc-agent".into(),
        "/home/alexandr/hub".into(),
        "/home/alexandr/kb".into(),
        "/home/alexandr/endoscope/src".into(),
        "/home/alexandr/spynel/.spynel/instructions".into(),
    ]
}

pub fn pid_cmdline(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{}/cmdline", pid))
        .unwrap_or_default()
        .replace('\0', " ")
        .trim()
        .to_string()
}

/// Глаз №1: каждый новый запуск в системе.
pub fn scan_procs(seen: &mut HashSet<u32>, journal: &mut Journal, recent: &mut VecDeque<Spawn>) {
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
            recent.push_back((now_ms(), pid, cmd.chars().take(200).collect(), agent));
            while recent.len() > 100 {
                recent.pop_front();
            }
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
pub fn scan_net(seen_conn: &mut HashSet<ConnKey>, journal: &mut Journal) {
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
            let key: ConnKey = (pid, inode, 0);
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

/// КТО виновник: ищем живой процесс, у которого этот файл открыт прямо сейчас.
pub fn attribute_open(path_str: &str) -> Option<(u32, &'static str)> {
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
                        if link.to_string_lossy() == path_str {
                            let cmd = pid_cmdline(pid);
                            return Some((pid, classify(&cmd)));
                        }
                    }
                }
            }
        }
    }
    None
}
