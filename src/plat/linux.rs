//! Linux: три глаза через `/proc`.
//! Логика v0.7 перенесена как есть — теперь это один из двух вариантов
//! платформенного слоя, а не единственный.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

use crate::journal::{now_ms, Journal};

use super::{record, ConnKey, ListenSnap, ProcSnap, Spawn, Who};

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

fn comm_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn ppid_of(pid: u32) -> u32 {
    let text = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let Some(rest) = text.rsplit_once(')').map(|(_, tail)| tail) else {
        return 0;
    };
    rest.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

pub fn who(pid: u32) -> Who {
    if pid == 0 {
        return Who::unknown();
    }
    let cmdline = pid_cmdline(pid);
    let mut image = comm_of(pid);
    if image.is_empty() {
        image = crate::feed::image_basename(&cmdline);
    }
    Who::from_parts(pid, ppid_of(pid), image, cmdline)
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
            let who = who(pid);
            if who.cmdline.is_empty() && who.image.is_empty() {
                continue;
            }
            let detail: String = if who.cmdline.is_empty() {
                who.image.clone()
            } else {
                who.cmdline.chars().take(200).collect()
            };
            recent.push_back((now_ms(), pid, detail.clone(), who.class));
            while recent.len() > 100 {
                recent.pop_front();
            }
            record(journal, "spawn", &who, detail);
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
            let who = who(pid);
            record(journal, "connect", &who, detail);
        }
    }
}

/// КТО виновник: ищем живой процесс, у которого этот файл открыт прямо сейчас.
pub fn attribute_open(path_str: &str) -> Option<u32> {
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
                            return Some(pid);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Живой кадр для XRAY: все процессы сейчас, без записи в журнал.
pub fn snapshot_procs() -> Vec<ProcSnap> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let Ok(name) = e.file_name().into_string() else { continue };
            let Ok(pid) = name.parse::<u32>() else { continue };
            let who = who(pid);
            if who.cmdline.is_empty() && who.image.is_empty() {
                continue;
            }
            let cmd = if who.cmdline.is_empty() {
                who.image.clone()
            } else {
                who.cmdline.chars().take(200).collect()
            };
            out.push(ProcSnap {
                pid,
                cmd,
                agent: who.class,
                image: who.image,
                ppid: who.ppid,
            });
        }
    }
    out
}

fn port_of(hex: &str) -> u32 {
    let Some((_, port)) = hex.rsplit_once(':') else { return 0 };
    u32::from_str_radix(port, 16).unwrap_or(0)
}

fn socket_owners() -> HashMap<u64, u32> {
    let mut inode_pid = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let Ok(name) = e.file_name().into_string() else { continue };
            let Ok(pid) = name.parse::<u32>() else { continue };
            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { continue };
            for fd in fds.flatten() {
                let Ok(link) = fd.path().read_link() else { continue };
                let s = link.to_string_lossy();
                let Some(rest) = s.strip_prefix("socket:[") else { continue };
                if let Ok(ino) = rest.trim_end_matches(']').parse::<u64>() {
                    inode_pid.insert(ino, pid);
                }
            }
        }
    }
    inode_pid
}

/// Слушающие порты. Глаз №2 пишет только ESTABLISHED, кадру нужны LISTEN.
pub fn snapshot_listens() -> Vec<ListenSnap> {
    let owners = socket_owners();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(text) = std::fs::read_to_string(file) else { continue };
        for line in text.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || cols[3] != "0A" {
                continue;
            }
            let Ok(inode) = cols[9].parse::<u64>() else { continue };
            let pid = owners.get(&inode).copied().unwrap_or(0);
            let port = port_of(cols[1]);
            if port == 0 || !seen.insert((pid, port)) {
                continue;
            }
            let local = if cols[1].split(':').next().map(|s| s.len()).unwrap_or(0) > 8 {
                format!("*:{port}")
            } else {
                decode_addr(cols[1])
            };
            out.push(ListenSnap { pid, port, local });
        }
    }
    out
}
