//! Платформенный слой: три глаза эндоскопа.
//!
//! * Linux — `/proc`: процессы, сокеты, `/proc/<pid>/fd`.
//! * Windows — `toolhelp32` (процессы), `iphlpapi` (TCP), файлы по mtime.
//!
//! Формат события, журнал, экран и детектор лжи — общие для обеих платформ:
//! один и тот же JSONL, один и тот же вердикт.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::journal::{Event, Journal};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub mod win_owner;

/// Процесс в живом кадре. Не событие журнала.
pub struct ProcSnap {
    pub pid: u32,
    pub cmd: String,
    pub agent: &'static str,
}

/// Слушающий TCP-порт в живом кадре.
pub struct ListenSnap {
    pub pid: u32,
    pub port: u32,
    pub local: String,
}

#[cfg(target_os = "linux")]
pub use linux::{scan_net, scan_procs, snapshot_listens, snapshot_procs, watch_dirs};
#[cfg(target_os = "windows")]
pub use windows::{scan_net, scan_procs, snapshot_listens, snapshot_procs, watch_dirs};

/// Ключ «висящего» соединения: pid + локальный адрес + локальный порт.
/// На Linux вместо адреса кладём inode сокета — смысл тот же (идентификатор конца).
pub type ConnKey = (u32, u64, u32);

/// Недавние запуски — для увязки «файл тронули, вот кто только что запускался».
pub type Spawn = (u64, u32, String, &'static str);

/// Классификация процесса: агент / инструмент / обычный процесс.
pub fn classify(cmd: &str) -> &'static str {
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

/// КТО виновник: ищем живой процесс, у которого этот файл открыт прямо сейчас.
#[cfg(target_os = "linux")]
pub fn attribute_open(path_str: &str) -> Option<(u32, &'static str)> {
    linux::attribute_open(path_str)
}

/// КТО виновник: ищем живой процесс, у которого этот файл открыт прямо сейчас.
#[cfg(target_os = "windows")]
pub fn attribute_open(path_str: &str) -> Option<(u32, &'static str)> {
    windows::attribute_open(path_str)
}

/// Запасной след: процесс, запущенный в последние 2 минуты и трогавший эту папку.
pub fn correlate_recent(recent: &VecDeque<Spawn>, path_str: &str) -> Option<(u32, &'static str)> {
    let parent = Path::new(path_str)
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if parent.is_empty() {
        return None;
    }
    let now = crate::journal::now_ms();
    for (ts, pid, cmd, agent) in recent.iter().rev() {
        if now.saturating_sub(*ts) < 120_000 && cmd.contains(parent) {
            return Some((*pid, agent));
        }
    }
    None
}

/// Мусор, который не пишем: кэши, сборка, git-внутренности.
pub fn is_noise(p: &Path) -> bool {
    let s = p.to_string_lossy().replace('\\', "/");
    s.contains("/target/")
        || s.contains("/.git/")
        || s.contains("/node_modules/")
        || s.contains("/__pycache__/")
        || s.contains("/.venv/")
        || s.ends_with(".pyc")
        || s.contains("/.spynel/history")
        || s.contains("/.spynel/tasks/")
        || s.contains("/.spynel/goals/")
        || s.contains("/.spynel/jobs/")
        || s.contains("/.spynel/runtime/")
}

/// Глаз №3: файлы. Слежение за ключевыми рабочими папками.
pub fn scan_files(
    state: &mut HashMap<PathBuf, (u64, u64)>,
    journal: &mut Journal,
    recent: &VecDeque<Spawn>,
    dirs: &[PathBuf],
) {
    for dir in dirs {
        walk_dir(dir, 3, state, journal, recent);
    }
}

fn walk_dir(
    dir: &Path,
    depth: u32,
    state: &mut HashMap<PathBuf, (u64, u64)>,
    journal: &mut Journal,
    recent: &VecDeque<Spawn>,
) {
    if depth == 0 {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut names: Vec<PathBuf> = Vec::new();
    for e in entries.flatten() {
        names.push(e.path());
    }
    let on_disk: HashSet<PathBuf> = names.iter().cloned().collect();
    let vanished: Vec<PathBuf> = state
        .keys()
        .filter(|p| p.parent() == Some(dir) && !on_disk.contains(*p))
        .cloned()
        .collect();
    for p in vanished {
        state.remove(&p);
        let ev = Event::now("file_delete", 0, "unknown", p.display().to_string());
        let _ = journal.write_event(&ev);
    }
    for path in names {
        if is_noise(&path) {
            continue;
        }
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_dir() {
            walk_dir(&path, depth - 1, state, journal, recent);
            continue;
        }
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let size = meta.len();
        let ps = path.display().to_string();
        let old = state.get(&path).copied();
        match old {
            None => {
                state.insert(path.clone(), (mtime, size));
                let (pid, agent) =
                    attribute_open(&ps).or_else(|| correlate_recent(recent, &ps)).unwrap_or((0, "unknown"));
                let ev = Event::now("file_create", pid, agent, ps);
                let _ = journal.write_event(&ev);
            }
            Some((old_mtime, old_size)) => {
                if old_mtime != mtime {
                    state.insert(path.clone(), (mtime, size));
                    let (pid, agent) =
                        attribute_open(&ps).or_else(|| correlate_recent(recent, &ps)).unwrap_or((0, "unknown"));
                    let detail = format!("{} ({} байт -> {} байт)", ps, old_size, size);
                    let ev = Event::now("file_write", pid, agent, detail);
                    let _ = journal.write_event(&ev);
                }
            }
        }
    }
}
