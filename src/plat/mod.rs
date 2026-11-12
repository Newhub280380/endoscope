//! Платформенный слой: три глаза эндоскопа.
//!
//! * Linux — `/proc`: процессы, сокеты, `/proc/<pid>/fd`.
//! * Windows — опрос (`toolhelp32`, `iphlpapi`, mtime) и, если есть права
//!   администратора, ETW (см. `etw`).
//!
//! Формат события, журнал, экран и детектор лжи — общие для обеих платформ.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use crate::feed;
use crate::journal::{Event, Journal};

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod etw;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub mod win_owner;

#[cfg(target_os = "linux")]
pub use linux::{scan_net, scan_procs, snapshot_listens, snapshot_procs, watch_dirs, who};
#[cfg(target_os = "windows")]
pub use windows::{scan_net, scan_procs, snapshot_listens, snapshot_procs, watch_dirs, who};

/// Процесс в живом кадре `/frame`. Не событие журнала.
pub struct ProcSnap {
    pub pid: u32,
    pub cmd: String,
    pub agent: &'static str,
    pub image: String,
    pub ppid: u32,
}

/// Слушающий TCP-порт в живом кадре.
pub struct ListenSnap {
    pub pid: u32,
    pub port: u32,
    pub local: String,
}

/// Ключ «висящего» соединения: pid + локальный адрес + локальный порт.
/// На Linux вместо адреса кладём inode сокета — смысл тот же (идентификатор конца).
pub type ConnKey = (u32, u64, u32);

/// Недавние запуски — для увязки «файл тронули, вот кто только что запускался».
pub type Spawn = (u64, u32, String, &'static str);

/// Кто сделал факт: имя образа, pid, родитель, командная строка.
/// `class` — прежняя корзина process/tool/ai-agent. `actor()` — то, что
/// пишется в поле `agent` журнала.
#[derive(Clone, Debug)]
pub struct Who {
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub cmdline: String,
    pub class: &'static str,
}

impl Who {
    pub fn unknown() -> Self {
        Self { pid: 0, ppid: 0, image: String::new(), cmdline: String::new(), class: "unknown" }
    }

    pub fn from_parts(pid: u32, ppid: u32, image: String, cmdline: String) -> Self {
        let basis = if !cmdline.is_empty() { cmdline.as_str() } else { image.as_str() };
        let class = if basis.is_empty() { "unknown" } else { classify(basis) };
        let image = if image.is_empty() { feed::image_basename(&cmdline) } else { image };
        Self { pid, ppid, image, cmdline, class }
    }

    pub fn actor(&self) -> String {
        feed::actor_name(&self.image, self.class)
    }
}

pub fn record(journal: &mut Journal, kind: &str, who: &Who, detail: String) {
    let ev = Event::full(
        kind,
        who.pid,
        &who.actor(),
        detail,
        &who.image,
        who.ppid,
        &who.cmdline,
        who.class,
    );
    let _ = journal.write_event(&ev);
}

/// Классификация процесса: агент / инструмент / обычный процесс.
pub fn classify(cmd: &str) -> &'static str {
    let c = cmd.to_lowercase();
    if c.contains("claude")
        || c.contains("devin")
        || c.contains("copilot")
        || c.contains("cursor")
        || c.contains("pcagent")
        || c.contains("spynel")
    {
        "ai-agent"
    } else if c.contains("python") || c.contains("node") || c.contains("cargo") {
        "tool"
    } else {
        "process"
    }
}

/// КТО виновник: pid процесса, у которого этот файл открыт прямо сейчас.
#[cfg(target_os = "linux")]
pub fn attribute_open(path_str: &str) -> Option<u32> {
    linux::attribute_open(path_str)
}

/// КТО виновник: pid процесса, у которого этот файл открыт прямо сейчас.
#[cfg(target_os = "windows")]
pub fn attribute_open(path_str: &str) -> Option<u32> {
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

fn blame(path: &str, recent: &VecDeque<Spawn>) -> Who {
    if let Some(pid) = attribute_open(path) {
        let who = who(pid);
        if who.pid != 0 && (!who.image.is_empty() || !who.cmdline.is_empty()) {
            return who;
        }
    }
    if let Some((pid, class)) = correlate_recent(recent, path) {
        let mut who = who(pid);
        who.pid = pid;
        if who.image.is_empty() && who.cmdline.is_empty() {
            for (_, recent_pid, cmd, _) in recent.iter().rev() {
                if *recent_pid == pid {
                    who.cmdline = cmd.clone();
                    who.image = feed::image_basename(cmd);
                    break;
                }
            }
        }
        if who.class == "unknown" {
            who.class = class;
        }
        return who;
    }
    Who::unknown()
}

/// Мусор, который не пишем: кэши, сборка, git-внутренности, temp и кэши браузеров.
pub fn is_noise(p: &Path) -> bool {
    feed::is_noise_path(&p.to_string_lossy())
}

/// Глаз №3: файлы. Слежение за ключевыми рабочими папками.
pub fn scan_files(
    state: &mut HashMap<PathBuf, (u64, u64)>,
    journal: &mut Journal,
    recent: &VecDeque<Spawn>,
    dirs: &[PathBuf],
) {
    for dir in dirs {
        walk_dir(dir, 5, state, journal, recent);
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
        if is_noise(&p) {
            continue;
        }
        record(journal, "file_delete", &Who::unknown(), p.display().to_string());
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
                let who = blame(&ps, recent);
                record(journal, "file_create", &who, ps);
            }
            Some((old_mtime, old_size)) => {
                if old_mtime != mtime {
                    state.insert(path.clone(), (mtime, size));
                    let who = blame(&ps, recent);
                    let detail = format!("{} ({} байт -> {} байт)", ps, old_size, size);
                    record(journal, "file_write", &who, detail);
                }
            }
        }
    }
}
