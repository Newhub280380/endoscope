//! Чистые правила ленты: куда смотреть, что считать шумом, как из
//! идентификатора ETW-события получить kind/detail, и как не залить журнал.
//!
//! Идентификаторы событий — манифесты Microsoft-Windows-Kernel-File и
//! Microsoft-Windows-Kernel-Network. Маршрутизация по event id, а не по
//! opcode: у этих провайдеров opcode в живом сеансе приходит нулём.
//! Диспозиция IRP_MJ_CREATE лежит в старшем байте CreateOptions.
#![cfg_attr(not(windows), allow(dead_code))]

use std::collections::HashMap;
use std::path::PathBuf;

use crate::netaddr::{decode_port, format_ipv4};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetKind {
    Tcp,
    Udp,
}

/// TCP connect (12), TCP accept (15) и UDP send (42) — это «соединение»
/// для ленты. Пакетные события (10/11 и остальные) сюда не входят.
pub fn map_net(event_id: u16) -> Option<NetKind> {
    match event_id {
        12 | 15 => Some(NetKind::Tcp),
        42 => Some(NetKind::Udp),
        _ => None,
    }
}

pub fn connect_detail(kind: NetKind, addr: u32, port_raw: u16) -> String {
    let ep = format!("{}:{}", format_ipv4(addr), decode_port(port_raw));
    match kind {
        NetKind::Tcp => format!("-> {ep}"),
        NetKind::Udp => format!("udp -> {ep}"),
    }
}

/// Create (event 12): открытие существующего файла — не событие.
/// Перезапись — file_write. Создание и «открыть или создать» — file_create.
/// Каталог (FILE_DIRECTORY_FILE) не пишем.
pub fn file_create_kind(create_options: u32) -> Option<&'static str> {
    if create_options & 0x0000_0001 != 0 {
        return None;
    }
    match (create_options >> 24) & 0xff {
        1 => None,
        4 => Some("file_write"),
        _ => Some("file_create"),
    }
}

pub fn image_basename(path: &str) -> String {
    let token = first_token(path.trim()).trim_matches('"');
    if token.is_empty() {
        return String::new();
    }
    token
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(token)
        .to_string()
}

fn first_token(s: &str) -> &str {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('"') {
        if let Some(end) = rest.find('"') {
            return &s[..=end + 1];
        }
    }
    s.split_whitespace().next().unwrap_or(s)
}

pub fn actor_name(image: &str, class: &str) -> String {
    if image.is_empty() {
        class.to_string()
    } else {
        image.to_string()
    }
}

pub fn looks_like_dir(path: &str) -> bool {
    path.ends_with('\\') || path.ends_with('/')
}

/// `\Device\HarddiskVolumeN\...` и префиксы `\??\` / `\\?\` → `C:\...`.
/// `volumes` — пары (device в нижнем регистре, буква с двоеточием).
pub fn to_dos_path(path: &str, volumes: &[(String, String)]) -> String {
    let mut p = path.trim().replace('/', "\\");
    if let Some(rest) = p.strip_prefix("\\??\\") {
        p = rest.to_string();
    } else if let Some(rest) = p.strip_prefix("\\\\?\\") {
        p = rest.to_string();
    }
    let low = p.to_lowercase();
    for (dev, dos) in volumes {
        if !dev.is_empty() && low.starts_with(dev.as_str()) {
            let rest = p[dev.len()..].trim_start_matches('\\');
            return format!("{dos}\\{rest}");
        }
    }
    p
}

pub fn is_noise_path(path: &str) -> bool {
    let s = path.replace('\\', "/").to_lowercase();
    // Каталог приходит без завершающего слэша — иначе Chrome/Temp не отсекаются
    // и обход профиля спускается внутрь кэша.
    noise_body(&s) || noise_body(&format!("{s}/"))
}

fn noise_body(s: &str) -> bool {
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
        || s.contains("/appdata/local/temp/")
        || s.contains("/appdata/local/google/chrome/")
        || s.contains("/appdata/local/microsoft/edge/")
        || s.contains("/appdata/local/microsoft/windows/inetcache/")
        || s.contains("/appdata/local/microsoft/windows/temporary internet files/")
        || s.contains("/appdata/local/microsoft/windows/explorer/")
        || s.contains("/appdata/local/mozilla/")
        || s.contains("/appdata/roaming/mozilla/")
        || s.contains("/appdata/local/brave/")
        || s.contains("/appdata/local/packages/")
        || s.contains("/appdata/local/npm-cache/")
        || s.contains("/appdata/local/pip/")
        || s.contains("/appdata/local/yarn/")
        || s.contains("/appdata/local/crashdumps/")
        || s.contains("/appdata/local/d3dscache/")
        || s.contains("/windows/temp/")
        || s.contains("/inetcache/")
        || s.ends_with("/thumbs.db")
        || s.ends_with("/desktop.ini")
        || s.ends_with("/ntuser.dat")
        || s.ends_with("/ntuser.dat.log")
}

pub fn is_watched(path: &str, dirs: &[PathBuf]) -> bool {
    if path.is_empty() || looks_like_dir(path) || is_noise_path(path) {
        return false;
    }
    let norm = path.replace('/', "\\").to_lowercase();
    for dir in dirs {
        let mut root = dir.to_string_lossy().replace('/', "\\").to_lowercase();
        while root.ends_with('\\') {
            root.pop();
        }
        if root.is_empty() {
            continue;
        }
        if norm == root || norm.starts_with(&format!("{root}\\")) {
            return true;
        }
    }
    false
}

/// Одинаковые факты в окне и общий потолок в секунду.
pub struct Dedup {
    last: HashMap<String, u64>,
    window_start: u64,
    in_window: u32,
    pub dropped: u64,
    rate_per_sec: u32,
}

impl Dedup {
    pub fn new() -> Self {
        Self {
            last: HashMap::new(),
            window_start: 0,
            in_window: 0,
            dropped: 0,
            rate_per_sec: 120,
        }
    }

    pub fn allow(&mut self, key: &str, now_ms: u64, window_ms: u64) -> bool {
        if self.window_start == 0 || now_ms.saturating_sub(self.window_start) >= 1000 {
            self.window_start = now_ms;
            self.in_window = 0;
        }
        if self.in_window >= self.rate_per_sec {
            self.dropped += 1;
            return false;
        }
        if window_ms > 0 {
            if let Some(prev) = self.last.get(key) {
                if now_ms.saturating_sub(*prev) < window_ms {
                    self.dropped += 1;
                    return false;
                }
            }
            self.last.insert(key.to_string(), now_ms);
            if self.last.len() > 8000 {
                self.last.clear();
                self.last.insert(key.to_string(), now_ms);
            }
        }
        self.in_window += 1;
        true
    }
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_and_udp_map_to_connect_with_host_address() {
        assert_eq!(map_net(12), Some(NetKind::Tcp));
        assert_eq!(map_net(15), Some(NetKind::Tcp));
        assert_eq!(map_net(42), Some(NetKind::Udp));
        for id in [0, 10, 11, 13, 14, 16, 26, 43, 58] {
            assert_eq!(map_net(id), None, "event {id}");
        }
        assert_eq!(
            connect_detail(NetKind::Tcp, 0x0100_007f, 0x5000),
            "-> 127.0.0.1:80"
        );
        assert_eq!(
            connect_detail(NetKind::Udp, 0x0100_007f, 0x3500),
            "udp -> 127.0.0.1:53"
        );
        assert!(!connect_detail(NetKind::Tcp, 0x0100_007f, 0x5000).contains("1.0.0.127"));
    }

    #[test]
    fn create_disposition_distinguishes_open_from_create() {
        assert_eq!(file_create_kind(1 << 24), None);
        assert_eq!(file_create_kind(2 << 24), Some("file_create"));
        assert_eq!(file_create_kind(3 << 24), Some("file_create"));
        assert_eq!(file_create_kind(4 << 24), Some("file_write"));
        assert_eq!(file_create_kind(5 << 24), Some("file_create"));
        assert_eq!(file_create_kind((2 << 24) | 1), None);
    }

    #[test]
    fn image_name_is_the_file_not_the_class() {
        assert_eq!(image_basename(r"C:\Windows\System32\notepad.exe"), "notepad.exe");
        assert_eq!(
            image_basename(r"\Device\HarddiskVolume3\Windows\System32\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(
            image_basename(r#""C:\Program Files\app.exe" --flag"#),
            "app.exe"
        );
        assert_eq!(actor_name("notepad.exe", "process"), "notepad.exe");
        assert_eq!(actor_name("", "process"), "process");
    }

    #[test]
    fn watch_filter_keeps_remote_and_drops_caches() {
        let remote = vec![PathBuf::from(r"C:\remote")];
        let profile = vec![PathBuf::from(r"C:\Users\alex")];
        assert!(is_watched(r"C:\remote\job.txt", &remote));
        assert!(is_watched(r"c:\remote\Sub\a.TXT", &remote));
        assert!(!is_watched(r"C:\remote2\a.txt", &remote));
        assert!(!is_watched(r"C:\Windows\notepad.exe", &remote));
        assert!(is_watched(r"C:\Users\alex\Documents\a.txt", &profile));
        assert!(!is_watched(
            r"C:\Users\alex\AppData\Local\Temp\x.txt",
            &profile
        ));
        assert!(!is_watched(
            r"C:\Users\alex\AppData\Local\Google\Chrome\User Data\Cache\a",
            &profile
        ));
        assert!(!is_noise_path(r"C:\remote\temp\keep.txt"));
        assert!(is_noise_path(r"C:\Users\alex\AppData\Local\Google\Chrome"));
        assert!(is_noise_path(r"C:\Users\alex\AppData\Local\Temp"));
        assert!(!is_noise_path(r"C:\remote\temp"));
    }

    #[test]
    fn device_path_becomes_a_drive() {
        let vols = vec![(r"\device\harddiskvolume3".to_string(), "C:".to_string())];
        assert_eq!(
            to_dos_path(r"\Device\HarddiskVolume3\remote\a.txt", &vols),
            r"C:\remote\a.txt"
        );
        assert_eq!(to_dos_path(r"\??\C:\remote\a.txt", &vols), r"C:\remote\a.txt");
        assert!(is_watched(
            &to_dos_path(r"\Device\HarddiskVolume3\remote\a.txt", &vols),
            &[PathBuf::from(r"C:\remote")]
        ));
    }

    #[test]
    fn dedup_suppresses_the_same_write_inside_the_window() {
        let mut d = Dedup::new();
        assert!(d.allow("file_write|1|C:\\remote\\a.txt", 1_000, 1_000));
        assert!(!d.allow("file_write|1|C:\\remote\\a.txt", 1_500, 1_000));
        assert!(d.allow("file_write|1|C:\\remote\\a.txt", 2_000, 1_000));
        assert!(d.allow("file_write|1|C:\\remote\\b.txt", 1_500, 1_000));
        assert_eq!(d.dropped, 1);
    }
}
