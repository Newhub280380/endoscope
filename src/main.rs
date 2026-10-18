//! Эндоскоп — рентген-камера для ИИ-агентов. Продукт №1 рембазы.
//! v0.6: три глаза + экран + АТРИБУЦИЯ (кто трогал файл)
//!       + ПРОВЕРКА ПРАВДЫ: кнопка «проверить путь» на экране.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

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
        Self { ts: now_ms(), kind: kind.into(), pid, agent: agent.into(), detail }
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

/// Недавние запуски — для увязки «файл тронули, вот кто только что запускался».
type Spawn = (u64, u32, String, &'static str); // ts, pid, cmd, agent

/// Глаз №1: каждый новый запуск в системе.
fn scan_procs(seen: &mut HashSet<u32>, journal: &mut Journal, recent: &mut VecDeque<Spawn>) {
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
fn scan_net(seen_conn: &mut HashSet<(u32, u64)>, journal: &mut Journal) {
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

/// Глаз №3: файлы. Слежение за ключевыми рабочими папками.
const WATCH_DIRS: &[&str] = &[
    "/home/alexandr/pc-agent",
    "/home/alexandr/hub",
    "/home/alexandr/kb",
    "/home/alexandr/endoscope/src",
    "/home/alexandr/spynel/.spynel/instructions",
];

/// КТО виновник: ищем живой процесс, у которого этот файл открыт прямо сейчас.
fn attribute_open(path_str: &str) -> Option<(u32, &'static str)> {
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

/// Запасной след: процесс, запущенный в последние 2 минуты и трогавший эту папку.
fn correlate_recent(recent: &VecDeque<Spawn>, path_str: &str) -> Option<(u32, &'static str)> {
    let parent = Path::new(path_str)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or("");
    let parent = parent.rsplit('/').next().unwrap_or("");
    if parent.is_empty() {
        return None;
    }
    let now = now_ms();
    for (ts, pid, cmd, agent) in recent.iter().rev() {
        if now.saturating_sub(*ts) < 120_000 && cmd.contains(parent) {
            return Some((*pid, agent));
        }
    }
    None
}

fn scan_files(
    state: &mut HashMap<PathBuf, (u64, u64)>,
    journal: &mut Journal,
    recent: &VecDeque<Spawn>,
) {
    for dir in WATCH_DIRS {
        walk_dir(Path::new(dir), 3, state, journal, recent);
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
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
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

/// Мусор, который не пишем: кэши, сборка, git-внутренности.
fn is_noise(p: &Path) -> bool {
    let s = p.to_string_lossy();
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

// ==================== ЭКРАН «КИНО» ====================

fn start_screen(journal_path: String) {
    std::thread::spawn(move || {
        let listener = match TcpListener::bind("127.0.0.1:7095") {
            Ok(l) => l,
            Err(e) => {
                eprintln!("экран: не смог занять порт 7095: {}", e);
                return;
            }
        };
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let req = String::from_utf8_lossy(&buf).to_string();
            let first = req.lines().next().unwrap_or("").to_string();
            let (body, ctype) = if first.starts_with("GET /events") {
                (events_json(&journal_path), "application/json")
            } else if first.starts_with("GET /check?path=") {
                let raw = first.trim_start_matches("GET /check?path=");
                let raw = raw.split(' ').next().unwrap_or("");
                (check_json(&journal_path, &url_decode(raw)), "application/json")
            } else {
                (PAGE.to_string(), "text/html; charset=utf-8")
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                ctype,
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.write_all(body.as_bytes());
            let _ = stream.flush();
        }
    });
}

fn url_decode(s: &str) -> String {
    s.replace("%20", " ").replace("%2F", "/").replace("%2f", "/").replace('+', " ")
}

fn load_lines(journal_path: &str) -> Vec<String> {
    std::fs::read_to_string(journal_path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .filter(|l| !l.trim().is_empty() && !l.contains("\"heartbeat\""))
        .collect()
}

/// Последние 100 фактов журнала — свежие сверху, готовым JSON-массивом.
fn events_json(journal_path: &str) -> String {
    let mut lines = load_lines(journal_path);
    if lines.len() > 100 {
        lines = lines.split_off(lines.len() - 100);
    }
    lines.reverse();
    format!("[{}]", lines.join(","))
}

/// ПРАВДА ПО ПУТИ: все факты, где путь всплывает. Вердикт — трогали или нет.
fn check_json(journal_path: &str, query: &str) -> String {
    let q = query.trim();
    let mut hits: Vec<String> = load_lines(journal_path)
        .into_iter()
        .filter(|l| q.len() > 3 && l.contains(q))
        .collect();
    let touched = hits.iter().filter(|l| {
        l.contains("file_create") || l.contains("file_write") || l.contains("file_delete")
    });
    let n_touched = touched.count();
    let (verdict, red) = if q.len() < 4 {
        ("Введите путь целиком (минимум 4 символа)", false)
    } else if n_touched > 0 {
        ("ФАЙЛ ТРОГАЛИ: найдено фактов", true)
    } else {
        ("По дневнику это НЕ трогали — чисто", false)
    };
    let shown: Vec<String> = if hits.len() > 100 {
        hits.split_off(hits.len() - 100)
    } else {
        hits
    };
    let mut out = shown;
    out.reverse();
    format!(
        "{{\"verdict\":{}\"{}\"{},\"touched\":{},\"events\":[{}]}}",
        if red { "" } else { "" },
        verdict.replace('"', ""),
        "",
        n_touched,
        out.join(",")
    )
}

const PAGE: &str = r#"<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8">
<title>ЭНДОСКОП — живая правда</title>
<style>
 body{font-family:system-ui;background:#0d1117;color:#e6edf3;margin:0;padding:20px}
 h1{font-size:22px;margin:0 0 4px}
 .sub{color:#8b949e;margin-bottom:12px;font-size:14px}
 .dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:#3fb950;margin-right:6px;animation:p 2s infinite}
 @keyframes p{50%{opacity:.3}}
 input{background:#161b22;color:#e6edf3;border:1px solid #30363d;border-radius:6px;padding:8px 12px;font-size:14px;width:70%}
 button{background:#238636;color:#fff;border:none;border-radius:6px;padding:9px 16px;font-size:14px;cursor:pointer}
 #verdict{margin:10px 0;padding:10px 14px;border-radius:6px;font-weight:600;display:none}
 .red{background:#3d1418;color:#f85149;border:1px solid #f85149}
 .green{background:#12261e;color:#3fb950;border:1px solid #3fb950}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th{position:sticky;top:0;background:#161b22;text-align:left;padding:8px;color:#8b949e}
 td{padding:6px 8px;border-top:1px solid #21262d;word-break:break-all}
 .spawn{color:#58a6ff}.connect{color:#3fb950}.file_create{color:#d29922}
 .file_write{color:#e3b341}.file_delete{color:#f85149}
 .agent{color:#bc8cff}.time{color:#8b949e;white-space:nowrap}
 #wrap{max-width:1100px;margin:0 auto}
</style></head><body><div id="wrap">
<h1><span class="dot"></span>ЭНДОСКОП — живая правда</h1>
<div class="sub">Что реально делали процессы и агенты. Лента обновляется каждые 2 секунды.</div>
<div><input id="q" placeholder="введи путь к файлу — проверить, трогали ли его">
<button onclick="check()">ПРОВЕРИТЬ</button></div>
<div id="verdict"></div>
<table><thead><tr><th>Время</th><th>Что</th><th>Кто</th><th>Деталь</th></tr></thead>
<tbody id="rows"></tbody></table></div>
<script>
function fmt(ts){const d=new Date(ts);return d.toLocaleTimeString('ru-RU')}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}
const RU={spawn:'запуск',connect:'связь',file_create:'файл создан',file_write:'файл переписан',file_delete:'файл удалён'};
function row(e){return '<tr><td class="time">'+fmt(e.ts)+'</td><td class="'+e.kind+'">'+(RU[e.kind]||e.kind)+'</td><td class="agent">'+esc(e.agent)+' #'+e.pid+'</td><td>'+esc(e.detail)+'</td></tr>'}
async function tick(){
 try{
  const r=await fetch('/events');const evs=await r.json();
  document.getElementById('rows').innerHTML=evs.map(row).join('');
 }catch(e){}
 setTimeout(tick,2000);
}
async function check(){
 const q=document.getElementById('q').value.trim();
 if(!q)return;
 const v=document.getElementById('verdict');v.style.display='block';
 try{
  const r=await fetch('/check?path='+encodeURIComponent(q));const d=await r.json();
  v.className=d.verdict.indexOf('ТРОГАЛИ')>=0?'red':'green';
  v.textContent=d.verdict+' ('+d.touched+')';
  document.getElementById('rows').innerHTML=d.events.map(row).join('');
 }catch(e){v.className='red';v.textContent='ошибка проверки'}
}
tick();
</script></body></html>"#;

fn main() -> std::io::Result<()> {
    let journal_path = std::env::var("ENDOSCOPE_JOURNAL")
        .unwrap_or_else(|_| "endoscope.jsonl".into());
    let mut journal = Journal::open(&journal_path)?;
    let mut seen: HashSet<u32> = HashSet::new();
    let mut seen_conn: HashSet<(u32, u64)> = HashSet::new();
    let mut file_state: HashMap<PathBuf, (u64, u64)> = HashMap::new();
    let mut recent: VecDeque<Spawn> = VecDeque::new();

    start_screen(journal_path.clone());

    // Первый проход — фиксируем тех, кто уже живёт.
    scan_procs(&mut seen, &mut journal, &mut recent);
    scan_net(&mut seen_conn, &mut journal);
    scan_files(&mut file_state, &mut journal, &recent);

    let pid = std::process::id();
    println!(
        "Эндоскоп v0.6 запущен. pid={}, журнал={}, экран=http://localhost:7095",
        pid, journal_path
    );
    loop {
        let before = journal.count;
        scan_procs(&mut seen, &mut journal, &mut recent);
        scan_net(&mut seen_conn, &mut journal);
        scan_files(&mut file_state, &mut journal, &recent);
        let new_events = journal.count - before;
        let ev = Event::now("heartbeat", pid, "endoscope", "alive".into());
        journal.write_event(&ev)?;
        println!("[{}] жива, новых фактов: {}", ev.ts, new_events);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
