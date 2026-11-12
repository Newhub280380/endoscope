//! ETW на Windows через ferrisetw.
//!
//! Две пользовательские сессии на манифестных провайдерах ядра
//! (их включает только повышенный токен) и, если поднимается, классическая
//! сессия процесса — в ней есть CommandLine, которого нет у
//! Microsoft-Windows-Kernel-Process.
//!
//! * процесс: `22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716`, keyword 0x10
//! * файл:    `edd08927-9cc4-4e65-b970-c2560fb5c289`
//!   (именно этот GUID зарегистрирован; соседний «похожий» молчит)
//! * сеть:    `7dd42a49-5329-4832-8dfd-43d979153a88`, keywords 0x10|0x20
//!
//! Маленький буфер у сессии процессов — чтобы короткая командная строка
//! не ждала, пока заполнится большой буфер. Файлы и сеть фильтруются
//! по event id ещё в ядре.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::kernel_providers;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::{stop_trace_by_name, KernelTrace, TraceProperties, UserTrace};
use ferrisetw::EventRecord;

use super::windows;
use crate::feed;

const SESSION_PROCESS: &str = "endoscope-etw-process";
const SESSION_MAIN: &str = "endoscope-etw-main";
const SESSION_CLASSIC: &str = "endoscope-etw-classic";

const KERNEL_PROCESS_GUID: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";
const KERNEL_FILE_GUID: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const KERNEL_NETWORK_GUID: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";

const KEYWORD_PROCESS: u64 = 0x10;
const KEYWORD_FILE: u64 = 0x10 | 0x20 | 0x80 | 0x200 | 0x400;
const KEYWORD_NET: u64 = 0x10 | 0x20;

const FILE_IDS: &[u16] = &[10, 11, 12, 14, 16, 26];
const NET_IDS: &[u16] = &[12, 15, 42];

pub struct Live {
    pub kind: &'static str,
    pub pid: u32,
    pub ppid: u32,
    pub image: String,
    pub cmdline: String,
    pub class: &'static str,
    pub detail: String,
}

pub struct EtwSource {
    _process: UserTrace,
    _main: UserTrace,
    _classic: Option<KernelTrace>,
    pub rx: Receiver<Live>,
    pub dropped: Arc<AtomicU64>,
}

#[derive(Clone)]
struct ProcInfo {
    ppid: u32,
    image: String,
    cmdline: String,
    class: &'static str,
}

impl ProcInfo {
    fn blank() -> Self {
        Self { ppid: 0, image: String::new(), cmdline: String::new(), class: "unknown" }
    }
}

#[derive(Default)]
struct PathCache {
    by_object: HashMap<u64, String>,
    by_key: HashMap<u64, String>,
}

impl PathCache {
    fn learn(&mut self, object: Option<u64>, key: Option<u64>, path: &str) {
        if path.is_empty() {
            return;
        }
        if self.by_object.len() + self.by_key.len() > 16_384 {
            self.by_object.clear();
            self.by_key.clear();
        }
        if let Some(object) = object {
            self.by_object.insert(object, path.to_string());
        }
        if let Some(key) = key {
            self.by_key.insert(key, path.to_string());
        }
    }

    fn resolve(&self, object: Option<u64>, key: Option<u64>) -> Option<String> {
        object
            .and_then(|object| self.by_object.get(&object).cloned())
            .or_else(|| key.and_then(|key| self.by_key.get(&key).cloned()))
    }

    fn forget_object(&mut self, object: u64) {
        self.by_object.remove(&object);
    }

    fn forget_key(&mut self, key: u64) {
        self.by_key.remove(&key);
    }
}

struct Shared {
    tx: SyncSender<Live>,
    watch: Vec<PathBuf>,
    volumes: Vec<(String, String)>,
    procs: Mutex<HashMap<u32, ProcInfo>>,
    paths: Mutex<PathCache>,
    dropped: Arc<AtomicU64>,
}

impl Shared {
    fn emit(&self, ev: Live) {
        if self.tx.try_send(ev).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

fn lock<'a, T>(m: &'a Mutex<T>) -> MutexGuard<'a, T> {
    m.lock().unwrap_or_else(|err| err.into_inner())
}

pub fn try_start(watch: &[PathBuf]) -> Option<EtwSource> {
    if std::env::var("ENDOSCOPE_MODE")
        .map(|v| v.eq_ignore_ascii_case("poll"))
        .unwrap_or(false)
    {
        println!("ENDOSCOPE_MODE=poll — ETW не включаю");
        return None;
    }
    let _ = stop_trace_by_name(SESSION_CLASSIC);
    let _ = stop_trace_by_name(SESSION_PROCESS);
    let _ = stop_trace_by_name(SESSION_MAIN);

    let (tx, rx) = mpsc::sync_channel(4096);
    let dropped = Arc::new(AtomicU64::new(0));
    let shared = Arc::new(Shared {
        tx,
        watch: watch.to_vec(),
        volumes: volume_map(),
        procs: Mutex::new(HashMap::new()),
        paths: Mutex::new(PathCache::default()),
        dropped: Arc::clone(&dropped),
    });
    if shared.volumes.is_empty() {
        eprintln!("ETW: карта дисков пуста — пути \\Device\\ могут не попасть в фильтр");
    }

    let classic = start_classic(&shared);
    let process = match start_user(&shared, true) {
        Ok(trace) => trace,
        Err(err) => {
            eprintln!(
                "ETW: сессия процессов не стартовала ({err:?}). Нужны права администратора — остаюсь на опросе."
            );
            return None;
        }
    };
    let main = match start_user(&shared, false) {
        Ok(trace) => trace,
        Err(err) => {
            eprintln!("ETW: сессия файлов и сети не стартовала ({err:?}). Остаюсь на опросе.");
            drop(process);
            return None;
        }
    };
    let classic_note = if classic.is_some() {
        format!(", {SESSION_CLASSIC} (командная строка)")
    } else {
        String::new()
    };
    println!("ETW сессии: {SESSION_PROCESS}, {SESSION_MAIN}{classic_note}");
    Some(EtwSource { _process: process, _main: main, _classic: classic, rx, dropped })
}

fn process_props() -> TraceProperties {
    let mut props = TraceProperties::default();
    props.buffer_size = 32;
    props.min_buffer = 16;
    props.max_buffer = 64;
    props.flush_timer = Duration::from_secs(1);
    props
}

fn main_props() -> TraceProperties {
    let mut props = TraceProperties::default();
    props.buffer_size = 64;
    props.min_buffer = 16;
    props.max_buffer = 64;
    props.flush_timer = Duration::from_secs(1);
    props
}

fn start_classic(shared: &Arc<Shared>) -> Option<KernelTrace> {
    let shared = Arc::clone(shared);
    let provider = Provider::kernel(&kernel_providers::PROCESS_PROVIDER)
        .add_callback(move |record, locator| {
            let shared = &shared;
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| on_classic(shared, record, locator)));
        })
        .build();
    match KernelTrace::new()
        .named(SESSION_CLASSIC.to_string())
        .set_trace_properties(process_props())
        .enable(provider)
        .start_and_process()
    {
        Ok(trace) => Some(trace),
        Err(err) => {
            eprintln!("ETW: классическая сессия процесса недоступна ({err:?}) — командную строку читаю из PEB");
            None
        }
    }
}

fn start_user(shared: &Arc<Shared>, process_session: bool) -> Result<UserTrace, ferrisetw::trace::TraceError> {
    if process_session {
        let shared = Arc::clone(shared);
        let provider = Provider::by_guid(KERNEL_PROCESS_GUID)
            .level(4)
            .any(KEYWORD_PROCESS)
            .add_callback(move |record, locator| {
                let shared = &shared;
                let _ = std::panic::catch_unwind(AssertUnwindSafe(|| on_process(shared, record, locator)));
            })
            .build();
        return UserTrace::new()
            .named(SESSION_PROCESS.to_string())
            .set_trace_properties(process_props())
            .enable(provider)
            .start_and_process();
    }

    let files = Arc::clone(shared);
    let mut file_provider = Provider::by_guid(KERNEL_FILE_GUID)
        .level(4)
        .any(KEYWORD_FILE)
        .add_callback(move |record, locator| {
            let files = &files;
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| on_file(files, record, locator)));
        });
    file_provider = file_provider.add_filter(EventFilter::ByEventIds(FILE_IDS.to_vec()));

    let nets = Arc::clone(shared);
    let mut net_provider = Provider::by_guid(KERNEL_NETWORK_GUID)
        .level(4)
        .any(KEYWORD_NET)
        .add_callback(move |record, locator| {
            let nets = &nets;
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| on_net(nets, record, locator)));
        });
    net_provider = net_provider.add_filter(EventFilter::ByEventIds(NET_IDS.to_vec()));

    UserTrace::new()
        .named(SESSION_MAIN.to_string())
        .set_trace_properties(main_props())
        .enable(file_provider.build())
        .enable(net_provider.build())
        .start_and_process()
}

fn on_classic(shared: &Shared, record: &EventRecord, locator: &SchemaLocator) {
    let op = record.opcode();
    if op != 1 && op != 3 {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let Some(pid) = prop_u32(&parser, &["ProcessId", "ProcessID"]) else {
        return;
    };
    if pid == 0 {
        return;
    }
    let cmd = prop_str(&parser, &["CommandLine"]).unwrap_or_default();
    let image = feed::image_basename(
        &prop_str(&parser, &["ImageFileName", "ImageName"]).unwrap_or_default(),
    );
    let ppid = prop_u32(&parser, &["ParentId", "ParentProcessID"]).unwrap_or(0);
    let mut procs = lock(&shared.procs);
    let info = procs.entry(pid).or_insert_with(ProcInfo::blank);
    if ppid != 0 {
        info.ppid = ppid;
    }
    if info.image.is_empty() && !image.is_empty() {
        info.image = image;
    }
    if !cmd.is_empty() {
        info.class = super::classify(&cmd);
        if info.image.is_empty() {
            info.image = feed::image_basename(&cmd);
        }
        info.cmdline = cmd;
    }
}

fn on_process(shared: &Shared, record: &EventRecord, locator: &SchemaLocator) {
    let id = record.event_id();
    let op = record.opcode();
    let rundown = id == 15 || op == 3;
    let stop = !rundown && (id == 2 || (op == 2 && id != 1));
    let start = !rundown && !stop && (id == 1 || (op == 1 && id == 0));
    if !rundown && !stop && !start {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let pid = prop_u32(&parser, &["ProcessID", "ProcessId"]).unwrap_or(0);
    let pid = if pid == 0 { record.process_id() } else { pid };
    if pid == 0 {
        return;
    }
    let ppid = prop_u32(&parser, &["ParentProcessID", "ParentId", "ParentProcessId"]).unwrap_or(0);
    let image_raw = prop_str(&parser, &["ImageName", "ImageFileName", "ProcessName"]).unwrap_or_default();
    let mut info = lock(&shared.procs).get(&pid).cloned().unwrap_or_else(ProcInfo::blank);
    if ppid != 0 {
        info.ppid = ppid;
    }
    let image = feed::image_basename(&image_raw);
    if !image.is_empty() {
        info.image = image;
    }
    if info.cmdline.is_empty() && (start || rundown) {
        let live = windows::who(pid);
        if info.ppid == 0 {
            info.ppid = live.ppid;
        }
        if info.image.is_empty() {
            info.image = live.image;
        }
        if info.cmdline.is_empty() {
            info.cmdline = live.cmdline;
        }
        if info.class == "unknown" {
            info.class = live.class;
        }
    }
    if info.class == "unknown" {
        let basis = if info.cmdline.is_empty() { info.image.as_str() } else { info.cmdline.as_str() };
        if !basis.is_empty() {
            info.class = super::classify(basis);
        }
    }
    {
        let mut procs = lock(&shared.procs);
        if let Some(prev) = procs.get(&pid) {
            if info.cmdline.is_empty() {
                info.cmdline = prev.cmdline.clone();
            }
            if info.image.is_empty() {
                info.image = prev.image.clone();
            }
            if info.ppid == 0 {
                info.ppid = prev.ppid;
            }
            if info.class == "unknown" {
                info.class = prev.class;
            }
        }
        procs.insert(pid, info.clone());
    }
    if rundown {
        return;
    }
    let kind = if stop { "exit" } else { "spawn" };
    let detail = if stop {
        if info.image.is_empty() { "exit".into() } else { info.image.clone() }
    } else if !info.cmdline.is_empty() {
        info.cmdline.chars().take(200).collect()
    } else if !image_raw.is_empty() {
        image_raw.chars().take(200).collect()
    } else {
        info.image.clone()
    };
    shared.emit(Live {
        kind,
        pid,
        ppid: info.ppid,
        image: info.image,
        cmdline: info.cmdline,
        class: info.class,
        detail,
    });
}

fn on_file(shared: &Shared, record: &EventRecord, locator: &SchemaLocator) {
    let id = record.event_id();
    if !matches!(id, 10 | 11 | 12 | 14 | 16 | 26) {
        return;
    }
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let file_object = prop_ptr(&parser, "FileObject");
    let file_key = prop_ptr(&parser, "FileKey");
    let pid = record.process_id();

    if id == 14 {
        if let Some(object) = file_object {
            lock(&shared.paths).forget_object(object);
        }
        return;
    }
    if id == 11 {
        if let Some(key) = file_key {
            lock(&shared.paths).forget_key(key);
        }
        return;
    }
    if id == 16 {
        let path = lock(&shared.paths).resolve(file_object, file_key);
        if let Some(path) = path {
            if feed::is_watched(&path, &shared.watch) {
                emit_file(shared, "file_write", pid, path);
            }
        }
        return;
    }

    let raw = prop_str(&parser, &["FileName", "FilePath"]).unwrap_or_default();
    if raw.is_empty() {
        return;
    }
    let path = feed::to_dos_path(&raw, &shared.volumes);
    if feed::looks_like_dir(&path) {
        return;
    }
    if id == 26 {
        if feed::is_watched(&path, &shared.watch) {
            emit_file(shared, "file_delete", pid, path);
        }
        if let Some(key) = file_key {
            lock(&shared.paths).forget_key(key);
        }
        return;
    }

    if id == 12 {
        if let Some(opts) = prop_u32(&parser, &["CreateOptions"]) {
            if opts & 1 != 0 {
                return;
            }
        }
    }
    if !feed::is_watched(&path, &shared.watch) {
        return;
    }
    lock(&shared.paths).learn(file_object, file_key, &path);
    if id == 12 {
        if let Some(opts) = prop_u32(&parser, &["CreateOptions"]) {
            if let Some(kind) = feed::file_create_kind(opts) {
                emit_file(shared, kind, pid, path);
            }
        }
    }
}

fn on_net(shared: &Shared, record: &EventRecord, locator: &SchemaLocator) {
    let id = record.event_id();
    let Some(kind) = feed::map_net(id) else {
        return;
    };
    let Ok(schema) = locator.event_schema(record) else {
        return;
    };
    let parser = Parser::create(record, &schema);
    let pid = prop_u32(&parser, &["PID", "ProcessId", "ProcessID"]).unwrap_or_else(|| record.process_id());
    let (addr_names, port_names): (&[&str], &[&str]) = if id == 15 {
        (&["saddr", "SourceAddress"], &["sport", "SourcePort"])
    } else {
        (&["daddr", "DestinationAddress"], &["dport", "DestinationPort"])
    };
    let Some(addr) = prop_u32(&parser, addr_names) else {
        return;
    };
    let Some(port_raw) = prop_u16(&parser, port_names) else {
        return;
    };
    let detail = feed::connect_detail(kind, addr, port_raw);
    if detail.contains("0.0.0.0") || detail.ends_with(":0") {
        return;
    }
    let info = actor(shared, pid);
    shared.emit(Live {
        kind: "connect",
        pid,
        ppid: info.ppid,
        image: info.image,
        cmdline: info.cmdline,
        class: info.class,
        detail,
    });
}

fn emit_file(shared: &Shared, kind: &'static str, pid: u32, path: String) {
    let info = actor(shared, pid);
    shared.emit(Live {
        kind,
        pid,
        ppid: info.ppid,
        image: info.image,
        cmdline: info.cmdline,
        class: info.class,
        detail: path,
    });
}

fn actor(shared: &Shared, pid: u32) -> ProcInfo {
    if pid == 0 {
        return ProcInfo::blank();
    }
    if let Some(info) = lock(&shared.procs).get(&pid).cloned() {
        if !info.image.is_empty() || !info.cmdline.is_empty() {
            return info;
        }
    }
    let live = windows::who(pid);
    let info = ProcInfo {
        ppid: live.ppid,
        image: live.image,
        cmdline: live.cmdline,
        class: live.class,
    };
    lock(&shared.procs).insert(pid, info.clone());
    info
}

fn prop_u32(parser: &Parser, names: &[&str]) -> Option<u32> {
    for name in names {
        if let Ok(value) = parser.try_parse::<u32>(name) {
            return Some(value);
        }
        if let Ok(value) = parser.try_parse::<u64>(name) {
            if let Ok(value) = u32::try_from(value) {
                return Some(value);
            }
        }
    }
    None
}

fn prop_u16(parser: &Parser, names: &[&str]) -> Option<u16> {
    for name in names {
        if let Ok(value) = parser.try_parse::<u16>(name) {
            return Some(value);
        }
        if let Ok(value) = parser.try_parse::<u32>(name) {
            return Some(value as u16);
        }
    }
    None
}

fn prop_str(parser: &Parser, names: &[&str]) -> Option<String> {
    for name in names {
        if let Ok(value) = parser.try_parse::<String>(name) {
            let value = value.trim_end_matches('\0').trim().to_string();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

fn prop_ptr(parser: &Parser, name: &str) -> Option<u64> {
    if let Ok(pointer) = parser.try_parse::<Pointer>(name) {
        let value = *pointer as u64;
        if value != 0 {
            return Some(value);
        }
    }
    if let Ok(value) = parser.try_parse::<u64>(name) {
        if value != 0 {
            return Some(value);
        }
    }
    None
}

fn volume_map() -> Vec<(String, String)> {
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    let mut vols = Vec::new();
    unsafe {
        for letter in b'A'..=b'Z' {
            let name = [letter as u16, b':' as u16, 0];
            let mut buf = [0u16; 512];
            let n = QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), buf.len() as u32);
            if n < 2 {
                continue;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            if end == 0 {
                continue;
            }
            let dev = String::from_utf16_lossy(&buf[..end]).trim().to_lowercase();
            if dev.is_empty() {
                continue;
            }
            vols.push((dev, format!("{}:", letter as char)));
        }
    }
    vols.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    vols
}
