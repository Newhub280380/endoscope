//! Перебор системных дескрипторов Windows: кто держит файл открытым.
//!
//! Linux делает это через `/proc/<pid>/fd`. На Windows аналог —
//! `NtQuerySystemInformation(SystemExtendedHandleInformation)`: таблица всех
//! дескрипторов системы с владельцем.
//!
//! Чтобы не дёргать `DuplicateHandle` на каждый дескриптор (а их сотни
//! тысяч), сначала определяем индекс типа объекта «файл» — по собственному
//! дескриптору журнала, — и дальше работаем только с файловыми дескрипторами.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};
use windows_sys::Wdk::System::SystemInformation::NtQuerySystemInformation;

/// `SystemExtendedHandleInformation`
const CLASS_EXTENDED_HANDLE_INFO: i32 = 64;

/// Запись таблицы дескрипторов (x64).
#[repr(C)]
#[derive(Clone, Copy)]
struct HandleEntry {
    object: usize,
    unique_process_id: usize,
    handle_value: usize,
    granted_access: u32,
    creator_back_trace_index: u16,
    object_type_index: u16,
    handle_attributes: u32,
    reserved: u32,
}

struct Cache {
    at: Instant,
    owners: HashMap<String, u32>,
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);
static JOURNAL_PATH: OnceLock<String> = OnceLock::new();

/// Запоминаем путь журнала — по нему возьмём эталонный файловый дескриптор.
pub fn set_journal_path(path: &str) {
    let abs = std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string());
    let _ = JOURNAL_PATH.set(abs);
}

/// Кто держит этот файл открытым прямо сейчас.
pub fn find_open_handle(path: &str) -> Option<(u32, String)> {
    let key = normalize(path);
    let owners = owners_map();
    owners.get(&key).map(|pid| (*pid, key.clone()))
}

/// Приводим путь к единому виду: без префикса `\\?\`, в нижний регистр.
fn normalize(p: &str) -> String {
    strip_ext_prefix(p).to_lowercase()
}

fn strip_ext_prefix(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{}", rest);
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        return rest.to_string();
    }
    s.to_string()
}

fn owners_map() -> HashMap<String, u32> {
    let mut guard = match CACHE.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(c) = guard.as_ref() {
        if c.at.elapsed() < Duration::from_secs(3) {
            return c.owners.clone();
        }
    }
    let owners = build();
    *guard = Some(Cache { at: Instant::now(), owners: owners.clone() });
    owners
}

/// Собираем карту «путь -> pid» по всем открытым файлам.
fn build() -> HashMap<String, u32> {
    let mut out: HashMap<String, u32> = HashMap::new();
    let entries = match unsafe { read_handle_table() } {
        Some(e) => e,
        None => return out,
    };
    if entries.is_empty() {
        return out;
    }
    // Эталонный файловый дескриптор — наш собственный файл журнала.
    let (our_pid, our_handle) = match reference_file_handle() {
        Some(x) => x,
        None => return out,
    };
    let file_type = entries
        .iter()
        .find(|e| e.unique_process_id == our_pid && e.handle_value == our_handle)
        .map(|e| e.object_type_index);
    let file_type = match file_type {
        Some(t) => t,
        None => return out,
    };

    // Группируем файловые дескрипторы по процессу-владельцу.
    let mut by_pid: HashMap<usize, Vec<usize>> = HashMap::new();
    for e in &entries {
        if e.object_type_index != file_type {
            continue;
        }
        by_pid
            .entry(e.unique_process_id)
            .or_default()
            .push(e.handle_value);
    }

    for (pid, handles) in by_pid {
        for hv in handles {
            if let Some(path) = unsafe { resolve(pid as u32, hv) } {
                out.entry(path).or_insert(pid as u32);
            }
        }
    }
    out
}

/// Читаем таблицу дескрипторов системы.
unsafe fn read_handle_table() -> Option<Vec<HandleEntry>> {
    let mut size: u32 = 0;
    // Первый вызов — спрашиваем размер (возвращает STATUS_INFO_LENGTH_MISMATCH).
    NtQuerySystemInformation(CLASS_EXTENDED_HANDLE_INFO, null_mut(), 0, &mut size);
    if size < 16 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let st = NtQuerySystemInformation(
        CLASS_EXTENDED_HANDLE_INFO,
        buf.as_mut_ptr() as *mut c_void,
        size,
        &mut size,
    );
    if st != 0 {
        return None;
    }
    let count = usize::from_le_bytes(buf[0..8].try_into().ok()?);
    let esz = size_of::<HandleEntry>();
    let avail = (buf.len().saturating_sub(16)) / esz;
    let n = count.min(avail);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = 16 + i * esz;
        let e: HandleEntry =
            std::ptr::read_unaligned(buf.as_ptr().add(off) as *const HandleEntry);
        out.push(e);
    }
    Some(out)
}

/// Наш собственный файловый дескриптор — эталон типа объекта «файл».
fn reference_file_handle() -> Option<(usize, usize)> {
    let path = JOURNAL_PATH.get()?;
    let file = std::fs::OpenOptions::new().read(true).open(path).ok()?;
    let handle = file.as_raw_handle() as usize;
    Some((std::process::id() as usize, handle))
}

/// Дублируем дескриптор в наш процесс и узнаём путь файла.
unsafe fn resolve(pid: u32, handle_value: usize) -> Option<String> {
    let ph = OpenProcess(PROCESS_DUP_HANDLE, 0, pid);
    if ph.is_null() {
        return None;
    }
    let mut dup: HANDLE = null_mut();
    let ok = DuplicateHandle(
        ph,
        handle_value as HANDLE,
        GetCurrentProcess(),
        &mut dup,
        0,
        0,
        DUPLICATE_SAME_ACCESS,
    );
    let mut res = None;
    if ok != 0 && !dup.is_null() {
        let mut buf = vec![0u16; 512];
        let n = GetFinalPathNameByHandleW(dup, buf.as_mut_ptr(), buf.len() as u32, 0);
        if n > 0 {
            let s = String::from_utf16_lossy(&buf[..(n as usize).min(buf.len())]);
            let s = strip_ext_prefix(&s).to_lowercase();            if !s.is_empty() {
                res = Some(s);
            }
        }
        CloseHandle(dup);
    }
    CloseHandle(ph);
    res
}
