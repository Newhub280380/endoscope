//! Windows: три глаза.
//!
//! * Глаз №1 (процессы) — `toolhelp32`: снимок всех процессов.
//! * Глаз №2 (сеть) — `iphlpapi`: `GetExtendedTcpTable` с классом
//!   `TCP_TABLE_OWNER_PID_ALL` — таблица TCP с владельцем (pid) сразу в строке.
//! * Глаз №3 (файлы) — `mtime`, общий с Linux.
//!
//! Командная строка процесса берётся из PEB через
//! `NtQueryInformationProcess(ProcessBasicInformation)` — это полная строка
//! запуска, как в `/proc/<pid>/cmdline`. Если процесс закрыт от чтения,
//! откатываемся на путь к исполняемому файлу (`QueryFullProcessImageNameW`).

use std::collections::{HashSet, VecDeque};
use std::ffi::c_void;
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{GetExtendedTcpTable, TCP_TABLE_OWNER_PID_ALL};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_BASIC_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};
use windows_sys::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};

use crate::journal::{now_ms, Event, Journal};

use super::{classify, ConnKey, Spawn};

/// `STATUS_SUCCESS`
const STATUS_SUCCESS: i32 = 0;
/// `AF_INET` — только IPv4 (как в /proc/net/tcp)
const AF_INET: u32 = 2;
/// `MIB_TCP_STATE_ESTABLISHED`
const TCP_STATE_ESTABLISHED: u32 = 5;
/// Смещение `PEB.ProcessParameters` (x64)
const PEB_PROCESS_PARAMETERS: usize = 0x20;
/// Смещение `RTL_USER_PROCESS_PARAMETERS.CommandLine` (x64)
const RTL_COMMAND_LINE: usize = 0x70;

/// UNICODE_STRING — так она лежит в RTL_USER_PROCESS_PARAMETERS.
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// MIB_TCPROW_OWNER_PID — строка таблицы TCP с владельцем.
#[repr(C)]
#[derive(Clone, Copy)]
struct TcpRowOwnerPid {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}

/// Какие папки смотрим. Перекрывается переменной ENDOSCOPE_WATCH_DIRS
/// (список через точку с запятой) — так же, как на Linux.
pub fn watch_dirs() -> Vec<PathBuf> {
    if let Ok(custom) = std::env::var("ENDOSCOPE_WATCH_DIRS") {
        let v: Vec<PathBuf> = custom
            .split(';')
            .filter(|s| !s.trim().is_empty())
            .map(PathBuf::from)
            .collect();
        if !v.is_empty() {
            return v;
        }
    }
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .unwrap_or_default();
    let mut v = Vec::new();
    for sub in [
        "pc-agent",
        "hub",
        "kb",
        "hub_out",
        "agent-xray",
        "workspace",
        "endoscope",
    ] {
        v.push(Path::new(&home).join(sub));
    }
    v
}

/// Полная командная строка процесса (аналог /proc/<pid>/cmdline).
pub fn pid_cmdline(pid: u32) -> String {
    unsafe {
        if let Some(cmd) = cmdline_from_peb(pid) {
            if !cmd.trim().is_empty() {
                return cmd;
            }
        }
        image_path(pid).unwrap_or_default()
    }
}

/// Читает командную строку из PEB процесса.
unsafe fn cmdline_from_peb(pid: u32) -> Option<String> {
    let h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
    if h.is_null() {
        return None;
    }
    let out = cmdline_from_handle(h);
    CloseHandle(h);
    out
}

unsafe fn cmdline_from_handle(h: HANDLE) -> Option<String> {
    let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
    let status = NtQueryInformationProcess(
        h,
        ProcessBasicInformation,
        &mut pbi as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
        size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        null_mut(),
    );
    if status != STATUS_SUCCESS {
        return None;
    }
    let peb = pbi.PebBaseAddress as usize;
    if peb == 0 {
        return None;
    }
    // PEB -> ProcessParameters
    let mut params: usize = 0;
    if !read_mem(
        h,
        peb + PEB_PROCESS_PARAMETERS,
        &mut params as *mut usize as *mut u8,
        size_of::<usize>(),
    ) {
        return None;
    }
    if params == 0 {
        return None;
    }
    // ProcessParameters -> CommandLine (UNICODE_STRING)
    let mut us = UnicodeString { length: 0, maximum_length: 0, buffer: null_mut() };
    if !read_mem(
        h,
        params + RTL_COMMAND_LINE,
        &mut us as *mut UnicodeString as *mut u8,
        size_of::<UnicodeString>(),
    ) {
        return None;
    }
    if us.length == 0 || us.buffer.is_null() {
        return None;
    }
    let mut buf = vec![0u16; (us.length as usize / 2) + 1];
    if !read_mem(h, us.buffer as usize, buf.as_mut_ptr() as *mut u8, us.length as usize) {
        return None;
    }
    let s = String::from_utf16_lossy(&buf);
    let s = s.trim_end_matches('\0').trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

unsafe fn read_mem(h: HANDLE, addr: usize, buf: *mut u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let mut read: usize = 0;
    let ok = ReadProcessMemory(
        h,
        addr as *const c_void,
        buf as *mut c_void,
        len,
        &mut read,
    );
    ok != 0 && read == len
}

/// Запасной путь: путь к исполняемому файлу.
unsafe fn image_path(pid: u32) -> Option<String> {
    let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if h.is_null() {
        return None;
    }
    let mut size: u32 = 1024;
    let mut buf = vec![0u16; size as usize];
    let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
    CloseHandle(h);
    if ok == 0 {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..(size as usize).min(buf.len())]);
    let s = s.trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Глаз №1: каждый новый запуск в системе.
pub fn scan_procs(seen: &mut HashSet<u32>, journal: &mut Journal, recent: &mut VecDeque<Spawn>) {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                if pid != 0 && !seen.contains(&pid) {
                    seen.insert(pid);
                    let cmd = pid_cmdline(pid);
                    if cmd.is_empty() {
                        continue;
                    }
                    let agent = classify(&cmd);
                    let detail: String = cmd.chars().take(200).collect();
                    recent.push_back((now_ms(), pid, detail.clone(), agent));
                    while recent.len() > 100 {
                        recent.pop_front();
                    }
                    let ev = Event::now("spawn", pid, agent, detail);
                    let _ = journal.write_event(&ev);
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
}

/// IPv4 в сетевом порядке + порт (тоже в сетевом порядке) -> "1.2.3.4:8080".
fn fmt_addr(ip: u32, port: u32) -> String {
    format!(
        "{}.{}.{}.{}:{}",
        (ip >> 24) & 0xff,
        (ip >> 16) & 0xff,
        (ip >> 8) & 0xff,
        ip & 0xff,
        u16::from_be(port as u16)
    )
}

/// Глаз №2: живые сетевые соединения — кто с кем разговаривает.
pub fn scan_net(seen_conn: &mut HashSet<ConnKey>, journal: &mut Journal) {
    unsafe {
        let mut size: u32 = 0;
        // Первый вызов — спрашиваем размер таблицы (возвращает ERROR_INSUFFICIENT_BUFFER).
        GetExtendedTcpTable(null_mut(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if size < 4 {
            return;
        }
        let mut buf = vec![0u8; size as usize];
        let res = GetExtendedTcpTable(
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if res != 0 {
            return;
        }
        // MIB_TCPTABLE_OWNER_PID: DWORD dwNumEntries, затем строки по 24 байта.
        let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = size_of::<TcpRowOwnerPid>();
        for i in 0..count {
            let off = 4 + i * row_size;
            if off + row_size > buf.len() {
                break;
            }
            let row = std::ptr::read_unaligned(buf.as_ptr().add(off) as *const TcpRowOwnerPid);
            if row.state != TCP_STATE_ESTABLISHED {
                continue;
            }
            if row.owning_pid == 0 {
                continue;
            }
            let key: ConnKey = (row.owning_pid, row.local_addr as u64, row.local_port as u32);
            if seen_conn.contains(&key) {
                continue;
            }
            seen_conn.insert(key);
            let detail = format!("-> {}", fmt_addr(row.remote_addr, row.remote_port));
            let cmd = pid_cmdline(row.owning_pid);
            let agent = classify(&cmd);
            let ev = Event::now("connect", row.owning_pid, agent, detail);
            let _ = journal.write_event(&ev);
        }
    }
}

/// КТО виновник: ищем живой процесс, у которого этот файл открыт прямо сейчас.
/// На Windows точный ответ даёт перебор системных дескрипторов
/// (NtQuerySystemInformation + DuplicateHandle + GetFinalPathNameByHandleW) —
/// см. `super::win_handles`. Если перебор недоступен, работает запасной след
/// `correlate_recent` (недавний запуск в этой папке).
pub fn attribute_open(path_str: &str) -> Option<(u32, &'static str)> {
    let (pid, _) = super::win_handles::find_open_handle(path_str)?;
    let cmd = pid_cmdline(pid);
    Some((pid, classify(&cmd)))
}

