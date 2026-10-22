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
use std::path::PathBuf;
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

use crate::journal::{now_ms, Journal};

use super::{record, ConnKey, ProcSnap, ListenSnap, Spawn, Who};

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
/// (список через точку с запятой). По умолчанию — `C:\remote` и профиль.
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
    let mut v = vec![PathBuf::from(r"C:\remote")];
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        if !home.is_empty() {
            v.push(PathBuf::from(home));
        }
    }
    v
}

fn exe_name(entry: &PROCESSENTRY32W) -> String {
    let buf = &entry.szExeFile;
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len]).trim().to_string()
}

/// Имя образа, родитель и командная строка одного процесса.
pub fn who(pid: u32) -> Who {
    if pid == 0 {
        return Who::unknown();
    }
    unsafe {
        let (cmdline, ppid, image_full) = inspect(pid);
        let image = {
            let from_path = crate::feed::image_basename(&image_full);
            if from_path.is_empty() {
                crate::feed::image_basename(&cmdline)
            } else {
                from_path
            }
        };
        let cmdline = if cmdline.is_empty() { image_full } else { cmdline };
        Who::from_parts(pid, ppid, image, cmdline)
    }
}

/// Полная командная строка процесса (аналог /proc/<pid>/cmdline).
pub fn pid_cmdline(pid: u32) -> String {
    unsafe {
        let (cmdline, _, image_full) = inspect(pid);
        if !cmdline.trim().is_empty() {
            cmdline
        } else {
            image_full
        }
    }
}

/// Командная строка, pid родителя и полный путь к образу — одним открытием процесса.
unsafe fn inspect(pid: u32) -> (String, u32, String) {
    let access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION;
    let h = OpenProcess(access, 0, pid);
    if h.is_null() {
        return (String::new(), 0, String::new());
    }
    let (cmdline, ppid) = cmdline_and_ppid(h);
    let image = image_from_handle(h).unwrap_or_default();
    CloseHandle(h);
    (cmdline.unwrap_or_default(), ppid, image)
}

unsafe fn cmdline_and_ppid(h: HANDLE) -> (Option<String>, u32) {
    let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
    let status = NtQueryInformationProcess(
        h,
        ProcessBasicInformation,
        &mut pbi as *mut PROCESS_BASIC_INFORMATION as *mut c_void,
        size_of::<PROCESS_BASIC_INFORMATION>() as u32,
        null_mut(),
    );
    let ppid = pbi.InheritedFromUniqueProcessId as u32;
    if status != STATUS_SUCCESS {
        return (None, ppid);
    }
    let peb = pbi.PebBaseAddress as usize;
    if peb == 0 {
        return (None, ppid);
    }
    // PEB -> ProcessParameters
    let mut params: usize = 0;
    if !read_mem(
        h,
        peb + PEB_PROCESS_PARAMETERS,
        &mut params as *mut usize as *mut u8,
        size_of::<usize>(),
    ) {
        return (None, ppid);
    }
    if params == 0 {
        return (None, ppid);
    }
    // ProcessParameters -> CommandLine (UNICODE_STRING)
    let mut us = UnicodeString { length: 0, maximum_length: 0, buffer: null_mut() };
    if !read_mem(
        h,
        params + RTL_COMMAND_LINE,
        &mut us as *mut UnicodeString as *mut u8,
        size_of::<UnicodeString>(),
    ) {
        return (None, ppid);
    }
    if us.length == 0 || us.buffer.is_null() {
        return (None, ppid);
    }
    let mut buf = vec![0u16; (us.length as usize / 2) + 1];
    if !read_mem(h, us.buffer as usize, buf.as_mut_ptr() as *mut u8, us.length as usize) {
        return (None, ppid);
    }
    let s = String::from_utf16_lossy(&buf);
    let s = s.trim_end_matches('\0').trim().to_string();
    if s.is_empty() {
        (None, ppid)
    } else {
        (Some(s), ppid)
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

unsafe fn image_from_handle(h: HANDLE) -> Option<String> {
    let mut size: u32 = 1024;
    let mut buf = vec![0u16; size as usize];
    let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut size);
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
/// Пустая командная строка не должна перескакивать `Process32NextW`.
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
                if pid != 0 && seen.insert(pid) {
                    let image = exe_name(&entry);
                    let cmdline = pid_cmdline(pid);
                    let who = Who::from_parts(pid, entry.th32ParentProcessID, image, cmdline);
                    if !who.image.is_empty() || !who.cmdline.is_empty() {
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
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
}

/// IPv4 из таблицы TCP: байты DWORD — сетевой порядок, не число big-endian.
fn fmt_addr(ip: u32, port: u32) -> String {
    crate::netaddr::format_ipv4_endpoint(ip, port as u16)
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
            let who = who(row.owning_pid);
            record(journal, "connect", &who, detail);
        }
    }
}

/// КТО виновник: ищем живой процесс, у которого этот файл открыт прямо сейчас.
/// На Windows это умеет Restart Manager (см. `super::win_owner`).
/// Если процесс не найден, работает запасной след `correlate_recent`
/// (недавний запуск в этой папке).
pub fn attribute_open(path_str: &str) -> Option<u32> {
    let (pid, _) = super::win_owner::find_open_handle(path_str)?;
    if pid == 0 {
        None
    } else {
        Some(pid)
    }
}

/// Живой кадр для XRAY. Не пишет журнал.
pub fn snapshot_procs() -> Vec<ProcSnap> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                let pid = entry.th32ProcessID;
                if pid != 0 {
                    let image = exe_name(&entry);
                    let cmdline = pid_cmdline(pid);
                    let who = Who::from_parts(pid, entry.th32ParentProcessID, image, cmdline);
                    if !who.image.is_empty() || !who.cmdline.is_empty() {
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
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

/// Слушающие TCP. Глаз №2 оставляет только ESTABLISHED.
pub fn snapshot_listens() -> Vec<ListenSnap> {
    let mut out = Vec::new();
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(null_mut(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if size < 4 {
            return out;
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
            return out;
        }
        let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        let row_size = size_of::<TcpRowOwnerPid>();
        let mut seen = HashSet::new();
        for i in 0..count {
            let off = 4 + i * row_size;
            if off + row_size > buf.len() {
                break;
            }
            let row = std::ptr::read_unaligned(buf.as_ptr().add(off) as *const TcpRowOwnerPid);
            if row.state != 2 {
                continue;
            }
            let port = u16::from_be(row.local_port as u16) as u32;
            if port == 0 || !seen.insert((row.owning_pid, port)) {
                continue;
            }
            out.push(ListenSnap {
                pid: row.owning_pid,
                port,
                local: fmt_addr(row.local_addr, row.local_port),
            });
        }
    }
    out
}
