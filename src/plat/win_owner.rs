//! Кто держит файл открытым на Windows.
//!
//! Документированный путь: Restart Manager (`rstrtmgr.dll`) —
//! `RmStartSession` / `RmRegisterResources` / `RmGetList` отвечают на вопрос
//! «кто использует этот файл» точечно, без перебора всех дескрипторов
//! системы (этот перебор дорог и упирается в драйверы).
//!
//! Аналог на Linux — `/proc/<pid>/fd`.

use std::ptr::{null, null_mut};

use windows_sys::Win32::System::RestartManager::{
    RmEndSession, RmGetList, RmRegisterResources, RmStartSession, CCH_RM_SESSION_KEY,
    RM_PROCESS_INFO,
};

/// `ERROR_MORE_DATA` — список процессов успел вырасти.
const ERROR_MORE_DATA: u32 = 234;

/// Кто держит этот файл открытым прямо сейчас.
pub fn find_open_handle(path: &str) -> Option<(u32, String)> {
    unsafe {
        let mut session: u32 = 0;
        let mut key = [0u16; (CCH_RM_SESSION_KEY + 1) as usize];
        if RmStartSession(&mut session, 0, key.as_mut_ptr()) != 0 {
            return None;
        }
        let result = query(&session, path);
        RmEndSession(session);
        result
    }
}

unsafe fn query(session: &u32, path: &str) -> Option<(u32, String)> {
    let wpath: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    let files = [wpath.as_ptr()];
    if RmRegisterResources(*session, 1, files.as_ptr(), 0, null(), 0, null()) != 0 {
        return None;
    }
    let mut needed: u32 = 0;
    let mut count: u32 = 0;
    let mut reasons: u32 = 0;
    // Первый вызов — спрашиваем, сколько процессов держит файл.
    RmGetList(*session, &mut needed, &mut count, null_mut(), &mut reasons);
    if needed == 0 {
        return None;
    }
    for _ in 0..3 {
        let mut infos: Vec<RM_PROCESS_INFO> = vec![std::mem::zeroed(); needed as usize];
        let mut got: u32 = needed;
        let rc = RmGetList(
            *session,
            &mut needed,
            &mut got,
            infos.as_mut_ptr(),
            &mut reasons,
        );
        if rc == 0 {
            if got == 0 {
                return None;
            }
            let pid = infos[0].Process.dwProcessId;
            if pid == 0 {
                return None;
            }
            return Some((pid, path.to_string()));
        }
        if rc != ERROR_MORE_DATA || needed == 0 {
            return None;
        }
        // Список вырос — пробуем ещё раз с новым размером.
    }
    None
}
