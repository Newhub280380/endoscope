//! Эндоскоп — рентген-камера для ИИ-агентов. Продукт №1 рембазы.
//! v0.9: на Windows живой глаз — ETW (процессы, файлы, сеть). Опрос
//!       (toolhelp32 + iphlpapi + mtime) остаётся, если сессию ядра
//!       поднять нельзя. На Linux по-прежнему только `/proc`.

mod feed;
mod journal;
mod mode;
mod netaddr;
mod plat;
mod screen;
mod version;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Duration;

use journal::Journal;
use plat::{ConnKey, Spawn};

fn main() -> std::io::Result<()> {
    let journal_path = std::env::var("ENDOSCOPE_JOURNAL")
        .unwrap_or_else(|_| "endoscope.jsonl".into());
    let mut journal = Journal::open(&journal_path)?;
    let mut seen: HashSet<u32> = HashSet::new();
    let mut seen_conn: HashSet<ConnKey> = HashSet::new();
    let mut file_state: HashMap<PathBuf, (u64, u64)> = HashMap::new();
    let mut recent: VecDeque<Spawn> = VecDeque::new();
    let watch = plat::watch_dirs();

    screen::start_screen(journal_path.clone());

    // Базовый снимок делаем один раз. Пока ETW жив, опрос не крутится —
    // иначе одни и те же факты пришли бы дважды.
    #[cfg(windows)]
    let mut need_baseline = true;
    #[cfg(not(windows))]
    let need_baseline = true;
    #[cfg(windows)]
    if let Some(src) = plat::etw::try_start(&watch) {
        // Снимок уже живущих процессов и файлов — это опрос, даже если дальше
        // пишет ETW. Иначе CI и первый проход помечали бы старые файлы как etw.
        baseline(
            &mut seen,
            &mut seen_conn,
            &mut file_state,
            &mut journal,
            &mut recent,
            &watch,
        );
        mode::set_etw();
        banner(&journal_path, &watch);
        need_baseline = false;
        run_etw(src, &mut seen, &mut journal, &mut recent)?;
        println!("ETW оборвался — перехожу на опрос.");
    }

    mode::set_poll();
    if need_baseline {
        banner(&journal_path, &watch);
        #[cfg(windows)]
        println!(
            "ETW-сессии ядра требуют администратора. Повышенный запуск: schtasks /Create /TN Endoscope /SC ONLOGON /RL HIGHEST /F /TR \"путь\\endoscope.exe\""
        );
        baseline(
            &mut seen,
            &mut seen_conn,
            &mut file_state,
            &mut journal,
            &mut recent,
            &watch,
        );
    }
    run_poll(
        &mut seen,
        &mut seen_conn,
        &mut file_state,
        &mut journal,
        &mut recent,
        &watch,
    )
}

fn banner(journal_path: &str, watch: &[PathBuf]) {
    println!(
        "Эндоскоп v{} запущен. режим={}, pid={}, журнал={}, экран=http://127.0.0.1:7095/ , здоровье=http://127.0.0.1:7095/health",
        version::VERSION,
        mode::name(),
        std::process::id(),
        journal_path
    );
    println!("Смотрю папки: {watch:?}");
}

fn baseline(
    seen: &mut HashSet<u32>,
    seen_conn: &mut HashSet<ConnKey>,
    file_state: &mut HashMap<PathBuf, (u64, u64)>,
    journal: &mut Journal,
    recent: &mut VecDeque<Spawn>,
    watch: &[PathBuf],
) {
    plat::scan_procs(seen, journal, recent);
    plat::scan_net(seen_conn, journal);
    plat::scan_files(file_state, journal, recent, watch);
}

fn run_poll(
    seen: &mut HashSet<u32>,
    seen_conn: &mut HashSet<ConnKey>,
    file_state: &mut HashMap<PathBuf, (u64, u64)>,
    journal: &mut Journal,
    recent: &mut VecDeque<Spawn>,
    watch: &[PathBuf],
) -> std::io::Result<()> {
    let mut marked = journal.count;
    loop {
        plat::scan_procs(seen, journal, recent);
        plat::scan_net(seen_conn, journal);
        plat::scan_files(file_state, journal, recent, watch);
        beat(journal, &mut marked, 0)?;
        std::thread::sleep(Duration::from_secs(5));
    }
}

#[cfg(windows)]
fn run_etw(
    src: plat::etw::EtwSource,
    seen: &mut HashSet<u32>,
    journal: &mut Journal,
    recent: &mut VecDeque<Spawn>,
) -> std::io::Result<()> {
    use std::sync::atomic::Ordering;

    let mut dedup = feed::Dedup::new();
    let mut last_beat = journal::now_ms();
    let mut marked = journal.count;
    loop {
        match src.rx.recv_timeout(Duration::from_secs(1)) {
            Ok(live) => apply_live(&live, seen, journal, recent, &mut dedup),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                mode::set_poll();
                return Ok(());
            }
        }
        let now = journal::now_ms();
        if now.saturating_sub(last_beat) >= 5_000 {
            let dropped = src.dropped.load(Ordering::Relaxed) + dedup.dropped;
            beat(journal, &mut marked, dropped)?;
            last_beat = now;
        }
    }
}

#[cfg(windows)]
fn apply_live(
    live: &plat::etw::Live,
    seen: &mut HashSet<u32>,
    journal: &mut Journal,
    recent: &mut VecDeque<Spawn>,
    dedup: &mut feed::Dedup,
) {
    if live.kind == "spawn" && seen.contains(&live.pid) {
        return;
    }
    let window_ms = match live.kind {
        "file_create" | "file_write" | "file_delete" => 1_000,
        "spawn" | "exit" => 2_000,
        "connect" if live.detail.starts_with("udp ") => 30_000,
        "connect" => 5_000,
        _ => 1_000,
    };
    let key = format!("{}|{}|{}", live.kind, live.pid, live.detail);
    if !dedup.allow(&key, journal::now_ms(), window_ms) {
        return;
    }
    if live.kind == "spawn" {
        seen.insert(live.pid);
        recent.push_back((journal::now_ms(), live.pid, live.detail.clone(), live.class));
        while recent.len() > 100 {
            recent.pop_front();
        }
    } else if live.kind == "exit" {
        seen.remove(&live.pid);
    }
    let who = plat::Who {
        pid: live.pid,
        ppid: live.ppid,
        image: live.image.clone(),
        cmdline: live.cmdline.clone(),
        class: live.class,
    };
    plat::record(journal, live.kind, &who, live.detail.clone());
}

fn beat(journal: &mut Journal, marked: &mut u64, dropped: u64) -> std::io::Result<()> {
    let new_events = journal.count - *marked;
    *marked = journal.count;
    let ev = journal::Event::now("heartbeat", std::process::id(), "endoscope", "alive".into());
    journal.write_event(&ev)?;
    println!(
        "[{}] жива ({}), новых фактов: {}, отброшено: {}",
        ev.ts,
        mode::name(),
        new_events,
        dropped
    );
    Ok(())
}
