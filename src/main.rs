//! Эндоскоп — рентген-камера для ИИ-агентов. Продукт №1 рембазы.
//! v0.8.1: живой кадр GET /frame (процессы и слушающие порты).
//! v0.8: порт на Windows (toolhelp32 + iphlpapi), экран и детектор лжи
//!       работают на обеих платформах.

mod journal;
mod plat;
mod screen;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;

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

    // Первый проход — фиксируем тех, кто уже живёт.
    plat::scan_procs(&mut seen, &mut journal, &mut recent);
    plat::scan_net(&mut seen_conn, &mut journal);
    plat::scan_files(&mut file_state, &mut journal, &recent, &watch);

    let pid = std::process::id();
    println!(
        "Эндоскоп v0.8.1 запущен. pid={}, журнал={}, экран=http://localhost:7095",
        pid, journal_path
    );
    println!("Смотрю папки: {:?}", watch);
    loop {
        let before = journal.count;
        plat::scan_procs(&mut seen, &mut journal, &mut recent);
        plat::scan_net(&mut seen_conn, &mut journal);
        plat::scan_files(&mut file_state, &mut journal, &recent, &watch);
        let new_events = journal.count - before;
        let ev = journal::Event::now("heartbeat", pid, "endoscope", "alive".into());
        journal.write_event(&ev)?;
        println!("[{}] жива, новых фактов: {}", ev.ts, new_events);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}
