//! FAIL-STOP и тройное подтверждение падения.
//!
//! Цель объявляется упавшей только когда сошлись три независимых канала:
//! процесс исчез или пришёл exit, её порт/связь мертвы, сердцебиение молчит
//! дольше порога. 1/3 — `warning`, 2/3 — `suspect` (снимок уже копится),
//! 3/3 — один `incident`, заморозка и конец наблюдения. Мёртвую цель
//! больше не опрашиваем.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::codes;
use crate::feed;
use crate::precursor::{self, Level, Probe, Sample};

pub const SILENCE_MS: u64 = 20_000;
pub const SAMPLE_MS: u64 = 15_000;
pub const WINDOW_MS: u64 = 30_000;
pub const MAX_TARGETS: usize = 32;
pub const RESTART_BUDGET: usize = 3;
pub const RESTART_WINDOW_MS: u64 = 600_000;
pub const FLOOD_LIMIT: u32 = 40;
pub const FLOOD_WINDOW_MS: u64 = 10_000;
pub const WALK_CAP: usize = 1_500;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    Watch = 0,
    Warning = 1,
    Suspect = 2,
    Fallen = 3,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Votes {
    pub process_gone: bool,
    pub link_dead: bool,
    pub silent: bool,
}

impl Votes {
    pub fn count(&self) -> u8 {
        u8::from(self.process_gone) + u8::from(self.link_dead) + u8::from(self.silent)
    }

    pub fn record(&self) -> String {
        format!(
            "process={},link={},silence={}",
            u8::from(self.process_gone),
            u8::from(self.link_dead),
            u8::from(self.silent)
        )
    }
}

#[derive(Clone, Debug)]
pub struct Obs {
    pub now: u64,
    pub alive: bool,
    pub link_up: bool,
    pub exit_code: Option<i32>,
    pub life: bool,
    pub silence_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verdict {
    pub kind: &'static str,
    pub code: &'static str,
    pub status: &'static str,
    pub votes: String,
    pub seal: bool,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub id: String,
    pub pid: u32,
    pub image: String,
    pub ppid: u32,
    pub cmdline: String,
    pub class: String,
    pub expects_link: bool,
    pub exit_code: Option<i32>,
    pub last_life_ms: u64,
    pub stage: Stage,
    pub fallen: bool,
    pub claimed_success: bool,
    pub device: bool,
    pub had_life: bool,
    pub saw_exit: bool,
    pub children: Vec<u32>,
    pub samples: VecDeque<Sample>,
    pub last_sample_ms: u64,
    pub last_cpu_ms: Option<u64>,
    pub last_level: String,
    pub last_precursor_ms: u64,
    pub error_hits: u32,
    pub error_seen: u32,
    pub restarts: u32,
    pub stamp: u64,
}

impl Target {
    fn blank(id: String, pid: u32) -> Self {
        Self {
            id,
            pid,
            image: String::new(),
            ppid: 0,
            cmdline: String::new(),
            class: String::new(),
            expects_link: false,
            exit_code: None,
            last_life_ms: 0,
            stage: Stage::Watch,
            fallen: false,
            claimed_success: false,
            device: false,
            had_life: false,
            saw_exit: false,
            children: Vec::new(),
            samples: VecDeque::new(),
            last_sample_ms: 0,
            last_cpu_ms: None,
            last_level: String::new(),
            last_precursor_ms: 0,
            error_hits: 0,
            error_seen: 0,
            restarts: 0,
            stamp: 0,
        }
    }
}

pub fn claimed_success(text: &str) -> bool {
    let t = text.to_lowercase();
    const WORDS: &[&str] = &[
        "success",
        "succeeded",
        "passed",
        "успех",
        "успешно",
        "тесты прошли",
        "tests passed",
    ];
    WORDS.iter().any(|w| t.contains(w))
}

pub fn diagnosis(t: &Target) -> &'static str {
    if t.device {
        return "E0201";
    }
    let nonzero = t.exit_code.map(|c| c != 0).unwrap_or(false);
    if t.claimed_success && nonzero {
        return "A0102";
    }
    if nonzero {
        return "E0101";
    }
    "E0102"
}

fn benign(t: &Target) -> bool {
    if t.device || t.class == "ai-agent" {
        return false;
    }
    !t.exit_code.map(|c| c != 0).unwrap_or(false)
}

/// Один шаг наблюдения. Упавшая цель не даёт новых событий.
pub fn step(t: &mut Target, obs: &Obs) -> Option<Verdict> {
    if t.fallen {
        return None;
    }
    if let Some(code) = obs.exit_code {
        t.exit_code = Some(code);
    }
    if obs.link_up {
        t.expects_link = true;
    }
    if obs.life {
        t.last_life_ms = obs.now;
        t.had_life = true;
    }
    let gone = !obs.alive || t.saw_exit;
    if gone && benign(t) {
        t.fallen = true;
        t.stage = Stage::Fallen;
        return None;
    }
    let process_gone = gone;
    let link_dead = if t.expects_link {
        !obs.link_up
    } else {
        process_gone && !obs.link_up
    };
    let silent = if t.device && !t.had_life && obs.alive {
        false
    } else {
        obs.now.saturating_sub(t.last_life_ms) >= obs.silence_ms
    };
    let votes = Votes { process_gone, link_dead, silent };
    let stage = match votes.count() {
        0 => Stage::Watch,
        1 => Stage::Warning,
        2 => Stage::Suspect,
        _ => Stage::Fallen,
    };
    if stage == Stage::Watch {
        t.stage = Stage::Watch;
        return None;
    }
    if stage == t.stage {
        return None;
    }
    if stage < t.stage {
        t.stage = stage;
        return None;
    }
    t.stage = stage;
    let code = if stage == Stage::Warning { "" } else { diagnosis(t) };
    let (kind, status, seal) = match stage {
        Stage::Warning => ("warning", "", false),
        Stage::Suspect => ("suspect", "pending", false),
        Stage::Fallen => {
            t.fallen = true;
            ("incident", "permanent", true)
        }
        Stage::Watch => ("warning", "", false),
    };
    Some(Verdict { kind, code, status, votes: votes.record(), seal })
}

#[derive(Clone, Debug)]
pub struct Planned {
    pub kind: &'static str,
    pub pid: u32,
    pub agent: String,
    pub detail: String,
    pub image: String,
    pub ppid: u32,
    pub cmdline: String,
    pub class: String,
    pub code: &'static str,
    pub status: &'static str,
    pub votes: String,
    pub level: String,
    pub indicators: String,
    pub ttf_s: Option<u64>,
    pub seal: Option<serde_json::Value>,
    pub seal_id: String,
}

#[derive(Clone, Debug)]
struct RingItem {
    ts: u64,
    pid: u32,
    ppid: u32,
    kind: String,
    agent: String,
    detail: String,
    image: String,
    cmdline: String,
}

pub struct FloodGuard {
    window: HashMap<String, (u64, u32)>,
    excluded: HashSet<String>,
    limit: u32,
    window_ms: u64,
}

impl FloodGuard {
    pub fn new() -> Self {
        Self {
            window: HashMap::new(),
            excluded: HashSet::new(),
            limit: FLOOD_LIMIT,
            window_ms: FLOOD_WINDOW_MS,
        }
    }

    pub fn is_excluded(&self, dir: &str) -> bool {
        self.excluded.contains(dir)
    }

    pub fn exclude(&mut self, dir: &str) {
        self.excluded.insert(dir.to_string());
    }

    /// true — этот удар переполнил окно, каталог надо закрыть один раз.
    pub fn hit(&mut self, dir: &str, now: u64) -> bool {
        if self.excluded.contains(dir) {
            return false;
        }
        let slot = self.window.entry(dir.to_string()).or_insert((now, 0));
        if now.saturating_sub(slot.0) >= self.window_ms {
            *slot = (now, 0);
        }
        slot.1 += 1;
        if slot.1 > self.limit {
            self.excluded.insert(dir.to_string());
            self.window.remove(dir);
            return true;
        }
        false
    }

    pub fn rate_per_min(&self, now: u64) -> f64 {
        self.window
            .values()
            .map(|(start, n)| {
                if now.saturating_sub(*start) >= self.window_ms {
                    0.0
                } else {
                    *n as f64 * 60_000.0 / self.window_ms as f64
                }
            })
            .fold(0.0, f64::max)
    }
}

impl Default for FloodGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct DirObs {
    pub path: String,
    pub present: bool,
    pub stamp: u64,
}

pub struct Tick<'a> {
    pub now: u64,
    pub alive: &'a HashSet<u32>,
    pub links: &'a HashSet<u32>,
    pub probes: &'a HashMap<u32, Probe>,
    pub dirs: &'a [DirObs],
    pub disk_free_mb: Option<u64>,
    pub self_pid: u32,
}

pub struct Watchman {
    targets: HashMap<String, Target>,
    denied: HashSet<String>,
    falls: HashMap<String, Vec<u64>>,
    budget_emitted: HashSet<String>,
    ring: VecDeque<RingItem>,
    roots: Vec<std::path::PathBuf>,
    pub flood: FloodGuard,
    extra: Vec<String>,
    self_pid: u32,
}

impl Watchman {
    pub fn new() -> Self {
        let extra = std::env::var("ENDOSCOPE_WATCH_PROCS")
            .unwrap_or_default()
            .split([',', ';'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        Self {
            targets: HashMap::new(),
            denied: HashSet::new(),
            falls: HashMap::new(),
            budget_emitted: HashSet::new(),
            ring: VecDeque::new(),
            roots: Vec::new(),
            flood: FloodGuard::new(),
            extra,
            self_pid: 0,
        }
    }

    pub fn set_roots(&mut self, roots: &[std::path::PathBuf]) {
        self.roots = roots.to_vec();
    }

    pub fn set_self_pid(&mut self, pid: u32) {
        self.self_pid = pid;
    }

    pub fn armed_pids(&self) -> Vec<u32> {
        self.targets
            .values()
            .filter(|t| t.pid != 0 && !t.fallen)
            .map(|t| t.pid)
            .collect()
    }

    pub fn due_pids(&self, now: u64, alive: &HashSet<u32>) -> Vec<u32> {
        self.targets
            .values()
            .filter(|t| {
                t.pid != 0
                    && !t.fallen
                    && alive.contains(&t.pid)
                    && now.saturating_sub(t.last_sample_ms) >= SAMPLE_MS
            })
            .take(MAX_TARGETS)
            .map(|t| t.pid)
            .collect()
    }

    pub fn file_root(&self, kind: &str, detail: &str) -> Option<String> {
        if !kind.starts_with("file_") {
            return None;
        }
        let path = detail.split(" (").next().unwrap_or(detail);
        feed::watch_root(path, &self.roots)
    }

    pub fn note(&mut self, ev: &Noted) {
        self.push_ring(ev);
        if ev.pid == 0 || ev.pid == self.self_pid {
            if ev.kind.starts_with("file_") {
                self.touch_dir(ev);
            }
            return;
        }
        if ev.kind == "spawn" {
            self.arm_from(ev);
        }
        let key = format!("pid:{}", ev.pid);
        let Some(t) = self.targets.get_mut(&key) else {
            return;
        };
        if ev.kind == "exit" {
            t.saw_exit = true;
            if let Some(code) = parse_exit(&ev.detail) {
                t.exit_code = Some(code);
            }
        }
        if ev.kind == "connect" {
            t.expects_link = true;
        }
        if is_life(&ev.kind) {
            t.last_life_ms = ev.ts;
            t.had_life = true;
        }
        if claimed_success(&ev.detail) || claimed_success(&ev.cmdline) {
            t.claimed_success = true;
        }
        if is_life(&ev.kind) {
            t.error_seen = t.error_seen.saturating_add(1);
            if looks_like_error(&ev.detail) {
                t.error_hits = t.error_hits.saturating_add(1);
            }
        }
        if ev.ppid != 0 {
            let ppid = ev.ppid;
            let pid = ev.pid;
            if let Some(parent) = self.targets.get_mut(&format!("pid:{ppid}")) {
                if !parent.children.contains(&pid) {
                    parent.children.push(pid);
                }
            }
        }
    }

    fn touch_dir(&mut self, ev: &Noted) {
        let Some(root) = self.file_root(&ev.kind, &ev.detail) else {
            return;
        };
        let key = format!("dir:{root}");
        if let Some(t) = self.targets.get_mut(&key) {
            t.last_life_ms = ev.ts;
            t.had_life = true;
        }
    }

    fn arm_from(&mut self, ev: &Noted) {
        if ev.pid == self.self_pid || self.denied.contains(&ev.image) {
            return;
        }
        if !interesting(&ev.class, &ev.image, &self.extra) {
            return;
        }
        let key = format!("pid:{}", ev.pid);
        if self.targets.contains_key(&key) || self.targets.len() >= MAX_TARGETS {
            return;
        }
        let mut t = Target::blank(key.clone(), ev.pid);
        t.image = ev.image.clone();
        t.ppid = ev.ppid;
        t.cmdline = ev.cmdline.clone();
        t.class = ev.class.clone();
        t.last_life_ms = ev.ts;
        t.had_life = true;
        t.claimed_success = claimed_success(&ev.cmdline);
        t.restarts = self.restart_count(&ev.image, ev.ts);
        self.targets.insert(key, t);
    }

    fn restart_count(&self, image: &str, now: u64) -> u32 {
        self.falls
            .get(image)
            .map(|v| v.iter().filter(|ts| now.saturating_sub(**ts) < RESTART_WINDOW_MS).count() as u32)
            .unwrap_or(0)
    }

    fn push_ring(&mut self, ev: &Noted) {
        if !is_life(&ev.kind) && ev.kind != "exit" && ev.kind != "spawn" {
            return;
        }
        self.ring.push_back(RingItem {
            ts: ev.ts,
            pid: ev.pid,
            ppid: ev.ppid,
            kind: ev.kind.clone(),
            agent: ev.agent.clone(),
            detail: ev.detail.clone(),
            image: ev.image.clone(),
            cmdline: ev.cmdline.clone(),
        });
        while self.ring.len() > 400 {
            self.ring.pop_front();
        }
    }

    pub fn tick(&mut self, tick: &Tick<'_>) -> Vec<Planned> {
        self.self_pid = tick.self_pid;
        let mut out = Vec::new();
        let flood = self.flood.rate_per_min(tick.now);
        let ids: Vec<String> = self
            .targets
            .keys()
            .filter(|k| k.starts_with("pid:"))
            .cloned()
            .collect();
        for id in ids {
            for plan in self.tick_pid(&id, tick, flood) {
                self.note_seal(&plan, tick.now, &mut out);
                out.push(plan);
            }
        }
        for dir in tick.dirs {
            self.tick_dir(dir, tick, &mut out);
        }
        out
    }

    fn note_seal(&mut self, plan: &Planned, now: u64, out: &mut Vec<Planned>) {
        if plan.seal.is_none() {
            return;
        }
        if plan.pid != 0 && !plan.image.is_empty() && plan.code != "E0103" {
            let image = plan.image.clone();
            self.falls.entry(image.clone()).or_default().push(now);
            self.enforce_budget(&image, now, out);
        }
        if plan.code == "E0201" {
            self.flood.exclude(&plan.image);
        }
    }

    fn enforce_budget(&mut self, image: &str, now: u64, out: &mut Vec<Planned>) {
        let n = self.restart_count(image, now);
        if n < RESTART_BUDGET as u32 || !self.budget_emitted.insert(image.to_string()) {
            return;
        }
        self.denied.insert(image.to_string());
        for t in self.targets.values_mut() {
            if t.image == image {
                t.fallen = true;
                t.stage = Stage::Fallen;
            }
        }
        out.push(Planned {
            kind: "incident",
            pid: 0,
            agent: image.to_string(),
            detail: format!(
                "E0103 бюджет перезапусков {image}: {n} падений за окно, наблюдение остановлено"
            ),
            image: image.to_string(),
            ppid: 0,
            cmdline: String::new(),
            class: "ai-agent".into(),
            code: "E0103",
            status: "permanent",
            votes: String::new(),
            level: String::new(),
            indicators: String::new(),
            ttf_s: None,
            seal: None,
            seal_id: String::new(),
        });
    }

    fn tick_dir(&mut self, dir: &DirObs, tick: &Tick<'_>, out: &mut Vec<Planned>) {
        if self.flood.is_excluded(&dir.path) {
            return;
        }
        let key = format!("dir:{}", dir.path);
        if !dir.present {
            if !self.targets.contains_key(&key) {
                return;
            }
            if let Some(plan) = self.apply_obs(&key, dead_obs(tick.now), tick.now) {
                self.note_seal(&plan, tick.now, out);
                out.push(plan);
            }
            return;
        }
        let fresh = !self.targets.contains_key(&key);
        {
            let t = self.targets.entry(key.clone()).or_insert_with(|| {
                let mut t = Target::blank(key.clone(), 0);
                t.device = true;
                t.expects_link = true;
                t.class = "device".into();
                t.image = dir.path.clone();
                t.last_life_ms = tick.now;
                t.stamp = dir.stamp;
                t
            });
            if fresh {
                return;
            }
            if t.stamp == 0 {
                t.stamp = dir.stamp;
            }
        }
        let stamp_ok = self
            .targets
            .get(&key)
            .map(|t| dir.stamp == 0 || t.stamp == 0 || dir.stamp == t.stamp)
            .unwrap_or(true);
        let obs = if stamp_ok {
            Obs {
                now: tick.now,
                alive: true,
                link_up: true,
                exit_code: None,
                life: false,
                silence_ms: SILENCE_MS,
            }
        } else {
            dead_obs(tick.now)
        };
        if let Some(plan) = self.apply_obs(&key, obs, tick.now) {
            self.note_seal(&plan, tick.now, out);
            out.push(plan);
        }
    }

    fn tick_pid(&mut self, id: &str, tick: &Tick<'_>, flood: f64) -> Vec<Planned> {
        let Some(t) = self.targets.get(id) else {
            return Vec::new();
        };
        if t.fallen || t.device {
            return Vec::new();
        }
        let pid = t.pid;
        let saw_exit = t.saw_exit;
        let exit_code = t.exit_code;
        if let Some(probe) = tick.probes.get(&pid) {
            self.push_sample(id, tick, probe, flood);
        }
        let mut out = Vec::new();
        if let Some(plan) = self.precursor_plan(id, tick.now) {
            out.push(plan);
        }
        let alive = tick.alive.contains(&pid) && !saw_exit;
        let link_up = tick.links.contains(&pid);
        let obs = Obs {
            now: tick.now,
            alive,
            link_up,
            exit_code,
            life: false,
            silence_ms: SILENCE_MS,
        };
        if let Some(plan) = self.apply_obs(id, obs, tick.now) {
            out.push(plan);
        }
        out
    }

    fn apply_obs(&mut self, id: &str, obs: Obs, now: u64) -> Option<Planned> {
        let verdict = {
            let t = self.targets.get_mut(id)?;
            if t.fallen {
                return None;
            }
            step(t, &obs)
        }?;
        Some(self.plan(id, now, &verdict))
    }

    fn push_sample(&mut self, id: &str, tick: &Tick<'_>, probe: &Probe, flood: f64) {
        let Some(t) = self.targets.get_mut(id) else {
            return;
        };
        let cpu_pct = match (t.last_cpu_ms, probe.cpu_ms) {
            (Some(prev), Some(now_cpu)) if t.last_sample_ms != 0 => {
                let wall = tick.now.saturating_sub(t.last_sample_ms);
                if wall == 0 {
                    None
                } else {
                    let used = now_cpu.saturating_sub(prev) as f64;
                    Some((used / wall as f64 * 100.0).min(100.0))
                }
            }
            _ => None,
        };
        t.last_cpu_ms = probe.cpu_ms.or(t.last_cpu_ms);
        t.last_sample_ms = tick.now;
        let error_pct = if t.error_seen == 0 {
            None
        } else {
            Some(t.error_hits as f64 * 100.0 / t.error_seen as f64)
        };
        let heartbeat_ms = Some(tick.now.saturating_sub(t.last_life_ms) as f64);
        t.samples.push_back(Sample {
            ts: tick.now,
            rss_kb: probe.rss_kb.map(|v| v as f64),
            handles: probe.handles.map(|v| v as f64),
            threads: probe.threads.map(|v| v as f64),
            cpu_pct,
            heartbeat_ms,
            error_pct,
            restarts: Some(t.restarts as f64),
            disk_free_mb: tick.disk_free_mb.map(|v| v as f64),
            flood_per_min: Some(flood),
        });
        while t.samples.len() > 8 {
            t.samples.pop_front();
        }
    }

    fn precursor_plan(&mut self, id: &str, now: u64) -> Option<Planned> {
        let t = self.targets.get_mut(id)?;
        if t.fallen || t.device {
            return None;
        }
        let report = precursor::assess(t.samples.make_contiguous())?;
        let level = report.level.as_str().to_string();
        let repeat_warning = report.level == Level::Warning && now.saturating_sub(t.last_precursor_ms) >= 60_000;
        if level == t.last_level && !repeat_warning {
            return None;
        }
        t.last_level = level.clone();
        t.last_precursor_ms = now;
        let indicators = report.indicators.join(",");
        let ttf = report.ttf_s;
        let image = t.image.clone();
        let pid = t.pid;
        let ppid = t.ppid;
        let cmdline = t.cmdline.clone();
        let class = t.class.clone();
        let agent = if image.is_empty() { class.clone() } else { image.clone() };
        let detail = match ttf {
            Some(s) => format!("уровень {level} показатели {indicators} ttf={s}с"),
            None => format!("уровень {level} показатели {indicators}"),
        };
        Some(Planned {
            kind: "precursor",
            pid,
            agent,
            detail,
            image,
            ppid,
            cmdline,
            class,
            code: "",
            status: "",
            votes: String::new(),
            level,
            indicators,
            ttf_s: ttf,
            seal: None,
            seal_id: String::new(),
        })
    }

    fn plan(&mut self, id: &str, now: u64, verdict: &Verdict) -> Planned {
        let t = self.targets.get(id).cloned().unwrap_or_else(|| Target::blank(id.into(), 0));
        let exit = t
            .exit_code
            .map(|c| format!(" exit={c}"))
            .unwrap_or_default();
        let detail = if verdict.kind == "incident" {
            format!(
                "{} {} {}{exit}",
                verdict.code,
                codes::title(verdict.code),
                verdict.votes
            )
        } else if verdict.code.is_empty() {
            format!("{} {}", verdict.kind, verdict.votes)
        } else {
            format!("{} {} {}", verdict.kind, verdict.code, verdict.votes)
        };
        let agent = if t.image.is_empty() { t.class.clone() } else { t.image.clone() };
        let seal = if verdict.seal {
            Some(self.hot_json(&t, now, &verdict.votes))
        } else {
            None
        };
        let seal_id = sanitize(&t.id);
        Planned {
            kind: verdict.kind,
            pid: t.pid,
            agent,
            detail,
            image: t.image,
            ppid: t.ppid,
            cmdline: t.cmdline,
            class: t.class,
            code: verdict.code,
            status: verdict.status,
            votes: verdict.votes.clone(),
            level: String::new(),
            indicators: String::new(),
            ttf_s: None,
            seal,
            seal_id,
        }
    }

    fn hot_json(&self, t: &Target, now: u64, votes: &str) -> serde_json::Value {
        let from = now.saturating_sub(WINDOW_MS);
        let events: Vec<serde_json::Value> = self
            .ring
            .iter()
            .filter(|e| e.ts >= from)
            .rev()
            .take(80)
            .map(|e| {
                serde_json::json!({
                    "ts": e.ts,
                    "kind": e.kind,
                    "pid": e.pid,
                    "ppid": e.ppid,
                    "agent": e.agent,
                    "image": e.image,
                    "cmdline": e.cmdline,
                    "detail": e.detail,
                })
            })
            .collect();
        let connections: Vec<&str> = self
            .ring
            .iter()
            .rev()
            .filter(|e| e.pid == t.pid && e.kind == "connect")
            .take(20)
            .map(|e| e.detail.as_str())
            .collect();
        serde_json::json!({
            "sealed": true,
            "ts": now,
            "target": t.id,
            "pid": t.pid,
            "ppid": t.ppid,
            "image": t.image,
            "cmdline": t.cmdline,
            "class": t.class,
            "exit_code": t.exit_code,
            "votes": votes,
            "children": t.children,
            "connections": connections,
            "events": events,
        })
    }
}

fn dead_obs(now: u64) -> Obs {
    Obs {
        now,
        alive: false,
        link_up: false,
        exit_code: None,
        life: false,
        silence_ms: SILENCE_MS,
    }
}

pub fn interesting(class: &str, image: &str, extra: &[String]) -> bool {
    if class == "ai-agent" || class == "tool" {
        return true;
    }
    extra.iter().any(|e| e.eq_ignore_ascii_case(image))
}

pub fn parse_exit(detail: &str) -> Option<i32> {
    let rest = detail.trim().strip_prefix("exit=")?;
    let num = rest.split_whitespace().next().unwrap_or(rest);
    num.parse().ok()
}

fn is_life(kind: &str) -> bool {
    !matches!(kind, "heartbeat" | "warning" | "suspect" | "incident" | "precursor")
}

fn looks_like_error(detail: &str) -> bool {
    let t = detail.to_lowercase();
    t.contains("error") || t.contains("fail") || t.contains("panic") || t.contains("ошиб")
}

fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(80)
        .collect()
}

/// Снимок события, который журнал отдаёт наблюдателю. Без циклической зависимости
/// на тип `Event` внутри шага голосования.
#[derive(Clone, Debug)]
pub struct Noted {
    pub ts: u64,
    pub kind: String,
    pub pid: u32,
    pub ppid: u32,
    pub agent: String,
    pub detail: String,
    pub image: String,
    pub cmdline: String,
    pub class: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Target {
        let mut t = Target::blank("pid:7".into(), 7);
        t.class = "ai-agent".into();
        t.image = "cursor".into();
        t.ppid = 1;
        t.cmdline = "cursor --task".into();
        t.last_life_ms = 1_000;
        t.had_life = true;
        t
    }

    fn obs(now: u64, alive: bool, link: bool) -> Obs {
        Obs { now, alive, link_up: link, exit_code: None, life: false, silence_ms: 20_000 }
    }

    #[test]
    fn votes_climb_warning_suspect_incident_once() {
        let mut t = agent();
        t.expects_link = true;
        let warning = step(&mut t, &obs(5_000, true, false)).unwrap();
        assert_eq!(warning.kind, "warning");
        assert!(warning.votes.contains("link=1"));
        assert!(step(&mut t, &obs(6_000, true, false)).is_none());

        let suspect = step(&mut t, &obs(30_000, true, false)).unwrap();
        assert_eq!(suspect.kind, "suspect");
        assert_eq!(suspect.status, "pending");
        assert!(!suspect.seal);

        t.saw_exit = true;
        t.exit_code = Some(1);
        let incident = step(&mut t, &obs(31_000, false, false)).unwrap();
        assert_eq!(incident.kind, "incident");
        assert_eq!(incident.code, "E0101");
        assert!(incident.seal);
        assert!(incident.votes.contains("process=1"));
        assert!(incident.votes.contains("link=1"));
        assert!(incident.votes.contains("silence=1"));
        assert!(step(&mut t, &obs(90_000, false, false)).is_none());
        assert!(t.fallen);
    }

    #[test]
    fn claimed_success_becomes_a0102() {
        let mut t = agent();
        t.claimed_success = true;
        t.exit_code = Some(2);
        t.expects_link = true;
        t.saw_exit = true;
        let v = step(&mut t, &obs(50_000, false, false)).unwrap();
        assert_eq!(v.code, "A0102");
        assert!(claimed_success("tests passed"));
        assert!(claimed_success("заявил успех"));
        assert!(!claimed_success("я не трогал файл"));
    }

    #[test]
    fn clean_tool_exit_stops_without_an_incident() {
        let mut t = Target::blank("pid:3".into(), 3);
        t.class = "tool".into();
        t.image = "python".into();
        t.last_life_ms = 0;
        t.exit_code = Some(0);
        assert!(step(&mut t, &obs(100, false, false)).is_none());
        assert!(t.fallen);
        assert!(step(&mut t, &obs(50_000, false, false)).is_none());
    }

    #[test]
    fn device_loss_is_e0201_and_flood_trips_once() {
        let mut t = Target::blank("dir:C".into(), 0);
        t.device = true;
        t.expects_link = true;
        t.class = "device".into();
        t.image = r"C:\remote".into();
        t.last_life_ms = 0;
        t.had_life = true;
        let v = step(&mut t, &obs(30_000, false, false)).unwrap();
        assert_eq!(v.kind, "incident");
        assert_eq!(v.code, "E0201");

        let mut flood = FloodGuard::new();
        flood.limit = 2;
        assert!(!flood.hit("C:\\remote", 0));
        assert!(!flood.hit("C:\\remote", 10));
        assert!(flood.hit("C:\\remote", 20));
        assert!(flood.is_excluded("C:\\remote"));
        assert!(!flood.hit("C:\\remote", 30));
    }

    #[test]
    fn one_channel_is_not_a_fall() {
        let mut t = agent();
        let v = step(&mut t, &obs(50_000, true, false)).unwrap();
        assert_eq!(v.kind, "warning");
        assert!(!t.fallen);
    }
}
