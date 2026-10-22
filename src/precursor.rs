//! Предвестники отказа: уровни EICAS (advisory / caution / warning)
//! и оценка времени до предела по линейному тренду. Считается по уже
//! собранным точкам, без обращения к ОС.

#[derive(Clone, Debug)]
pub struct Probe {
    pub rss_kb: Option<u64>,
    pub handles: Option<u64>,
    pub threads: Option<u64>,
    pub cpu_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Sample {
    pub ts: u64,
    pub rss_kb: Option<f64>,
    pub handles: Option<f64>,
    pub threads: Option<f64>,
    pub cpu_pct: Option<f64>,
    pub heartbeat_ms: Option<f64>,
    pub error_pct: Option<f64>,
    pub restarts: Option<f64>,
    pub disk_free_mb: Option<f64>,
    pub flood_per_min: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Advisory,
    Caution,
    Warning,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Advisory => "advisory",
            Level::Caution => "caution",
            Level::Warning => "warning",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub level: Level,
    pub ttf_s: Option<u64>,
    pub indicators: Vec<&'static str>,
}

struct Spec {
    name: &'static str,
    hard: f64,
    soft: f64,
    rising: bool,
}

const SPECS: &[Spec] = &[
    Spec { name: "rss", hard: 1_500_000.0, soft: 400_000.0, rising: true },
    Spec { name: "handles", hard: 2_000.0, soft: 400.0, rising: true },
    Spec { name: "threads", hard: 250.0, soft: 64.0, rising: true },
    Spec { name: "cpu", hard: 95.0, soft: 80.0, rising: true },
    Spec { name: "heartbeat", hard: 60_000.0, soft: 20_000.0, rising: true },
    Spec { name: "errors", hard: 50.0, soft: 20.0, rising: true },
    Spec { name: "restarts", hard: 5.0, soft: 2.0, rising: true },
    Spec { name: "disk", hard: 100.0, soft: 500.0, rising: false },
    Spec { name: "flood", hard: 80.0, soft: 30.0, rising: true },
];

#[derive(Clone, Copy)]
struct Ind {
    name: &'static str,
    fast: bool,
    near: bool,
    ttf_s: Option<u64>,
}

/// Наклон в единицах величины на секунду. Нужны две разные по времени точки.
pub fn slope_per_sec(points: &[(u64, f64)]) -> Option<f64> {
    if points.len() < 2 {
        return None;
    }
    let n = points.len() as f64;
    let t0 = points[0].0 as f64;
    let mut sx = 0.0;
    let mut sy = 0.0;
    let mut sxx = 0.0;
    let mut sxy = 0.0;
    for (t, v) in points {
        let x = (*t as f64 - t0) / 1000.0;
        sx += x;
        sy += *v;
        sxx += x * x;
        sxy += x * *v;
    }
    let den = n * sxx - sx * sx;
    if den.abs() < 1e-9 {
        return None;
    }
    Some((n * sxy - sx * sy) / den)
}

/// Секунды до предела, если величина движется к нему.
pub fn ttf_until(points: &[(u64, f64)], limit: f64, rising: bool) -> Option<u64> {
    let slope = slope_per_sec(points)?;
    let last = points.last()?.1;
    if rising {
        if slope <= 0.0 {
            return None;
        }
        if last >= limit {
            return Some(0);
        }
        Some(((limit - last) / slope).ceil().max(0.0) as u64)
    } else {
        if slope >= 0.0 {
            return None;
        }
        if last <= limit {
            return Some(0);
        }
        Some(((last - limit) / -slope).ceil().max(0.0) as u64)
    }
}

fn series(samples: &[Sample], name: &str) -> Vec<(u64, f64)> {
    let mut out = Vec::new();
    for s in samples {
        let v = match name {
            "rss" => s.rss_kb,
            "handles" => s.handles,
            "threads" => s.threads,
            "cpu" => s.cpu_pct,
            "heartbeat" => s.heartbeat_ms,
            "errors" => s.error_pct,
            "restarts" => s.restarts,
            "disk" => s.disk_free_mb,
            "flood" => s.flood_per_min,
            _ => None,
        };
        if let Some(v) = v {
            out.push((s.ts, v));
        }
    }
    out
}

fn judge(spec: &Spec, points: &[(u64, f64)]) -> Option<Ind> {
    let last = points.last()?.1;
    let ttf_s = ttf_until(points, spec.hard, spec.rising);
    let past_soft = if spec.rising { last >= spec.soft } else { last <= spec.soft };
    let near = if spec.rising {
        last >= spec.hard * 0.9
    } else {
        last <= spec.hard * 1.1
    };
    let fast = ttf_s.map(|t| t < 60).unwrap_or(false) && past_soft;
    let bad = past_soft || near;
    if !bad && !fast {
        return None;
    }
    Some(Ind { name: spec.name, fast, near, ttf_s })
}

/// Один плохой показатель — advisory, два или крутой тренд — caution,
/// три или близость к пределу — warning.
pub fn assess(samples: &[Sample]) -> Option<Report> {
    if samples.is_empty() {
        return None;
    }
    let mut inds = Vec::new();
    for spec in SPECS {
        let points = series(samples, spec.name);
        if let Some(ind) = judge(spec, &points) {
            inds.push(ind);
        }
    }
    if inds.is_empty() {
        return None;
    }
    let bad = inds.len();
    let fast = inds.iter().any(|i| i.fast);
    let near = inds.iter().any(|i| i.near);
    let level = if near || bad >= 3 {
        Level::Warning
    } else if bad >= 2 || fast {
        Level::Caution
    } else {
        Level::Advisory
    };
    let ttf_s = inds.iter().filter_map(|i| i.ttf_s).min();
    let indicators = inds.into_iter().map(|i| i.name).collect();
    Some(Report { level, ttf_s, indicators })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pt(ts: u64, rss: f64) -> Sample {
        Sample {
            ts,
            rss_kb: Some(rss),
            handles: None,
            threads: None,
            cpu_pct: None,
            heartbeat_ms: None,
            error_pct: None,
            restarts: None,
            disk_free_mb: None,
            flood_per_min: None,
        }
    }

    #[test]
    fn linear_ttf_reaches_the_limit() {
        let points = [(0, 0.0), (10_000, 10.0), (20_000, 20.0)];
        let slope = slope_per_sec(&points).unwrap();
        assert!((slope - 1.0).abs() < 1e-6, "{slope}");
        assert_eq!(ttf_until(&points, 100.0, true), Some(80));
    }

    #[test]
    fn one_indicator_is_advisory_three_are_warning() {
        // Медленный рост за мягким порогом: один показатель, до предела далеко.
        let samples = vec![pt(0, 420_000.0), pt(60_000, 430_000.0)];
        let report = assess(&samples).unwrap();
        assert_eq!(report.level, Level::Advisory);
        assert_eq!(report.indicators, vec!["rss"]);
        assert!(report.ttf_s.unwrap() > 60);

        let mut hot = pt(0, 1_400_000.0);
        hot.cpu_pct = Some(96.0);
        hot.handles = Some(2_100.0);
        let report = assess(&[hot]).unwrap();
        assert_eq!(report.level, Level::Warning);
        assert!(report.indicators.len() >= 3);
    }

    #[test]
    fn two_indicators_are_caution_and_fast_trend_too() {
        let mut a = pt(0, 450_000.0);
        a.threads = Some(80.0);
        let report = assess(&[a]).unwrap();
        assert_eq!(report.level, Level::Caution);

        // Крутой тренд, но ещё не у жёсткого предела: caution, не warning.
        let fast = vec![pt(0, 1_100_000.0), pt(10_000, 1_200_000.0)];
        let report = assess(&fast).unwrap();
        assert_eq!(report.level, Level::Caution);
        assert!(report.ttf_s.unwrap() < 60);
    }
}
