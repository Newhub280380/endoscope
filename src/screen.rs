//! Экран «кино» на 127.0.0.1:7095 + ДЕТЕКТОР ЛЖИ.
//! Логика перенесена из v0.7 без изменений: тот же JSON, тот же вердикт,
//! та же страница. Работает одинаково под Linux и Windows.

use std::io::{Read, Write};
use std::net::TcpListener;

/// Путь в том виде, в каком он лежит в JSON-журнале:
/// обратные слэши экранированы, а на Windows регистр не важен.
fn needle(path: &str) -> String {
    let escaped = path.replace('\\', "\\\\").replace('"', "\\\"");
    if cfg!(target_os = "windows") {
        escaped.to_lowercase()
    } else {
        escaped
    }
}

/// Строка журнала в том же «регистре», что и needle.
fn norm_line(line: &str) -> String {
    if cfg!(target_os = "windows") {
        line.to_lowercase()
    } else {
        line.to_string()
    }
}

/// Экранирование строки для вставки в JSON (Windows-пути содержат обратные слэши).
fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Вытаскиваем пути из заявления: unix-пути (/...) и windows-пути (C:\... или C:/...).
fn extract_paths(claim: &str) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    for word in claim.split_whitespace() {
        let w = word.trim_matches(|c: char| c == ',' || c == '.' || c == '"' || c == '\'' || c == ')' || c == '(');
        let b = w.as_bytes();
        let unix = w.starts_with('/') && w.len() > 4;
        let win = b.len() > 4
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (w.contains('\\') || w.contains('/'));
        if (unix || win) && !paths.iter().any(|p| p == w) {
            paths.push(w.to_string());
        }
    }
    paths
}

pub fn start_screen(journal_path: String) {
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
            let mut buf = [0u8; 8192];
            let _ = stream.read(&mut buf);
            let req = String::from_utf8_lossy(&buf).to_string();
            let first = req.lines().next().unwrap_or("").to_string();
            let (body, ctype) = if first.starts_with("GET /events") {
                (events_json(&journal_path), "application/json")
            } else if first.starts_with("GET /health") {
                (health_json(&journal_path), "application/json")
            } else if first.starts_with("GET /frame") {
                (frame_json(&journal_path), "application/json")
            } else if first.starts_with("GET /check?path=") {
                let raw = first.trim_start_matches("GET /check?path=");
                let raw = raw.split(' ').next().unwrap_or("");
                (check_json(&journal_path, &url_decode(raw)), "application/json")
            } else if first.starts_with("GET /verify") {
                (verify_json(&journal_path), "application/json")
            } else if first.starts_with("GET /codes") {
                (codes_json(&journal_path), "application/json")
            } else if first.starts_with("GET /precursors") {
                (precursors_json(&journal_path), "application/json")
            } else if first.starts_with("GET /lie?claim=") {
                let raw = first.trim_start_matches("GET /lie?claim=");
                let raw = raw.split(' ').next().unwrap_or("");
                (lie_json(&journal_path, &url_decode(raw)), "application/json")
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

pub fn url_decode(s: &str) -> String {
    let mut out: Vec<u8> = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        if b[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(b[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

pub fn load_lines(journal_path: &str) -> Vec<String> {
    std::fs::read_to_string(journal_path)
        .unwrap_or_default()
        .lines()
        .map(|l| l.to_string())
        .filter(|l| !l.trim().is_empty() && !l.contains("\"heartbeat\""))
        .collect()
}

pub fn verify_json(journal_path: &str) -> String {
    let report = crate::chain::verify(
        std::path::Path::new(journal_path),
        &crate::chain::default_key_path(),
    );
    serde_json::json!({
        "ok": report.ok,
        "legacy": report.legacy,
        "chained": report.chained,
        "head": report.head,
        "signed": report.signed,
        "freezes": report.freezes,
        "reason": report.reason,
    })
    .to_string()
}

pub fn codes_json(journal_path: &str) -> String {
    let mut active: Vec<serde_json::Value> = Vec::new();
    let mut index: std::collections::HashMap<(String, u32), usize> = std::collections::HashMap::new();
    for line in load_lines(journal_path) {
        let Ok(ev) = serde_json::from_str::<crate::journal::Event>(&line) else {
            continue;
        };
        if ev.code.is_empty() {
            continue;
        }
        let key = (ev.code.clone(), ev.pid);
        let row = serde_json::json!({
            "code": ev.code,
            "title": crate::codes::title(&ev.code),
            "status": ev.status,
            "pid": ev.pid,
            "ts": ev.ts,
            "agent": ev.agent,
            "votes": ev.votes,
            "freeze": ev.freeze,
            "detail": ev.detail,
        });
        if let Some(slot) = index.get(&key) {
            let prev = active[*slot]["status"].as_str().unwrap_or("");
            let merged = crate::codes::merge_status(prev, &ev.status);
            active[*slot] = row;
            active[*slot]["status"] = serde_json::Value::String(merged);
        } else {
            index.insert(key, active.len());
            active.push(row);
        }
    }
    let catalog: Vec<serde_json::Value> = crate::codes::CATALOG
        .iter()
        .map(|c| serde_json::json!({"code": c.code, "title": c.title}))
        .collect();
    serde_json::json!({"ok": true, "catalog": catalog, "active": active}).to_string()
}

pub fn precursors_json(journal_path: &str) -> String {
    let mut latest: Vec<serde_json::Value> = Vec::new();
    let mut index: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for line in load_lines(journal_path) {
        let Ok(ev) = serde_json::from_str::<crate::journal::Event>(&line) else {
            continue;
        };
        if ev.kind != "precursor" {
            continue;
        }
        let row = serde_json::json!({
            "ts": ev.ts,
            "pid": ev.pid,
            "agent": ev.agent,
            "level": ev.level,
            "ttf_s": ev.ttf_s,
            "indicators": ev.indicators,
            "detail": ev.detail,
        });
        if let Some(slot) = index.get(&ev.pid) {
            latest[*slot] = row;
        } else {
            index.insert(ev.pid, latest.len());
            latest.push(row);
        }
    }
    serde_json::json!({"ok": true, "precursors": latest}).to_string()
}

/// Какой глаз пишет журнал прямо сейчас.
pub fn health_json(journal_path: &str) -> String {
    serde_json::json!({
        "ok": true,
        "version": crate::version::VERSION,
        "mode": crate::mode::name(),
        "journal": journal_path,
    })
    .to_string()
}

/// Живой кадр: процессы и слушающие порты сейчас, плюс хвост журнала.
/// Поля `pid`/`cmd`/`agent` у процесса — как в 0.8.1 (`agent` остаётся классом).
/// Рядом добавлены `image` и `ppid`.
pub fn frame_json(journal_path: &str) -> String {
    let procs: Vec<serde_json::Value> = crate::plat::snapshot_procs()
        .into_iter()
        .map(|p| {
            serde_json::json!({
                "pid": p.pid,
                "cmd": p.cmd,
                "agent": p.agent,
                "image": p.image,
                "ppid": p.ppid,
            })
        })
        .collect();
    let listens: Vec<serde_json::Value> = crate::plat::snapshot_listens()
        .into_iter()
        .map(|l| {
            serde_json::json!({
                "pid": l.pid,
                "port": l.port,
                "local": l.local,
            })
        })
        .collect();
    let events: serde_json::Value =
        serde_json::from_str(&events_json(journal_path)).unwrap_or(serde_json::json!([]));
    serde_json::json!({
        "ok": true,
        "version": crate::version::VERSION,
        "mode": crate::mode::name(),
        "journal": journal_path,
        "procs": procs,
        "listens": listens,
        "events": events,
    })
    .to_string()
}

/// Последние 100 фактов журнала — свежие сверху, готовым JSON-массивом.
pub fn events_json(journal_path: &str) -> String {
    let mut lines = load_lines(journal_path);
    if lines.len() > 100 {
        lines = lines.split_off(lines.len() - 100);
    }
    lines.reverse();
    format!("[{}]", lines.join(","))
}

/// ПРАВДА ПО ПУТИ: все факты, где путь всплывает.
pub fn check_json(journal_path: &str, query: &str) -> String {
    let q = query.trim();
    let nd = needle(q);
    let mut hits: Vec<String> = load_lines(journal_path)
        .into_iter()
        .filter(|l| q.len() > 3 && norm_line(l).contains(&nd))
        .collect();
    let n_touched = hits
        .iter()
        .filter(|l| {
            l.contains("file_create") || l.contains("file_write") || l.contains("file_delete")
        })
        .count();
    let (verdict, red) = if q.len() < 4 {
        ("Введите путь целиком (минимум 4 символа)".to_string(), false)
    } else if n_touched > 0 {
        (format!("ФАЙЛ ТРОГАЛИ: найдено фактов {}", n_touched), true)
    } else {
        ("По дневнику это НЕ трогали — чисто".to_string(), false)
    };
    let mut shown = if hits.len() > 100 {
        hits.split_off(hits.len() - 100)
    } else {
        hits
    };
    shown.reverse();
    format!(
        "{{\"verdict\":\"{}\",\"touched\":{},\"events\":[{}]}}",
        verdict.replace('"', "'"),
        n_touched,
        shown.join(",")
    )
}

/// ДЕТЕКТОР ЛЖИ: сверка заявления с дневником правды.
/// Заявление вида "я не трогал /home/alexandr/hub/paragon_monitor.py"
/// вытаскиваем все пути и сверяем с фактами.
pub fn lie_json(journal_path: &str, claim: &str) -> String {
    let lines = load_lines(journal_path);
    let claim_l = claim.to_lowercase();
    let denies = claim_l.contains("не трогал") || claim_l.contains("не менял")
        || claim_l.contains("ничего не делал") || claim_l.contains("не создавал")
        || claim_l.contains("не удалял");
    // вытаскиваем пути из заявления: unix (/...) и windows (C:\...)
    let paths = extract_paths(claim);
    let mut items: Vec<String> = Vec::new();
    let mut lies = 0;
    let mut truths = 0;
    for p in &paths {
        let nd = needle(p);
        let touched: Vec<&String> = lines
            .iter()
            .filter(|l| {
                norm_line(l).contains(&nd)
                    && (l.contains("file_create") || l.contains("file_write") || l.contains("file_delete"))
            })
            .collect();
        let n = touched.len();
        let fact = n > 0;
        if denies && fact {
            lies += 1;
        } else if fact {
            truths += 1;
        }
        let status = if denies {
            if fact { "СОВРАЛ" } else { "ПРАВДА" }
        } else if fact {
            "ПОДТВЕРЖДЕНО"
        } else {
            "НЕ НАЙДЕНО"
        };
        let proof = if n > 0 {
            touched
                .iter()
                .rev()
                .take(3)
                .map(|l| l.replace('"', "'"))
                .collect::<Vec<_>>()
                .join(" | ")
        } else {
            String::new()
        };
        items.push(format!(
            "{{\"path\":\"{}\",\"status\":\"{}\",\"facts\":{},\"proof\":\"{}\"}}",
            json_escape(p),
            status,
            n,
            json_escape(&proof)
        ));
    }
    let verdict = if lies > 0 {
        format!("ВРАНЬЁ ОБНАРУЖЕНО: {} из {} пунктов противоречат дневнику", lies, items.len())
    } else if items.is_empty() {
        "В заявлении нет путей для проверки — вставь текст с путями файлов".to_string()
    } else {
        format!("Заявление не противоречит дневнику ({} пунктов проверено)", items.len())
    };
    format!(
        "{{\"verdict\":\"{}\",\"lies\":{},\"items\":[{}]}}",
        verdict.replace('"', "'"),
        lies,
        items.join(",")
    )
}

pub const PAGE: &str = r#"<!DOCTYPE html>
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
 .lie{border:1px solid #30363d;border-radius:6px;padding:10px 14px;margin:10px 0}
 .lie .path{color:#e6edf3;font-size:13px;word-break:break-all}
 .lie .st{font-weight:700;margin-right:8px}
 .st-СОВРАЛ{color:#f85149}.st-ПРАВДА{color:#3fb950}.st-ПОДТВЕРЖДЕНО{color:#58a6ff}.st-НЕ_НАЙДЕНО{color:#8b949e}
 .lie .proof{color:#8b949e;font-size:12px;margin-top:4px;word-break:break-all}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th{position:sticky;top:0;background:#161b22;text-align:left;padding:8px;color:#8b949e}
 td{padding:6px 8px;border-top:1px solid #21262d;word-break:break-all}
 .spawn{color:#58a6ff}.connect{color:#3fb950}.file_create{color:#d29922}
 .file_write{color:#e3b341}.file_delete{color:#f85149}.exit{color:#8b949e}
 .agent{color:#bc8cff}.time{color:#8b949e;white-space:nowrap}
 #wrap{max-width:1100px;margin:0 auto}
</style></head><body><div id="wrap">
<h1><span class="dot"></span>ЭНДОСКОП — живая правда</h1>
<div class="sub">Что реально делали процессы и агенты. Лента обновляется каждые 2 секунды. <span id="mode"></span></div>
<div><input id="q" placeholder="введи путь к файлу — проверить, трогали ли его">
<button onclick="check()">ПРОВЕРИТЬ</button></div>
<div id="verdict"></div>
<div class="lie" style="background:#161b22">
 <div style="color:#8b949e;font-size:13px;margin-bottom:6px">ДЕТЕКТОР ЛЖИ: вставь заявление агента (например: «я не трогал /путь/файл»)</div>
 <input id="claim" placeholder="заявление агента для проверки">
 <button onclick="lie()">СВЕРИТЬ С ПРАВДОЙ</button>
 <div id="lieverdict"></div>
 <div id="lieitems"></div>
</div>
<table><thead><tr><th>Время</th><th>Что</th><th>Кто</th><th>Деталь</th></tr></thead>
<tbody id="rows"></tbody></table></div>
<script>
function fmt(ts){const d=new Date(ts);return d.toLocaleTimeString('ru-RU')}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}
const RU={spawn:'запуск',exit:'выход',connect:'связь',file_create:'файл создан',file_write:'файл переписан',file_delete:'файл удалён'};
function who(e){const name=e.image||e.agent||'';const parent=e.ppid?(' ppid '+e.ppid):'';return esc(name)+' #'+(e.pid||0)+parent}
function row(e){return '<tr><td class="time">'+fmt(e.ts)+'</td><td class="'+e.kind+'">'+(RU[e.kind]||e.kind)+'</td><td class="agent">'+who(e)+'</td><td>'+esc(e.detail)+'</td></tr>'}
async function tick(){
 try{
  const h=await fetch('/health');const d=await h.json();
  document.getElementById('mode').textContent='режим: '+(d.mode||'');
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
  v.textContent=d.verdict;
  document.getElementById('rows').innerHTML=d.events.map(row).join('');
 }catch(e){v.className='red';v.textContent='ошибка проверки'}
}
async function lie(){
 const c=document.getElementById('claim').value.trim();
 if(!c)return;
 const v=document.getElementById('lieverdict');
 try{
  const r=await fetch('/lie?claim='+encodeURIComponent(c));const d=await r.json();
  v.className=d.lies>0?'red':'green';v.style.display='block';v.style.margin='10px 0';v.style.padding='10px 14px';v.style.borderRadius='6px';v.style.fontWeight='600';
  v.textContent=d.verdict;
  document.getElementById('lieitems').innerHTML=(d.items||[]).map(i=>
   '<div class="lie"><span class="st st-'+i.status+'">'+i.status+'</span>'+
   '<span class="path">'+esc(i.path)+'</span>'+
   (i.proof?'<div class="proof">доказательство: '+esc(i.proof)+'</div>':'')+
   '</div>').join('');
 }catch(e){v.className='red';v.textContent='ошибка сверки'}
}
tick();
</script></body></html>"#;
