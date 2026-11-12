//! Бортовой самописец: каждая строка журнала — звено хеш-цепочки.
//! Голову цепочки подписывает Ed25519. Секретный ключ лежит в файле
//! рядом с exe и никуда не печатается.

use ed25519_dalek::{Signature, Signer as SignBytes, SigningKey, Verifier};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// Писатель журнала и /verify делят один замок: строка и подпись головы
/// появляются вместе, иначе проверка ловит чужую голову.
static IO_LOCK: Mutex<()> = Mutex::new(());

pub fn io_lock() -> MutexGuard<'static, ()> {
    IO_LOCK.lock().unwrap_or_else(|err| err.into_inner())
}

pub const GENESIS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(Sha256::digest(bytes).as_slice())
}

/// Каноническая строка записи: JSON с отсортированными ключами, без поля `hash`.
pub fn canonical(value: &serde_json::Value) -> String {
    let mut v = value.clone();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("hash");
    }
    serde_json::to_string(&v).unwrap_or_else(|_| "{}".into())
}

pub fn hash_canonical(value: &serde_json::Value) -> String {
    sha256_hex(canonical(value).as_bytes())
}

pub fn stamp(ev: &crate::journal::Event, prev: &str) -> (String, String) {
    let mut ev = ev.clone();
    ev.prev_hash = prev.to_string();
    ev.hash.clear();
    let mut v = serde_json::to_value(&ev).unwrap_or_else(|_| serde_json::json!({}));
    if let Some(obj) = v.as_object_mut() {
        obj.remove("hash");
    }
    let hash = sha256_hex(canonical(&v).as_bytes());
    if let Some(obj) = v.as_object_mut() {
        obj.insert("hash".into(), serde_json::Value::String(hash.clone()));
    }
    let line = serde_json::to_string(&v).unwrap_or_else(|_| "{}".into());
    (line, hash)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = hex_val(b[i])?;
        let lo = hex_val(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub struct Signer {
    key: SigningKey,
}

impl Signer {
    pub fn load_or_create(path: &Path) -> io::Result<Self> {
        if path.exists() {
            let text = fs::read_to_string(path)?;
            let raw = hex_decode(text.trim()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "файл ключа повреждён")
            })?;
            if raw.len() != 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "файл ключа повреждён",
                ));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&raw);
            let key = SigningKey::from_bytes(&seed);
            seed.fill(0);
            return Ok(Self { key });
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(path)?;
            file.write_all(hex_encode(&seed).as_bytes())?;
        }
        let key = SigningKey::from_bytes(&seed);
        seed.fill(0);
        Ok(Self { key })
    }

    pub fn sign_hex(&self, message: &str) -> String {
        let sig = self.key.sign(message.as_bytes());
        hex_encode(&sig.to_bytes())
    }

    pub fn verify_message(key_path: &Path, message: &str, sig_hex: &str) -> bool {
        let Ok(text) = fs::read_to_string(key_path) else {
            return false;
        };
        let Some(raw) = hex_decode(text.trim()) else {
            return false;
        };
        if raw.len() != 32 {
            return false;
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        let key = SigningKey::from_bytes(&seed);
        let vk = key.verifying_key();
        seed.fill(0);
        let Some(bytes) = hex_decode(sig_hex) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&bytes) else {
            return false;
        };
        vk.verify(message.as_bytes(), &sig).is_ok()
    }
}

pub fn default_key_path() -> PathBuf {
    if let Ok(dir) = std::env::var("ENDOSCOPE_KEY_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("endoscope.key");
        }
    }
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("endoscope.key")))
        .unwrap_or_else(|| PathBuf::from("endoscope.key"))
}

pub fn sig_path_for(journal: &Path) -> PathBuf {
    let mut s = journal.as_os_str().to_owned();
    s.push(".sig");
    PathBuf::from(s)
}

pub fn write_sig(path: &Path, head: &str, sig_hex: &str) -> io::Result<()> {
    let tmp = path.with_extension("sig.tmp");
    {
        let mut file = OpenOptions::new().create(true).write(true).truncate(true).open(&tmp)?;
        writeln!(file, "{head}")?;
        writeln!(file, "{sig_hex}")?;
        file.flush()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub ok: bool,
    pub legacy: u64,
    pub chained: u64,
    pub head: String,
    pub signed: bool,
    pub reason: String,
    pub freezes: u64,
}

pub fn last_head(path: &Path) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return GENESIS.to_string();
    };
    let mut head = GENESIS.to_string();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(h) = v.get("hash").and_then(|x| x.as_str()) {
            if !h.is_empty() {
                head = h.to_string();
            }
        }
    }
    head
}

pub fn verify(journal: &Path, key_path: &Path) -> Report {
    let _guard = io_lock();
    verify_locked(journal, key_path)
}

fn verify_locked(journal: &Path, key_path: &Path) -> Report {
    let text = match fs::read_to_string(journal) {
        Ok(t) => t,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Report {
                ok: true,
                legacy: 0,
                chained: 0,
                head: GENESIS.into(),
                signed: true,
                reason: "журнал ещё пуст".into(),
                freezes: 0,
            };
        }
        Err(err) => {
            return Report {
                ok: false,
                legacy: 0,
                chained: 0,
                head: String::new(),
                signed: false,
                reason: format!("журнал не читается: {err}"),
                freezes: 0,
            };
        }
    };
    let mut expected = GENESIS.to_string();
    let mut legacy = 0u64;
    let mut chained = 0u64;
    let mut started = false;
    let mut reason = String::new();
    let mut ok = true;
    let mut freeze_checks = 0u64;
    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) if idx + 1 == text.lines().count() => continue,
            Err(_) => {
                ok = false;
                reason = format!("строка {} не json", idx + 1);
                break;
            }
        };
        let hash = value.get("hash").and_then(|x| x.as_str()).unwrap_or("");
        if hash.is_empty() {
            if started {
                ok = false;
                reason = format!("строка {} без хеша после начала цепочки", idx + 1);
                break;
            }
            legacy += 1;
            continue;
        }
        started = true;
        let prev = value.get("prev_hash").and_then(|x| x.as_str()).unwrap_or("");
        if prev != expected {
            ok = false;
            reason = format!("строка {} порвала цепочку", idx + 1);
            break;
        }
        let got = hash_canonical(&value);
        if got != hash {
            ok = false;
            reason = format!("строка {} не сходится с sha256", idx + 1);
            break;
        }
        if let Some(fh) = value.get("freeze_hash").and_then(|x| x.as_str()) {
            if !fh.is_empty() {
                freeze_checks += 1;
                let fp = value.get("freeze").and_then(|x| x.as_str()).unwrap_or("");
                match fs::read(fp) {
                    Ok(bytes) if sha256_hex(&bytes) == fh => {}
                    Ok(_) => {
                        ok = false;
                        reason = format!("заморозка {fp} не сходится с хешем");
                        break;
                    }
                    Err(_) => {
                        ok = false;
                        reason = format!("заморозка {fp} не читается");
                        break;
                    }
                }
            }
        }
        expected = hash.to_string();
        chained += 1;
    }
    let head = if chained == 0 { GENESIS.to_string() } else { expected };
    let signed = if !ok || chained == 0 {
        chained == 0 && ok
    } else {
        match fs::read_to_string(sig_path_for(journal)) {
            Ok(text) => {
                let mut lines = text.lines();
                let sig_head = lines.next().unwrap_or("").trim();
                let sig = lines.next().unwrap_or("").trim();
                sig_head == head && Signer::verify_message(key_path, &head, sig)
            }
            Err(_) => false,
        }
    };
    if ok && chained > 0 && !signed && reason.is_empty() {
        ok = false;
        reason = "подпись головы не сошлась".into();
    }
    if ok && reason.is_empty() {
        reason = "цепочка цела".into();
    }
    Report { ok, legacy, chained, head, signed, reason, freezes: freeze_checks }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_roundtrip_rejects_a_different_head() {
        let dir = std::env::temp_dir().join(format!(
            "endo-sig-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("endoscope.key");
        let signer = Signer::load_or_create(&path).unwrap();
        let again = Signer::load_or_create(&path).unwrap();
        let sig = signer.sign_hex("abc");
        assert!(Signer::verify_message(&path, "abc", &sig));
        assert!(again.sign_hex("abc") == sig || Signer::verify_message(&path, "abc", &again.sign_hex("abc")));
        assert!(!Signer::verify_message(&path, "abd", &sig));
        let _ = fs::remove_dir_all(&dir);
    }
}
