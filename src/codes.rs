//! Каталог кодов отказа в духе OBD-II / UDS.
//! Буква — система, дальше класс и номер. Статусы: pending, confirmed, permanent.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Code {
    pub code: &'static str,
    pub title: &'static str,
}

pub const CATALOG: &[Code] = &[
    Code { code: "E0101", title: "процесс завершился с ненулевым кодом" },
    Code { code: "E0102", title: "агент исчез: процесса нет, код выхода неизвестен или ноль" },
    Code { code: "E0103", title: "бюджет перезапусков исчерпан, цель больше не наблюдаем" },
    Code { code: "E0201", title: "устройство или каталог наблюдения отключились" },
    Code { code: "A0102", title: "агент заявил успех, код выхода не ноль" },
    Code { code: "F0301", title: "каталог залит событиями и исключён из наблюдения" },
    Code { code: "S0001", title: "канал ETW оборвался, сенсор один раз перешёл на опрос" },
];

#[cfg_attr(not(test), allow(dead_code))]
pub fn known(code: &str) -> bool {
    CATALOG.iter().any(|c| c.code == code)
}

pub fn title(code: &str) -> &'static str {
    CATALOG
        .iter()
        .find(|c| c.code == code)
        .map(|c| c.title)
        .unwrap_or("неизвестный код")
}

/// Постоянный статус не понижается более поздним pending.
pub fn merge_status(prev: &str, next: &str) -> String {
    if prev == "permanent" || next.is_empty() {
        return prev.to_string();
    }
    if next == "permanent" || prev.is_empty() || prev == "pending" && next == "confirmed" {
        return next.to_string();
    }
    if prev == "confirmed" && next == "pending" {
        return prev.to_string();
    }
    next.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_the_owner_codes() {
        for code in ["E0101", "E0201", "A0102", "F0301", "S0001"] {
            assert!(known(code), "{code}");
            assert!(!title(code).is_empty());
        }
    }

    #[test]
    fn permanent_status_sticks() {
        assert_eq!(merge_status("permanent", "pending"), "permanent");
        assert_eq!(merge_status("pending", "confirmed"), "confirmed");
        assert_eq!(merge_status("confirmed", "permanent"), "permanent");
        assert_eq!(merge_status("confirmed", "pending"), "confirmed");
    }
}
