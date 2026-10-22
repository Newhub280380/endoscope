//! Адреса IPv4 из Windows.
//!
//! И `GetExtendedTcpTable`, и Microsoft-Windows-Kernel-Network кладут IPv4
//! в DWORD так, что байты в памяти идут в сетевом порядке. На little-endian
//! это число читается перевёрнутым: 127.0.0.1 становится 0x0100007F, и сдвиг
//! со старшего байта печатает 1.0.0.127. Берём байты числа в little-endian
//! порядке — это и есть исходная четвёрка.
//!
//! Порт в том же DWORD/WORD лежит в сетевом порядке.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::Ipv4Addr;

pub fn format_ipv4(dword: u32) -> String {
    Ipv4Addr::from(dword.to_le_bytes()).to_string()
}

pub fn decode_port(port: u16) -> u16 {
    u16::from_be(port)
}

pub fn format_ipv4_endpoint(dword: u32, port: u16) -> String {
    format!("{}:{}", format_ipv4(dword), decode_port(port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_reversed(ip: u32) -> String {
        format!(
            "{}.{}.{}.{}",
            (ip >> 24) & 0xff,
            (ip >> 16) & 0xff,
            (ip >> 8) & 0xff,
            ip & 0xff
        )
    }

    #[test]
    fn loopback_is_not_byte_reversed() {
        let dword = 0x0100_007f;
        assert_eq!(legacy_reversed(dword), "1.0.0.127");
        assert_eq!(format_ipv4(dword), "127.0.0.1");
    }

    #[test]
    fn dotted_quad_round_trip() {
        assert_eq!(format_ipv4(0x0808_0808), "8.8.8.8");
        assert_eq!(format_ipv4(0x2914_020a), "10.2.20.41");
        assert_eq!(format_ipv4(0), "0.0.0.0");
    }

    #[test]
    fn ports_are_network_order() {
        assert_eq!(decode_port(0x5000), 80);
        assert_eq!(decode_port(0xbb01), 443);
        assert_eq!(format_ipv4_endpoint(0x0100_007f, 0x5000), "127.0.0.1:80");
    }
}
