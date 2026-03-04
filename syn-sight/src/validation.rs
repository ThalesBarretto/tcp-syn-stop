// SPDX-License-Identifier: GPL-2.0-only
use std::net::Ipv4Addr;

/// Parse "ip/prefix" into (network_u32, prefix_len). Returns None on bad input.
pub fn parse_cidr(s: &str) -> Option<(u32, u8)> {
    let (ip_str, prefix_str) = s.trim().split_once('/')?;
    let addr: Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix == 0 || prefix > 32 {
        return None;
    }
    let mask = cidr_mask(prefix);
    Some((u32::from(addr) & mask, prefix))
}

/// Returns true if `inner` CIDR is fully contained within `outer` CIDR.
/// Both must be valid "ip/prefix" strings. Returns false on parse failure.
pub fn cidr_contains(outer: &str, inner: &str) -> bool {
    let Some((outer_net, outer_prefix)) = parse_cidr(outer) else {
        return false;
    };
    let Some((inner_net, inner_prefix)) = parse_cidr(inner) else {
        return false;
    };
    // inner must have equal or longer prefix (narrower or same range)
    // and inner's network, masked to outer's prefix, must equal outer's network
    inner_prefix >= outer_prefix && (inner_net & cidr_mask(outer_prefix)) == outer_net
}

fn cidr_mask(prefix: u8) -> u32 {
    if prefix == 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - prefix)) - 1)
    }
}

/// Validate all entries in a config file. Returns (valid_count, errors).
pub fn validate_config_file(path: &str) -> (usize, Vec<String>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (0, Vec::new()), // File missing is not an error (may not exist yet)
    };
    let mut valid = 0;
    let mut errors = Vec::new();
    for (i, raw_line) in content.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        match validate_cidr(line) {
            Ok(_) => valid += 1,
            Err(e) => errors.push(format!("{}:{}: {}", path, i + 1, e)),
        }
    }
    (valid, errors)
}

pub fn validate_cidr(input: &str) -> Result<String, String> {
    let input = input.trim();
    let (ip_str, prefix_str) = input
        .split_once('/')
        .ok_or_else(|| "Missing /prefix (e.g. 10.0.0.0/24)".to_string())?;

    let addr: Ipv4Addr = ip_str.parse().map_err(|_| format!("Invalid IP: {}", ip_str))?;

    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| format!("Invalid prefix: {}", prefix_str))?;

    if prefix == 0 {
        return Err("/0 prefix not allowed".to_string());
    }
    if prefix > 32 {
        return Err("Prefix must be 1-32".to_string());
    }

    let ip_u32 = u32::from(addr);
    let mask = cidr_mask(prefix);
    if ip_u32 & mask != ip_u32 {
        return Err(format!(
            "Host bits set: {} should be {}/{}",
            input,
            Ipv4Addr::from(ip_u32 & mask),
            prefix
        ));
    }

    Ok(format!("{}/{}", addr, prefix))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_cidr_valid() {
        assert_eq!(validate_cidr("10.0.0.0/24").unwrap(), "10.0.0.0/24");
        assert_eq!(validate_cidr("192.168.1.0/32").unwrap(), "192.168.1.0/32");
        assert_eq!(validate_cidr(" 10.0.0.0/8 ").unwrap(), "10.0.0.0/8");
    }

    #[test]
    fn test_validate_cidr_host_bits_set() {
        assert!(validate_cidr("10.0.0.1/24").is_err());
    }

    #[test]
    fn test_validate_cidr_slash_zero() {
        assert!(validate_cidr("0.0.0.0/0").is_err());
    }

    #[test]
    fn test_validate_cidr_missing_prefix() {
        assert!(validate_cidr("10.0.0.0").is_err());
    }

    #[test]
    fn test_validate_cidr_invalid_ip() {
        assert!(validate_cidr("999.0.0.0/24").is_err());
    }

    #[test]
    fn test_validate_cidr_prefix_too_large() {
        assert!(validate_cidr("10.0.0.0/33").is_err());
    }

    // --- parse_cidr ---

    #[test]
    fn test_parse_cidr_valid() {
        assert_eq!(parse_cidr("10.0.0.0/24"), Some((0x0A000000, 24)));
        assert_eq!(parse_cidr("192.168.1.0/32"), Some((0xC0A80100, 32)));
        assert_eq!(parse_cidr("10.0.0.0/8"), Some((0x0A000000, 8)));
    }

    #[test]
    fn test_parse_cidr_masks_host_bits() {
        // 10.0.0.1/24 → network is 10.0.0.0
        assert_eq!(parse_cidr("10.0.0.1/24"), Some((0x0A000000, 24)));
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert_eq!(parse_cidr("garbage"), None);
        assert_eq!(parse_cidr("10.0.0.0/0"), None);
        assert_eq!(parse_cidr("10.0.0.0/33"), None);
        assert_eq!(parse_cidr("999.0.0.0/24"), None);
    }

    // --- cidr_contains ---

    #[test]
    fn test_cidr_contains_exact_match() {
        assert!(cidr_contains("10.0.0.0/24", "10.0.0.0/24"));
    }

    #[test]
    fn test_cidr_contains_subset() {
        assert!(cidr_contains("10.0.0.0/16", "10.0.0.0/24"));
        assert!(cidr_contains("10.0.0.0/24", "10.0.0.1/32"));
    }

    #[test]
    fn test_cidr_contains_superset_not_contained() {
        assert!(!cidr_contains("10.0.0.0/24", "10.0.0.0/16"));
        assert!(!cidr_contains("10.0.0.1/32", "10.0.0.0/24"));
    }

    #[test]
    fn test_cidr_contains_disjoint() {
        assert!(!cidr_contains("10.0.0.0/24", "10.0.1.0/24"));
        assert!(!cidr_contains("192.168.0.0/16", "10.0.0.0/8"));
    }

    #[test]
    fn test_cidr_contains_invalid_input() {
        assert!(!cidr_contains("garbage", "10.0.0.0/24"));
        assert!(!cidr_contains("10.0.0.0/24", "garbage"));
    }

    // --- validate_config_file ---

    #[test]
    fn test_validate_config_file_missing() {
        let (valid, errors) = validate_config_file("/nonexistent/path");
        assert_eq!(valid, 0);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_config_file_valid() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "10.0.0.0/24\n192.168.0.0/16\n# comment\n").unwrap();
        let (valid, errors) = validate_config_file(tmp.path().to_str().unwrap());
        assert_eq!(valid, 2);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_validate_config_file_with_errors() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "10.0.0.0/24\ngarbage\n10.0.0.1/24\n").unwrap();
        let (valid, errors) = validate_config_file(tmp.path().to_str().unwrap());
        assert_eq!(valid, 1); // only 10.0.0.0/24 is valid
        assert_eq!(errors.len(), 2); // "garbage" (no prefix) + "10.0.0.1/24" (host bits)
    }
}
