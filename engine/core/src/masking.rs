//! Masks, hashes and placeholders. No more than 4 characters of a value ever leave this module.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::tables;
use crate::uni;

const LAST4_RULES: [&str; 6] = ["PII_CREDIT_CARD", "PII_AADHAAR", "PII_SSN", "PII_PHONE", "PII_PAN", "PII_IBAN"];

/// First 12 hex characters of `HMAC-SHA256(salt, value)`.
pub fn hash12(value: &str, salt: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC takes a key of any length");
    mac.update(value.as_bytes());
    let digest = mac.finalize().into_bytes();
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

pub fn mask_secret(value: &str) -> String {
    let n = uni::len(value);
    if n >= 20 {
        format!("{}... (len {n})", uni::prefix_chars(value, 4))
    } else {
        format!("... (len {n})")
    }
}

pub fn mask_email(value: &str) -> String {
    match value.split_once('@') {
        Some((local, domain)) if !local.is_empty() && !domain.is_empty() => {
            format!("{}***@{domain}", local.chars().next().unwrap())
        }
        _ => mask_secret(value),
    }
}

fn is_py_space(c: char) -> bool {
    tables::SPACE.contains(&(c as u32))
}

/// Spaces and dashes are removed first; 4 characters or fewer show nothing.
pub fn mask_last4(value: &str) -> String {
    let compact: String = value.chars().filter(|&c| !is_py_space(c) && c != '-').collect();
    if uni::len(&compact) > 4 {
        format!("****{}", uni::suffix_chars(&compact, 4))
    } else {
        "****".to_string()
    }
}

/// The display mask for a match of `rule_id`.
pub fn mask_for(rule_id: &str, value: &str) -> String {
    if rule_id == "PII_EMAIL" {
        mask_email(value)
    } else if LAST4_RULES.contains(&rule_id) {
        mask_last4(value)
    } else {
        mask_secret(value)
    }
}

/// `[PII:<TYPE>]` for personal data, `[REDACTED:<rule_id>:<hash12>]` otherwise.
pub fn placeholder_for(rule_id: &str, hash: &str) -> String {
    match rule_id.strip_prefix("PII_") {
        Some(kind) => format!("[PII:{kind}]"),
        None => format!("[REDACTED:{rule_id}:{hash}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_match_the_reference() {
        assert_eq!(mask_secret("abcdefghijklmnopqrstuv"), "abcd... (len 22)");
        assert_eq!(mask_secret("short"), "... (len 5)");
        assert_eq!(mask_email("jordan@acme.invalid"), "j***@acme.invalid");
        assert_eq!(mask_last4("4111 1111 1111 1111"), "****1111");
        assert_eq!(mask_last4("1-2"), "****");
        assert_eq!(placeholder_for("PII_EMAIL", "x"), "[PII:EMAIL]");
        assert_eq!(placeholder_for("SEC_JWT", "0123456789ab"), "[REDACTED:SEC_JWT:0123456789ab]");
    }

    #[test]
    fn hash12_is_hmac_sha256() {
        // python: hmac.new(b"s"*32, b"abc", "sha256").hexdigest()[:12]
        assert_eq!(hash12("abc", &[b's'; 32]), "b0f19dfebace"); // masking.hash12("abc", b"s" * 32)
    }
}
