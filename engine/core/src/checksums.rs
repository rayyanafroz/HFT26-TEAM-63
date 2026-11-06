//! Luhn (cards), Verhoeff (Aadhaar) and mod-97 (IBAN). Bad input is `false`, never a panic.

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// ASCII digits only: `str.isdigit` alone would also take a superscript 2.
fn ascii_digits(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(s.bytes().map(|b| b - b'0').collect())
}

pub fn luhn_valid(s: &str) -> bool {
    let Some(digits) = ascii_digits(s) else { return false };
    if digits.len() < 2 {
        return false;
    }
    let mut total = 0u32;
    for (i, &d) in digits.iter().rev().enumerate() {
        let d = u32::from(d);
        total += if i % 2 == 1 { if d > 4 { d * 2 - 9 } else { d * 2 } } else { d };
    }
    total % 10 == 0
}

pub fn verhoeff_valid(s: &str) -> bool {
    let Some(digits) = ascii_digits(s) else { return false };
    if digits.len() < 2 {
        return false;
    }
    let mut check = 0usize;
    for (i, &d) in digits.iter().rev().enumerate() {
        check = VERHOEFF_D[check][VERHOEFF_P[i % 8][d as usize] as usize] as usize;
    }
    check == 0
}

/// `^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$` and mod-97 == 1. Python's `\d` and `$` are honoured: Unicode
/// digits pass the shape check but the mod-97 step then fails, and a trailing newline is allowed.
pub fn iban_valid(s: &str) -> bool {
    let body = s.strip_suffix('\n').unwrap_or(s);
    let chars: Vec<char> = body.chars().collect();
    if chars.len() < 15 || chars.len() > 34 {
        return false;
    }
    if !chars[..2].iter().all(|c| c.is_ascii_uppercase()) || !chars[2..4].iter().all(|&c| crate::uni::is_nd(c)) {
        return false;
    }
    if !chars[4..].iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
        return false;
    }
    // int(char, 36) on every character of text[4:] + text[:4], where text is the whole string.
    let all: Vec<char> = s.chars().collect();
    let rotated = all[4..].iter().chain(all[..4].iter());
    let mut remainder: u64 = 0;
    for &c in rotated {
        // int(char, 36) also reads any Unicode decimal digit ("GB٨٢..." reaches here through Python's \d).
        let v = match c.to_digit(36).or_else(|| crate::uni::nd_value(c)) {
            Some(v) => u64::from(v),
            None => return false,
        };
        remainder = if v >= 10 { (remainder * 100 + v) % 97 } else { (remainder * 10 + v) % 97 };
    }
    remainder == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_values() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
        assert!(verhoeff_valid("2363"));
        assert!(!verhoeff_valid("2364"));
        assert!(iban_valid("GB82WEST12345698765432"));
        assert!(!iban_valid("GB82WEST12345698765433"));
        assert!(!luhn_valid("4") && !luhn_valid("") && !luhn_valid("41a1"));
    }
}
