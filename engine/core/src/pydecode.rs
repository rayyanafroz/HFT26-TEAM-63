//! Decoders that behave like CPython's: `binascii.a2b_base64` (strict and lenient), `binascii.unhexlify`,
//! `bytes.decode("utf-8")`, and the part of `json.loads` the JWT check needs.

/// `binascii.a2b_base64(data, strict_mode=strict)`. `Err` wherever CPython raises `binascii.Error`.
///
/// CPython 3.14's lenient mode skips every `=` and every character outside the alphabet; padding is only
/// checked at the end, where enough `=` must follow the last data character. (Older versions stopped at
/// the first complete pad sequence; the fuzzer in conformance/fuzz.py checks this against the real thing.)
pub fn a2b_base64(data: &[u8], strict: bool) -> Result<Vec<u8>, ()> {
    if !strict {
        return a2b_base64_lenient(data);
    }
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    if strict && data.first() == Some(&b'=') {
        return Err(()); // leading padding
    }
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 3);
    let mut quad_pos = 0u8;
    let mut left: u8 = 0;
    let mut pads = 0u32;
    let mut padding_started = false;
    for (i, &c) in data.iter().enumerate() {
        if c == b'=' {
            padding_started = true;
            if strict && quad_pos == 0 {
                return Err(()); // excess padding
            }
            if quad_pos >= 2 {
                pads += 1;
                if u32::from(quad_pos) + pads >= 4 {
                    if strict && i + 1 < data.len() {
                        return Err(()); // excess data after padding
                    }
                    return Ok(out);
                }
            }
            continue;
        }
        let Some(v) = value(c) else {
            if strict {
                return Err(()); // only base64 data is allowed
            }
            continue;
        };
        if strict && padding_started {
            return Err(()); // discontinuous padding
        }
        pads = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = v;
            }
            1 => {
                quad_pos = 2;
                out.push((left << 2) | (v >> 4));
                left = v & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((left << 4) | (v >> 2));
                left = v & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((left << 6) | v);
                left = 0;
            }
        }
    }
    if quad_pos != 0 {
        return Err(()); // one extra character, or incorrect padding
    }
    Ok(out)
}

fn base64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

fn a2b_base64_lenient(data: &[u8]) -> Result<Vec<u8>, ()> {
    let mut out = Vec::with_capacity(data.len() / 4 * 3 + 3);
    let mut quad_pos = 0u8;
    let mut left: u8 = 0;
    let mut pads_after = 0usize;
    for &c in data {
        if c == b'=' {
            pads_after += 1;
            continue;
        }
        let Some(v) = base64_value(c) else { continue };
        pads_after = 0;
        match quad_pos {
            0 => {
                quad_pos = 1;
                left = v;
            }
            1 => {
                quad_pos = 2;
                out.push((left << 2) | (v >> 4));
                left = v & 0x0f;
            }
            2 => {
                quad_pos = 3;
                out.push((left << 4) | (v >> 2));
                left = v & 0x03;
            }
            _ => {
                quad_pos = 0;
                out.push((left << 6) | v);
                left = 0;
            }
        }
    }
    match quad_pos {
        0 => Ok(out),
        1 => Err(()),
        q if pads_after >= usize::from(4 - q) => Ok(out),
        _ => Err(()),
    }
}

/// `binascii.unhexlify`.
pub fn unhexlify(text: &str) -> Result<Vec<u8>, ()> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(());
    }
    bytes
        .chunks(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|_| ())?;
            u8::from_str_radix(s, 16).map_err(|_| ())
        })
        .collect()
}

/// Why `json.loads` gave up: a syntax error (`ValueError`), or nesting deep enough that CPython would
/// raise `RecursionError` (its limit depends on the C stack; about 52,000 levels on a typical build).
#[derive(Debug, PartialEq)]
pub enum JsonError {
    Invalid,
    TooDeep,
}

pub const JSON_MAX_DEPTH: usize = 50_000;

/// `json.loads(raw)` on bytes, answering only whether the result is an object with key `key`.
/// The parser keeps its own stack, so hostile nesting cannot overflow the thread (or WebAssembly) stack.
pub fn json_object_has_key(raw: &[u8], key: &str) -> Result<bool, JsonError> {
    let text = decode_json_bytes(raw).ok_or(JsonError::Invalid)?;
    let want: Vec<u32> = key.chars().map(|c| c as u32).collect();
    let mut p = Parser { s: &text, i: 0 };
    let found = p.document(&want)?;
    p.skip_ws();
    if p.i != p.s.len() {
        return Err(JsonError::Invalid);
    }
    Ok(found)
}

/// `json.detect_encoding` and `bytes.decode(encoding, "surrogatepass")`, as code points.
fn decode_json_bytes(b: &[u8]) -> Option<Vec<u32>> {
    let utf32 = |b: &[u8], le: bool| -> Option<Vec<u32>> {
        if b.len() % 4 != 0 {
            return None;
        }
        b.chunks(4)
            .map(|c| {
                let v = if le { u32::from_le_bytes([c[0], c[1], c[2], c[3]]) } else { u32::from_be_bytes([c[0], c[1], c[2], c[3]]) };
                (v <= 0x10FFFF).then_some(v)
            })
            .collect()
    };
    let utf16 = |b: &[u8], le: bool| -> Option<Vec<u32>> {
        if b.len() % 2 != 0 {
            return None;
        }
        let units: Vec<u16> = b.chunks(2).map(|c| if le { u16::from_le_bytes([c[0], c[1]]) } else { u16::from_be_bytes([c[0], c[1]]) }).collect();
        let mut out = Vec::with_capacity(units.len());
        let mut i = 0;
        while i < units.len() {
            let u = u32::from(units[i]);
            if (0xD800..0xDC00).contains(&u) && i + 1 < units.len() && (0xDC00..0xE000).contains(&u32::from(units[i + 1])) {
                out.push(0x10000 + ((u - 0xD800) << 10) + (u32::from(units[i + 1]) - 0xDC00));
                i += 2;
            } else {
                out.push(u); // surrogatepass keeps a lone surrogate
                i += 1;
            }
        }
        Some(out)
    };
    if b.starts_with(&[0, 0, 0xFE, 0xFF]) {
        return utf32(&b[4..], false);
    }
    if b.starts_with(&[0xFF, 0xFE, 0, 0]) {
        return utf32(&b[4..], true);
    }
    if b.starts_with(&[0xFE, 0xFF]) {
        return utf16(&b[2..], false);
    }
    if b.starts_with(&[0xFF, 0xFE]) {
        return utf16(&b[2..], true);
    }
    if b.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return utf8_surrogatepass(&b[3..]);
    }
    if b.len() >= 4 {
        if b[0] == 0 {
            return if b[1] != 0 { utf16(b, false) } else { utf32(b, false) };
        }
        if b[1] == 0 {
            return if b[2] != 0 || b[3] != 0 { utf16(b, true) } else { utf32(b, true) };
        }
    } else if b.len() == 2 {
        if b[0] == 0 {
            return utf16(b, false);
        }
        if b[1] == 0 {
            return utf16(b, true);
        }
    }
    utf8_surrogatepass(b)
}

/// UTF-8 where encoded surrogates (ED A0 80 to ED BF BF) are allowed, as "surrogatepass" does.
fn utf8_surrogatepass(b: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        let (len, min, init) = match c {
            0x00..=0x7F => (1, 0, u32::from(c)),
            0xC2..=0xDF => (2, 0x80, u32::from(c & 0x1F)),
            0xE0..=0xEF => (3, 0x800, u32::from(c & 0x0F)),
            0xF0..=0xF4 => (4, 0x10000, u32::from(c & 0x07)),
            _ => return None,
        };
        if i + len > b.len() {
            return None;
        }
        let mut v = init;
        for k in 1..len {
            let cont = b[i + k];
            if cont & 0xC0 != 0x80 {
                return None;
            }
            v = (v << 6) | u32::from(cont & 0x3F);
        }
        if v < min || v > 0x10FFFF {
            return None;
        }
        out.push(v);
        i += len;
    }
    Some(out)
}

struct Parser<'a> {
    s: &'a [u32],
    i: usize,
}

/// An open container while parsing: an array, or an object (and whether it is the top-level one).
enum Open {
    Array,
    Object { top: bool },
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.s.get(self.i).and_then(|&c| char::from_u32(c))
    }
    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, word: &str) -> bool {
        let w: Vec<u32> = word.chars().map(|c| c as u32).collect();
        if self.s.get(self.i..self.i + w.len()) == Some(&w[..]) {
            self.i += w.len();
            true
        } else {
            false
        }
    }
    /// After `{` or `,` inside an object: `"key"` `:`. Returns the key.
    fn key(&mut self) -> Result<Vec<u32>, JsonError> {
        self.skip_ws();
        if self.peek() != Some('"') {
            return Err(JsonError::Invalid);
        }
        let key = self.string()?;
        self.skip_ws();
        if self.peek() != Some(':') {
            return Err(JsonError::Invalid);
        }
        self.i += 1;
        Ok(key)
    }
    /// One whole JSON value; true when it is an object with the key `want` at its top level.
    fn document(&mut self, want: &[u32]) -> Result<bool, JsonError> {
        let mut stack: Vec<Open> = Vec::new();
        let mut found = false;
        'value: loop {
            self.skip_ws();
            match self.peek() {
                Some(open @ ('{' | '[')) => {
                    if stack.len() >= JSON_MAX_DEPTH {
                        return Err(JsonError::TooDeep);
                    }
                    self.i += 1;
                    self.skip_ws();
                    if open == '{' {
                        let top = stack.is_empty();
                        if self.peek() == Some('}') {
                            self.i += 1;
                        } else {
                            if self.key()? == want && top {
                                found = true;
                            }
                            stack.push(Open::Object { top });
                            continue 'value;
                        }
                    } else if self.peek() == Some(']') {
                        self.i += 1;
                    } else {
                        stack.push(Open::Array);
                        continue 'value;
                    }
                }
                Some('"') => {
                    self.string()?;
                }
                Some('n') if self.eat("null") => {}
                Some('t') if self.eat("true") => {}
                Some('f') if self.eat("false") => {}
                Some('N') if self.eat("NaN") => {}
                Some('I') if self.eat("Infinity") => {}
                Some('-') if self.eat("-Infinity") => {}
                Some('-' | '0'..='9') => self.number()?,
                _ => return Err(JsonError::Invalid),
            }
            // A value is complete: close containers until one wants another value.
            loop {
                self.skip_ws();
                match stack.last() {
                    None => return Ok(found),
                    Some(Open::Array) => match self.peek() {
                        Some(',') => {
                            self.i += 1;
                            continue 'value;
                        }
                        Some(']') => {
                            self.i += 1;
                            stack.pop();
                        }
                        _ => return Err(JsonError::Invalid),
                    },
                    Some(Open::Object { top }) => {
                        let top = *top;
                        match self.peek() {
                            Some(',') => {
                                self.i += 1;
                                if self.key()? == want && top {
                                    found = true;
                                }
                                continue 'value;
                            }
                            Some('}') => {
                                self.i += 1;
                                stack.pop();
                            }
                            _ => return Err(JsonError::Invalid),
                        }
                    }
                }
            }
        }
    }
    fn number(&mut self) -> Result<(), JsonError> {
        let digits = |p: &mut Self| -> usize {
            let start = p.i;
            while matches!(p.peek(), Some('0'..='9')) {
                p.i += 1;
            }
            p.i - start
        };
        if self.peek() == Some('-') {
            self.i += 1;
        }
        match self.peek() {
            Some('0') => self.i += 1,
            Some('1'..='9') => {
                digits(self);
            }
            _ => return Err(JsonError::Invalid),
        }
        // Python's number pattern only takes the fraction and exponent when they are complete.
        if self.peek() == Some('.') && matches!(self.s.get(self.i + 1).and_then(|&c| char::from_u32(c)), Some('0'..='9')) {
            self.i += 1;
            digits(self);
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            let save = self.i;
            self.i += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                self.i = save;
            }
        }
        Ok(())
    }
    fn string(&mut self) -> Result<Vec<u32>, JsonError> {
        self.i += 1; // the opening quote
        let mut out = Vec::new();
        loop {
            let c = *self.s.get(self.i).ok_or(JsonError::Invalid)?;
            self.i += 1;
            match c {
                0x22 => return Ok(out),
                0x5C => {
                    let e = *self.s.get(self.i).ok_or(JsonError::Invalid)?;
                    self.i += 1;
                    let simple = match char::from_u32(e) {
                        Some('"') => Some(0x22),
                        Some('\\') => Some(0x5C),
                        Some('/') => Some(0x2F),
                        Some('b') => Some(0x08),
                        Some('f') => Some(0x0C),
                        Some('n') => Some(0x0A),
                        Some('r') => Some(0x0D),
                        Some('t') => Some(0x09),
                        Some('u') => None,
                        _ => return Err(JsonError::Invalid),
                    };
                    if let Some(v) = simple {
                        out.push(v);
                        continue;
                    }
                    let unit = self.hex4()?;
                    if (0xD800..0xDC00).contains(&unit) && self.s.get(self.i) == Some(&0x5C) && self.s.get(self.i + 1) == Some(&(u32::from('u'))) {
                        let save = self.i;
                        self.i += 2;
                        let low = self.hex4()?;
                        if (0xDC00..0xE000).contains(&low) {
                            out.push(0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00));
                            continue;
                        }
                        self.i = save;
                    }
                    out.push(unit);
                }
                c if c < 0x20 => return Err(JsonError::Invalid), // strict: no control characters
                c => out.push(c),
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, JsonError> {
        let digits = self.s.get(self.i..self.i + 4).ok_or(JsonError::Invalid)?;
        let mut v = 0;
        for &d in digits {
            let c = char::from_u32(d).ok_or(JsonError::Invalid)?;
            v = v * 16 + c.to_digit(16).ok_or(JsonError::Invalid)?;
        }
        self.i += 4;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_follows_cpython() {
        assert_eq!(a2b_base64(b"aGVsbG8=", true).unwrap(), b"hello");
        assert_eq!(a2b_base64(b"aGVs bG8=", false).unwrap(), b"hello");
        assert!(a2b_base64(b"aGVs bG8=", true).is_err());
        assert!(a2b_base64(b"aGVsbG8", false).is_err());
        assert!(a2b_base64(b"=aGVs", true).is_err());
        assert!(a2b_base64(b"aGVsbG8=junk", false).is_err()); // 3.14: padding no longer stops decoding
        assert_eq!(a2b_base64(b"QQ==QQ==", false).unwrap(), b"\x41\x04\x10");
        assert_eq!(a2b_base64(b"QUJ=", false).unwrap(), b"AB");
        assert!(a2b_base64(b"QQ=", false).is_err());
        assert!(a2b_base64(b"aGVsbG8=junk", true).is_err());
    }

    #[test]
    fn json_check_reads_like_json_loads() {
        assert_eq!(json_object_has_key(br#"{"alg":"HS256","typ":"JWT"}"#, "alg"), Ok(true));
        assert_eq!(json_object_has_key(br#" {"typ": NaN} "#, "alg"), Ok(false));
        assert_eq!(json_object_has_key(br#"{"alg":1}"#, "alg"), Ok(true));
        assert_eq!(json_object_has_key(br#"[1,2]"#, "alg"), Ok(false));
        assert_eq!(json_object_has_key(br#"{"x":{"alg":1}}"#, "alg"), Ok(false));
        assert_eq!(json_object_has_key(br#"{"x":[1,{"y":2}],"alg":[]}"#, "alg"), Ok(true));
        assert!(json_object_has_key(br#"{"a":1,}"#, "alg").is_err());
        assert!(json_object_has_key(br#"[1,]"#, "alg").is_err());
        assert!(json_object_has_key(br#"{"alg":1}x"#, "alg").is_err());
        assert!(json_object_has_key(b"{\"a\nb\":1}", "alg").is_err());
        assert_eq!(json_object_has_key(b"\xef\xbb\xbf{\"alg\":1}", "alg"), Ok(true));
        assert_eq!(json_object_has_key(br#"{"alg": 1.}"#, "alg"), Err(JsonError::Invalid));
        let deep = format!("{{\"a\":{}{}}}", "[".repeat(60_000), "]".repeat(60_000));
        assert_eq!(json_object_has_key(deep.as_bytes(), "alg"), Err(JsonError::TooDeep));
    }
}
