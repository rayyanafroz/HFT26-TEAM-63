//! Times every detector pattern on one input, to find slow ones:
//!     cargo run --release --example profile -- path/to/input.txt
use shadowlens_engine::patterns as p;
use shadowlens_engine::pyre::{Flags, Re};
use std::time::Instant;

fn main() {
    let path = std::env::args().nth(1).expect("an input file");
    let text = std::fs::read_to_string(path).expect("readable UTF-8");
    let mut all: Vec<(String, (&str, Flags))> = Vec::new();
    for (rule, def) in p::NAMED_PATTERNS { all.push((rule.to_string(), *def)); }
    for (i, def) in p::VENDOR_PATTERNS.iter().enumerate() { all.push((format!("VENDOR_{i}"), *def)); }
    for (i, def) in p::PHONE_PATTERNS.iter().enumerate() { all.push((format!("PHONE_{i}"), *def)); }
    macro_rules! add { ($($n:ident),*) => { $( all.push((stringify!($n).to_string(), p::$n)); )* } }
    add!(AWS_SECRET_RE, JWT_RE, NAMED_PREFILTER_RE, GENERIC_RE, GENERIC_PLAIN_RE, GENERIC_QUOTED_RE, PAIR_RE, BEARER_RE,
         CLI_PASSWORD_RE, URL_CREDENTIALS_RE, GENERIC_CAMEL_RE, DIGIT_RUN_RE, SINGLE_DIGITS_RE, SSN_RE,
         SSN_WORDED_RE, PAN_RE, EMAIL_RE, EMAIL_SPELLED_RE, HOSTNAME_RE, PRIVATE_IP_RE, KEY_START, NEXT_PIECE,
         MARKER_RE, COPYRIGHT_RE, FENCE_RE, CODE_TOKEN_RE, CODE_LINE_RE, PLACEHOLDER_RE);
    let mut rows = Vec::new();
    for (name, (pattern, flags)) in all {
        let t = Instant::now();
        let re = Re::new(pattern, flags).unwrap();
        let compile = t.elapsed();
        let t = Instant::now();
        let n = re.find_all(&text).map(|v| v.len()).unwrap_or(usize::MAX);
        rows.push((t.elapsed(), compile, name, n));
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0));
    for (run, compile, name, n) in rows.iter().take(15) {
        println!("{name:24} run {:8.1} ms  compile {:6.1} ms  matches {n}", run.as_secs_f64() * 1e3, compile.as_secs_f64() * 1e3);
    }
    let total: f64 = rows.iter().map(|r| r.1.as_secs_f64()).sum();
    println!("total compile {:.0} ms", total * 1e3);
}
