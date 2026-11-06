//! The conformance protocol over the Rust engine: one JSON object per line in, one per line out.
//!
//!     engine-adapter [--settings settings.json] < cases > answers
//!
//! A request is `{"id": ..., "text": ...}`. Requests with an `op` field reach internal pieces directly, so
//! they can be compared with CPython one by one: `b64` (`binascii.a2b_base64`), `fold`, `entropy`.

use std::io::{self, BufRead, BufWriter, Write};

use serde_json::{json, Value};
use shadowlens_engine::{fold, pydecode, secrets, Engine, Settings};

fn answer(engine: &Engine, request: &Value) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    match request.get("op").and_then(Value::as_str) {
        None => {
            let text = request.get("text").and_then(Value::as_str).unwrap_or("");
            let result = engine.analyze(text);
            let mut out = serde_json::to_value(&result).expect("an analysis always serializes");
            out["id"] = id;
            out
        }
        Some("b64") => {
            let data = request["data"].as_str().unwrap_or("");
            let strict = request["strict"].as_bool().unwrap_or(false);
            match pydecode::a2b_base64(data.as_bytes(), strict) {
                Ok(bytes) => json!({"id": id, "ok": true, "hex": bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()}),
                Err(()) => json!({"id": id, "ok": false}),
            }
        }
        Some("fold") => {
            let view = fold::fold(request["text"].as_str().unwrap_or(""));
            let (starts, ends) = view.maps.clone().unzip();
            json!({"id": id, "view": view.text, "starts": starts, "ends": ends})
        }
        Some("entropy") => json!({"id": id, "entropy": secrets::shannon_entropy(request["text"].as_str().unwrap_or(""))}),
        Some(other) => json!({"id": id, "error": format!("unknown op {other}")}),
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut settings = Settings::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--settings" => {
                let path = args.next().expect("--settings needs a path");
                let json = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"));
                settings = Settings::from_json(&json).unwrap_or_else(|e| panic!("bad settings: {e}"));
            }
            other => panic!("unknown argument {other}"),
        }
    }
    let engine = Engine::new(settings).unwrap_or_else(|e| panic!("a pattern did not compile: {}", e.0));
    let stdin = io::stdin();
    let mut out = BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin is UTF-8");
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = serde_json::from_str(&line).expect("each line is a JSON object");
        serde_json::to_writer(&mut out, &answer(&engine, &request)).expect("stdout is writable");
        out.write_all(b"\n").expect("stdout is writable");
        // An interactive caller waits for each answer before sending the next request.
        out.flush().expect("stdout is writable");
    }
    out.flush().expect("stdout is writable");
}
