//! The engine as a WebAssembly module, with a small C-style interface and JSON in and out.
//!
//! The host (extension/engine/engine.js) calls, in order:
//!
//! * `sl_alloc(len)` to get a buffer, writes UTF-8 into it;
//! * `sl_init(ptr, len)` once, with the settings as JSON (`{}` for the defaults); returns 0 on success;
//! * `sl_analyze(ptr, len)` with the text; returns a pointer to the result JSON, whose length is
//!   `sl_result_len()`; the host copies it out and calls `sl_free(ptr, len)`.
//!
//! An error is returned as JSON too: `{"error": "..."}`. Nothing here ever panics across the boundary
//! on bad input: text that is not valid UTF-8 is an error result, not a trap.

use std::cell::{Cell, RefCell};

use shadowlens_engine::{Engine, Settings};

thread_local! {
    static ENGINE: RefCell<Option<Engine>> = const { RefCell::new(None) };
    static RESULT_LEN: Cell<usize> = const { Cell::new(0) };
}

/// Buffers are boxed slices, so their size is exactly `len` and freeing them needs only `len`.
#[no_mangle]
pub extern "C" fn sl_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()).cast::<u8>()
}

/// # Safety
/// `ptr` and `len` must come from `sl_alloc` (same `len`) or be a result of `sl_analyze` and its
/// `sl_result_len()`, and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn sl_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

unsafe fn read_str<'a>(ptr: *const u8, len: usize) -> Result<&'a str, String> {
    let bytes = if len == 0 { &[][..] } else { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes).map_err(|_| "input is not valid UTF-8".to_string())
}

fn hand_back(json: String) -> *mut u8 {
    let bytes = json.into_bytes().into_boxed_slice();
    RESULT_LEN.with(|l| l.set(bytes.len()));
    Box::into_raw(bytes).cast::<u8>()
}

/// Build the engine. Returns 0 on success, 1 for bad settings, 2 if a pattern did not compile.
///
/// # Safety
/// `ptr`/`len` must describe a buffer from `sl_alloc` holding UTF-8.
#[no_mangle]
pub unsafe extern "C" fn sl_init(ptr: *const u8, len: usize) -> u32 {
    let Ok(json) = read_str(ptr, len) else { return 1 };
    let json = if json.trim().is_empty() { "{}" } else { json };
    let Ok(settings) = Settings::from_json(json) else { return 1 };
    match Engine::new(settings) {
        Ok(engine) => {
            ENGINE.with(|e| *e.borrow_mut() = Some(engine));
            0
        }
        Err(_) => 2,
    }
}

/// Analyze UTF-8 text. Returns a pointer to UTF-8 JSON of length `sl_result_len()`.
///
/// # Safety
/// `ptr`/`len` must describe a buffer from `sl_alloc`.
#[no_mangle]
pub unsafe extern "C" fn sl_analyze(ptr: *const u8, len: usize) -> *mut u8 {
    let json = match read_str(ptr, len) {
        Err(message) => serde_json::json!({ "error": message }).to_string(),
        Ok(text) => ENGINE.with(|e| match e.borrow().as_ref() {
            None => serde_json::json!({ "error": "sl_init was not called" }).to_string(),
            Some(engine) => serde_json::to_string(&engine.analyze(text)).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")),
        }),
    };
    hand_back(json)
}

#[no_mangle]
pub extern "C" fn sl_result_len() -> usize {
    RESULT_LEN.with(Cell::get)
}

/// Compile every pattern now (normally they compile on first use). Returns 0 on success.
#[no_mangle]
pub extern "C" fn sl_warm() -> u32 {
    ENGINE.with(|e| match e.borrow().as_ref() {
        Some(engine) => {
            let _ = engine.analyze("warm up: a@b.co (x) [y] {z} password=Xk39aQ2zLm7pR GB82WEST12345698765432 4111 1111 1111 1111\n```\ndef f(): pass\n```");
            0
        }
        None => 1,
    })
}
