//! Minimal fail-closed evaluator for the truly in-memory Ring 0 path.

use std::ffi::{c_char, CStr};
use std::panic;
use std::sync::atomic::{AtomicBool, Ordering};

pub const ALLOW: i32 = 0;
pub const DENY: i32 = 1;
pub const ERROR: i32 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HotPathRequest {
    pub tool_name: *const c_char,
    pub ring: i32,
    pub principal_id: *const c_char,
}

fn evaluate_values(tool: &str, ring: i32, principal: &str) -> i32 {
    if tool.is_empty() || principal.is_empty() {
        return DENY;
    }

    // Exact names avoid the over-broad prefix matching used by the book sample.
    match (ring, tool) {
        (0, "prompt-code-reader") => ALLOW,
        (0, "policy-metadata-reader") => ALLOW,
        _ => DENY,
    }
}

/// Lab lifecycle wrapper for the native hot-path component.
///
/// A real loader would also retain and unload an OS dynamic-library handle.
/// This type proves the important contract: validate at startup, deny after
/// shutdown, make close idempotent, and let Drop perform the same cleanup.
pub struct ProductionHotPathHandle {
    library_path: String,
    active: AtomicBool,
}

impl ProductionHotPathHandle {
    pub fn initialize(library_path: &str) -> Result<Self, &'static str> {
        if library_path.trim().is_empty() {
            return Err("native library path is required");
        }
        Ok(Self {
            library_path: library_path.to_owned(),
            active: AtomicBool::new(true),
        })
    }

    pub fn is_ready(&self) -> bool {
        self.active.load(Ordering::Acquire) && !self.library_path.is_empty()
    }

    pub fn evaluate(&self, tool: &str, ring: i32, principal: &str) -> i32 {
        if !self.is_ready() {
            return DENY;
        }
        evaluate_values(tool, ring, principal)
    }

    pub fn close(&self) {
        self.active.store(false, Ordering::Release);
    }
}

impl Drop for ProductionHotPathHandle {
    fn drop(&mut self) {
        self.close();
    }
}

#[no_mangle]
pub extern "C" fn evaluate_hot_path(request: HotPathRequest) -> i32 {
    match panic::catch_unwind(|| {
        if request.tool_name.is_null() || request.principal_id.is_null() {
            return ERROR;
        }

        let tool = unsafe { CStr::from_ptr(request.tool_name) };
        let principal = unsafe { CStr::from_ptr(request.principal_id) };
        let Ok(tool) = tool.to_str() else { return ERROR };
        let Ok(principal) = principal.to_str() else { return ERROR };
        evaluate_values(tool, request.ring, principal)
    }) {
        Ok(verdict) => verdict,
        Err(_) => ERROR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_exact_ring_zero_tool() {
        assert_eq!(evaluate_values("prompt-code-reader", 0, "developer-1"), ALLOW);
    }

    #[test]
    fn denies_prefix_confusion_and_wrong_ring() {
        assert_eq!(evaluate_values("prompt-code-reader-evil", 0, "developer-1"), DENY);
        assert_eq!(evaluate_values("prompt-code-reader", 1, "developer-1"), DENY);
    }

    #[test]
    fn denies_empty_identity() {
        assert_eq!(evaluate_values("prompt-code-reader", 0, ""), DENY);
    }

    #[test]
    fn production_handle_validates_startup_and_denies_after_close() {
        assert!(ProductionHotPathHandle::initialize("  ").is_err());
        let handle = ProductionHotPathHandle::initialize("libhot_path_evaluator.dylib").unwrap();
        assert!(handle.is_ready());
        assert_eq!(handle.evaluate("prompt-code-reader", 0, "developer-1"), ALLOW);
        handle.close();
        handle.close();
        assert!(!handle.is_ready());
        assert_eq!(handle.evaluate("prompt-code-reader", 0, "developer-1"), DENY);
    }
}
