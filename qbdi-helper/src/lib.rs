#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod data;
mod state;
mod trace_api;
mod vm_api;
mod writer;

use std::ffi::c_void;

extern "C" {
    fn get_hide_result() -> *const c_void;
}

#[no_mangle]
pub extern "C" fn rust_get_hide_result() -> *const c_void {
    unsafe { get_hide_result() }
}
