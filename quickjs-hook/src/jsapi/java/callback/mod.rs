//! Java hook callback and registry + replacedMethods mapping
//!
//! Split into focused fragments:
//! - registry/signature parsing
//! - Java/JS marshalling helpers
//! - Java._invokeMethod / ctx.orig()
//! - hook trampoline callback and replacement mapping

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    ensure_registry_initialized, extract_pointer_address, extract_string_arg, get_js_u64_property,
    invoke_hook_callback_common, js_value_to_u64_or_zero, set_js_cfunction_property,
    set_js_u64_property, throw_internal_error, throw_type_error, BiMap,
};
use crate::value::JSValue;
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use super::jni_core::*;
use super::reflect::{find_class_safe, REFLECT_IDS};

include!("registry.rs");
include!("signature.rs");
include!("marshal.rs");
include!("invoke.rs");
include!("original_call.rs");
include!("hook.rs");
include!("replaced.rs");
