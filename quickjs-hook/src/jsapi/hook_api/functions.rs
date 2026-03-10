//! js_hook, js_unhook, js_call_native implementations

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    dup_callback_to_bytes, ensure_function_arg, extract_pointer_address,
    js_i64_to_js_number_or_bigint, js_value_to_u64_or_zero, throw_internal_error,
};
use crate::jsapi::util::is_addr_accessible;
use crate::value::JSValue;

use super::callback::hook_callback_wrapper;
use super::registry::{hook_error_message, init_registry, HookData, HOOK_OK, HOOK_REGISTRY};
use crate::jsapi::callback_util::with_registry_mut;

/// hook(ptr, callback, stealth?) - Install a hook at the given address
/// stealth: optional boolean, default false. If true, uses wxshadow for traceless hooking.
pub(crate) unsafe extern "C" fn js_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 2 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"hook() requires at least 2 arguments\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);
    let callback_arg = JSValue(*argv.add(1));

    // Get optional stealth flag (3rd argument, default false)
    let stealth = if argc >= 3 {
        let stealth_arg = JSValue(*argv.add(2));
        stealth_arg.to_bool().unwrap_or(false)
    } else {
        false
    };

    // Get the address
    let addr = match extract_pointer_address(ctx, ptr_arg, "hook") {
        Ok(a) => a,
        Err(e) => return e,
    };

    // Check callback is a function
    if let Err(err) = ensure_function_arg(
        ctx,
        callback_arg,
        b"hook() second argument must be a function\0",
    ) {
        return err;
    }

    // Initialize registry
    init_registry();

    // Duplicate callback and convert to bytes for Send/Sync-safe registry storage
    let callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());

    // 使用 hook_replace 代替 hook_attach，支持 replace 模式
    // hook_replace 返回 trampoline 地址（用于 callOriginal），失败返回 NULL
    let trampoline = hook_ffi::hook_replace(
        addr as *mut std::ffi::c_void,
        Some(hook_callback_wrapper),
        addr as *mut std::ffi::c_void, // Use address as user_data to look up callback
        if stealth { 1 } else { 0 },
    );

    if trampoline.is_null() {
        // hook 安装失败，释放 JS 回调引用
        let callback: ffi::JSValue = std::ptr::read(callback_bytes.as_ptr() as *const ffi::JSValue);
        ffi::qjs_free_value(ctx, callback);
        return throw_internal_error(ctx, "hook_replace failed: could not install hook");
    }

    // hook 已安装，将 callback 和 trampoline 插入 registry
    with_registry_mut(&HOOK_REGISTRY, |registry| {
        registry.insert(
            addr,
            HookData {
                ctx: ctx as usize,
                callback_bytes,
                trampoline: trampoline as u64,
            },
        );
    });

    JSValue::bool(true).raw()
}

/// unhook(ptr) - Remove a hook at the given address
pub(crate) unsafe extern "C" fn js_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(ctx, b"unhook() requires 1 argument\0".as_ptr() as *const _);
    }

    let ptr_arg = JSValue(*argv);

    // Get the address
    let addr = match extract_pointer_address(ctx, ptr_arg, "unhook") {
        Ok(a) => a,
        Err(e) => return e,
    };

    // 先移除 hook（阻止新回调进入），再从 registry 移除并释放 callback。
    // 颠倒顺序会导致 use-after-free：窗口期内回调线程可能用已释放的 JSValue 调用 JS_Call。
    let result = hook_ffi::hook_remove(addr as *mut std::ffi::c_void);

    if result != HOOK_OK {
        let err_msg = hook_error_message(result);
        return ffi::JS_ThrowInternalError(ctx, err_msg.as_ptr() as *const _);
    }

    // hook 已移除，不会再有新回调触发，安全释放 callback
    if let Some(data) = with_registry_mut(&HOOK_REGISTRY, |registry| registry.remove(&addr)) {
        if let Some(data) = data {
            let ctx = data.ctx as *mut ffi::JSContext;
            let callback: ffi::JSValue =
                std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
            ffi::qjs_free_value(ctx, callback);
        }
    }

    JSValue::bool(true).raw()
}

/// callNative(ptr, arg0?, arg1?, ..., arg5?) - Call a native function at addr with 0-6 args.
/// Arguments are passed in x0-x5 (ARM64 calling convention). Unspecified args default to 0.
/// Return value: Number when result fits exactly in f64 (≤ 2^53), BigUint64 otherwise.
pub(crate) unsafe extern "C" fn js_call_native(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"callNative() requires at least 1 argument\0".as_ptr() as *const _,
        );
    }

    let ptr_arg = JSValue(*argv);

    let addr = match extract_pointer_address(ctx, ptr_arg, "callNative") {
        Ok(a) => a,
        Err(e) => return e,
    };

    // Reject null and near-zero addresses without calling mincore:
    // the first 64KB is never a valid user-space function pointer on ARM64 Android.
    if addr < 0x10000 {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"callNative() address is not mapped\0".as_ptr() as *const _,
        );
    }

    // For higher addresses, verify accessibility via mincore before calling.
    if !is_addr_accessible(addr, 4) {
        return ffi::JS_ThrowRangeError(
            ctx,
            b"callNative() address is not mapped\0".as_ptr() as *const _,
        );
    }

    // Verify the address is in a known executable segment via dladdr.
    // is_addr_accessible only checks if the page is resident, not if it's code.
    // Calling a data pointer or non-executable page would SIGSEGV/SIGILL crash.
    {
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        if unsafe { libc::dladdr(addr as *const std::ffi::c_void, &mut info) } == 0 {
            return ffi::JS_ThrowRangeError(
                ctx,
                b"callNative() address is not in an executable segment\0".as_ptr() as *const _,
            );
        }
    }

    // Extract up to 6 integer/pointer arguments (argv[1..6]), passed via x0-x5.
    // Unspecified arguments default to 0.
    let mut args = [0u64; 6];
    for i in 0..6usize {
        if (i + 1) < argc as usize {
            let arg = JSValue(*argv.add(i + 1));
            args[i] = js_value_to_u64_or_zero(ctx, arg);
        }
    }

    let func: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> i64 =
        std::mem::transmute(addr as usize);
    let result = func(args[0], args[1], args[2], args[3], args[4], args[5]);

    // Return Number when the result magnitude fits exactly as f64 (≤ 2^53).
    // Use unsigned_abs() so negative i64 results (e.g. errno -1) are also returned
    // as JS Number instead of wrapping to a huge BigInt.
    // JS_NewInt64 encodes small integers as JS_TAG_INT (typeof === "number").
    js_i64_to_js_number_or_bigint(ctx, result)
}
