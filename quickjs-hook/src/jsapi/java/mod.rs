//! Java.use() API — Frida-style Java method hooking
//!
//! 统一 Clone+Replace 策略:
//! 所有方法统一走 clone → replacement → artController 三层拦截矩阵。
//! 编译方法额外安装 per-method 路由 hook (Layer 3)。
//!
//! On ARM64 Android, jmethodID == ArtMethod*. All methods use a replacement
//! ArtMethod (native, jniCode=thunk) routed through the three-layer interception
//! matrix. All callbacks use unified JNI calling convention.
//!
//! ## JS API
//!
//! ```javascript
//! var Activity = Java.use("android.app.Activity");
//! Activity.onResume.impl = function(ctx) { console.log("hit"); };
//! Activity.onResume.impl = null; // unhook
//! // For overloaded methods:
//! Activity.foo.overload("(II)V").impl = function(ctx) { ... };
//! ```

/// Transmute a JNI function pointer from the function table by index.
macro_rules! jni_fn {
    ($env:expr, $ty:ty, $idx:expr) => {
        std::mem::transmute::<*const std::ffi::c_void, $ty>(
            $crate::jsapi::java::jni_core::jni_fn_ptr($env, $idx),
        )
    };
}

/// ARM64 PAC/TBI 位剥离掩码 — 保留 48-bit 规范虚拟地址
/// MTE 设备上 bit 48-55 可能非零，必须用 48-bit 而非 56-bit 掩码
pub(crate) const PAC_STRIP_MASK: u64 = 0x0000_FFFF_FFFF_FFFF;

mod art_class;
mod art_controller;
mod art_method;
mod art_thread;
mod callback;
mod java_field_api;
mod java_hook_api;
mod java_inspect_api;
mod java_method_list_api;
mod jni_core;
mod reflect;
mod safe_mem;

pub(crate) use jni_core::ensure_jni_initialized;
pub(crate) use reflect::get_class_name_unchecked;

use crate::context::JSContext;
use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::console::output_message;
use crate::jsapi::util::add_cfunction_to_object;
use crate::value::JSValue;

use art_controller::{is_stealth_enabled, set_stealth_enabled};
use art_method::try_invalidate_jit_cache;
use callback::*;
use java_field_api::*;
use java_hook_api::*;
use java_inspect_api::*;
use java_method_list_api::*;
use jni_core::*;
use reflect::*;

/// JS CFunction: Java.deopt() — 清空 JIT 缓存 (InvalidateAllMethods)
/// 返回 true/false 表示操作是否成功
unsafe extern "C" fn js_java_deopt(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    output_message("[java deopt] 清空 JIT 缓存...");
    try_invalidate_jit_cache();
    output_message("[java deopt] JIT 缓存清空完成");
    JSValue::bool(true).raw()
}

/// JS CFunction: Java._artRouterDebug() — dump ART router not_found capture
/// Shows the last X0 (ArtMethod*) seen in the thunk's not_found path and the
/// total miss count. Also reads back entry_point of all hooked methods to check
/// if our writes persisted.
unsafe extern "C" fn js_art_router_debug(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let mut last_x0: u64 = 0;
    let mut miss_count: u64 = 0;
    hook_ffi::hook_art_router_get_debug(&mut last_x0, &mut miss_count);
    output_message(&format!(
        "[art_router_debug] last_x0={:#x}, miss_count={}",
        last_x0, miss_count
    ));

    // Also dump the table for reference
    hook_ffi::hook_art_router_table_dump();

    // Read back entry_point of all hooked methods to check persistence
    {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref registry) = *guard {
            for (art_method, data) in registry.iter() {
                if let Some(spec) = ART_METHOD_SPEC.get() {
                    let current_ep = std::ptr::read_volatile(
                        (*art_method as usize + spec.entry_point_offset) as *const u64,
                    );
                    let current_flags = std::ptr::read_volatile(
                        (*art_method as usize + spec.access_flags_offset) as *const u32,
                    );
                    output_message(&format!(
                        "[art_router_debug] ArtMethod={:#x}: current_ep={:#x} (original={:#x}), flags={:#x} (original={:#x})",
                        art_method, current_ep, data.original_entry_point,
                        current_flags, data.original_access_flags
                    ));
                }
            }
        }
    }

    // Reset counters for next check
    hook_ffi::hook_art_router_reset_debug();
    JSValue::bool(true).raw()
}

/// JS CFunction: Java.setStealth(enabled) — 启用/禁用 wxshadow stealth 模式
///
/// 启用后所有 inline hook 优先尝试 wxshadow，内核不支持则自动 fallback 到 mprotect。
/// 建议在首次 Java.hook() 之前调用，否则已安装的 Layer 1/2 hook 不受影响。
unsafe extern "C" fn js_java_set_stealth(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.setStealth() requires 1 argument: boolean\0".as_ptr() as *const _,
        );
    }
    let arg = JSValue(*argv);
    let enabled = arg.to_bool().unwrap_or(false);
    set_stealth_enabled(enabled);
    JSValue::bool(enabled).raw()
}

/// JS CFunction: Java.getStealth() — 查询 stealth 开关状态
unsafe extern "C" fn js_java_get_stealth(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(is_stealth_enabled()).raw()
}

/// JS CFunction: Java._updateClassLoader(ptr) — 更新缓存的 app ClassLoader
/// 由 Java.ready() gate hook 在 Instrumentation.newApplication 回调中调用，
/// 传入 ClassLoader 的 jobject 指针。
unsafe extern "C" fn js_update_classloader(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 1 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java._updateClassLoader() requires 1 argument: ClassLoader jobject ptr\0".as_ptr()
                as *const _,
        );
    }
    let arg = JSValue(*argv);
    let cl_ptr = match arg.to_u64(ctx) {
        Some(v) => v as *mut std::ffi::c_void,
        None => {
            return ffi::JS_ThrowTypeError(
                ctx,
                b"Java._updateClassLoader() argument must be a pointer (BigInt)\0".as_ptr()
                    as *const _,
            )
        }
    };

    match ensure_jni_initialized() {
        Ok(env) => {
            update_app_classloader(env, cl_ptr);
            output_message("[java.ready] ClassLoader 已更新");
            JSValue::bool(true).raw()
        }
        Err(_) => {
            output_message("[java.ready] 获取 JNIEnv 失败，ClassLoader 更新失败");
            JSValue::bool(false).raw()
        }
    }
}

/// JS CFunction: Java._isClassLoaderReady() — 检查 app ClassLoader 是否已就绪
unsafe extern "C" fn js_is_classloader_ready(
    _ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    JSValue::bool(is_classloader_ready()).raw()
}

/// Register Java API: hook/unhook (C-level) + _methods, then eval boot script
/// to set up the Proxy-based Java.use() API.
pub fn register_java_api(ctx: &JSContext) {
    // Pre-cache reflection method IDs from the safe init thread.
    // This must happen here (not from hook callbacks) because FindClass
    // triggers ART stack walking, which crashes inside hook trampolines.
    if let Ok(env) = ensure_jni_initialized() {
        unsafe {
            cache_reflect_ids(env);
        }
    }

    let global = ctx.global_object();

    unsafe {
        // Create the "Java" namespace object
        let java_obj = ffi::JS_NewObject(ctx.as_ptr());

        let ctx_ptr = ctx.as_ptr();
        add_cfunction_to_object(ctx_ptr, java_obj, "hook", js_java_hook, 4);
        add_cfunction_to_object(ctx_ptr, java_obj, "unhook", js_java_unhook, 3);
        add_cfunction_to_object(ctx_ptr, java_obj, "deopt", js_java_deopt, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "setStealth", js_java_set_stealth, 1);
        add_cfunction_to_object(ctx_ptr, java_obj, "getStealth", js_java_get_stealth, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_artRouterDebug", js_art_router_debug, 0);
        add_cfunction_to_object(ctx_ptr, java_obj, "_methods", js_java_methods, 1);
        // Instance method invocation helper used by Java object proxies
        add_cfunction_to_object(ctx_ptr, java_obj, "_invokeMethod", js_java_invoke_method, 4);
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_invokeStaticMethod",
            js_java_invoke_static_method,
            4,
        );
        add_cfunction_to_object(ctx_ptr, java_obj, "_newObject", js_java_new_object, 2);
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_getFieldAuto",
            js_java_get_field_auto,
            3,
        );
        add_cfunction_to_object(ctx_ptr, java_obj, "getField", js_java_get_field, 4);

        // 检测面测试 API
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_inspectArtMethod",
            js_java_inspect_art_method,
            3,
        );
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_setForcedInterpretOnly",
            js_java_set_forced_interpret_only,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_initArtController",
            js_java_init_art_controller,
            0,
        );
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_updateClassLoader",
            js_update_classloader,
            1,
        );
        add_cfunction_to_object(
            ctx_ptr,
            java_obj,
            "_isClassLoaderReady",
            js_is_classloader_ready,
            0,
        );

        // Set Java object on global
        global.set_property(ctx.as_ptr(), "Java", JSValue(java_obj));
    }

    global.free(ctx.as_ptr());

    // Load boot script: sets up Java.use() Proxy API, captures hook/unhook/
    // _methods in closures, then removes them from the Java object.
    let boot = include_str!("java_boot.js");
    match ctx.eval(boot, "<java_boot>") {
        Ok(val) => val.free(ctx.as_ptr()),
        Err(e) => output_message(&format!("[java_api] boot script error: {}", e)),
    }
}

/// Cleanup all Java hooks (call before dropping context)
///
/// Frida revert() 风格: 恢复全部 ArtMethod 字段，清理 replacedMethods 映射。
///
/// 调用路径: JSEngine::drop() → cleanup_java_hooks()
/// 此时 JS_ENGINE 锁已被当前线程持有（cleanup_engine() 中 `*engine = None` 触发 drop），
/// 因此不能再次 lock()（非重入锁会死锁）。使用 try_lock() 安全处理两种情况：
/// - WouldBlock: 当前线程已持有锁（正常路径），JS callback 释放安全
/// - Ok: 意外的非锁定路径调用，获取锁后释放 JS callback
pub fn cleanup_java_hooks() {
    // 【关键】先清空 C 侧 ART router 查表，切断路由 → 防止并发线程通过
    // Layer 1 router 访问即将释放的 replacement ArtMethod (UAF)
    unsafe {
        hook_ffi::hook_art_router_table_clear();
    }

    // ============================================================
    // Pass 1: 恢复所有 ArtMethod 字段 + 删除 replacedMethods 映射
    //
    // 【必须在移除 Layer 1 hooks 之前完成】
    // 否则: Layer 1 hook 移除后原始 trampoline 恢复，但 ArtMethod 仍然是
    // native+data_=our_thunk → 其他线程调用 → jni_trampoline → 我们的 thunk
    // → callback 找不到 registry → 返回 x0=JNIEnv* 作为返回值 → 崩溃
    // ============================================================
    {
        let guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(registry) = guard.as_ref() {
            for (_art_method, data) in registry.iter() {
                unsafe {
                    // 恢复 ArtMethod 字段 (flags, data_, entry_point)
                    if let Some(spec) = ART_METHOD_SPEC.get() {
                        let ep_offset = spec.entry_point_offset;
                        let data_off = spec.data_offset;

                        std::ptr::write_volatile(
                            (data.art_method as usize + spec.access_flags_offset) as *mut u32,
                            data.original_access_flags,
                        );
                        std::ptr::write_volatile(
                            (data.art_method as usize + data_off) as *mut u64,
                            data.original_data,
                        );
                        std::ptr::write_volatile(
                            (data.art_method as usize + ep_offset) as *mut u64,
                            data.original_entry_point,
                        );
                        hook_ffi::hook_flush_cache(
                            (data.art_method as usize) as *mut std::ffi::c_void,
                            ep_offset + 8,
                        );
                    }

                    // 删除 replacedMethods 映射
                    callback::delete_replacement_method(data.art_method);
                }
            }
        }
    } // guard dropped — 释放锁让 in-flight callback 能获取锁并安全退出

    // 短暂等待让 in-flight thunk 回调完成
    // ArtMethod 已恢复 → 不会有新线程进入 thunk，只需等待已在 thunk 中的线程退出
    std::thread::sleep(std::time::Duration::from_millis(50));

    // 移除 artController 全局 hook (Layer 1/2/GC)
    // 此时 ArtMethod 已全部恢复，移除 Layer 1 hook 后不会有线程进入 thunk
    art_controller::cleanup_art_controller();

    // ============================================================
    // Pass 2: 移除 per-method hooks + 释放资源
    // ============================================================

    // Get JNIEnv for global ref cleanup (best effort)
    let env_opt = unsafe { get_thread_env().ok() };

    // try_lock JS_ENGINE: 通常已被当前线程持有（从 drop 调用），
    // WouldBlock 时说明当前线程已持有锁，JS 操作安全
    let _js_guard = crate::JS_ENGINE.try_lock();
    // 无论是否获取到锁，都继续清理（drop 路径下已持有锁）

    let mut guard = JAVA_HOOK_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(registry) = guard.take() {
        for (_art_method, data) in registry {
            unsafe {
                match &data.hook_type {
                    callback::HookType::Replaced {
                        replacement_addr,
                        per_method_hook_target,
                    } => {
                        // 移除 per-method 路由 hook (Layer 3, if any)
                        if let Some(target) = per_method_hook_target {
                            hook_ffi::hook_remove(*target as *mut std::ffi::c_void);
                        }

                        // 移除 native trampoline
                        hook_ffi::hook_remove_redirect(data.art_method);

                        // 释放 replacement ArtMethod (malloc 分配)
                        if *replacement_addr != 0 {
                            libc::free(*replacement_addr as *mut std::ffi::c_void);
                        }
                    }
                }

                // 释放 backup clone (callOriginal)
                if data.clone_addr != 0 {
                    libc::free(data.clone_addr as *mut std::ffi::c_void);
                }

                // 删除 JNI global ref
                if data.class_global_ref != 0 {
                    if let Some(env) = env_opt {
                        let delete_global_ref: DeleteGlobalRefFn =
                            jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
                        delete_global_ref(env, data.class_global_ref as *mut std::ffi::c_void);
                    }
                }

                // 释放 JS callback
                let ctx = data.ctx as *mut ffi::JSContext;
                let callback: ffi::JSValue =
                    std::ptr::read(data.callback_bytes.as_ptr() as *const ffi::JSValue);
                ffi::qjs_free_value(ctx, callback);
            }
        }
    }
}
