//! JS API: Java.hook / Java.unhook
//!
//! 统一 Clone+Replace 策略:
//! 所有方法（无论编译/解释）统一走:
//! 1. clone → backup (callOriginal 用)
//! 2. 创建 replacement (native, jniCode=thunk, quickCode=jni_trampoline, flags=native)
//! 3. 修改 original flags (kAccCompileDontBother 等)
//! 4. Nterp 降级 (如果需要)
//! 5. 确保 artController 初始化 (Layer 1 + Layer 2)
//! 6. 注册 replacedMethods(original, replacement)
//! 7. 编译方法: 安装 per-method 路由 hook (Layer 3)
//! 8. 注册 JAVA_HOOK_REGISTRY
//!
//! 所有 callback 统一 JNI 约定: x0=JNIEnv*, x1=this/class, x2+=args

use crate::ffi;
use crate::ffi::hook as hook_ffi;
use crate::jsapi::callback_util::{
    dup_callback_to_bytes, ensure_function_arg, extract_string_arg, throw_internal_error,
    with_registry, with_registry_mut,
};
use crate::jsapi::console::output_message;
use crate::value::JSValue;

use super::art_controller::{ensure_art_controller_initialized, stealth_flag};
use super::art_method::*;
use super::callback::*;
use super::jni_core::*;
use super::reflect::*;

// ============================================================================
// JS API: Java.hook(class, method, sig, callback)
//
// 统一 Clone+Replace 流程:
//
// 1. fetchArtMethod — 读取原始 4 字段
// 2. 检查 Xposed (kAccXposedHookedMethod)
// 3. cloneArtMethod — 堆分配 backup clone (callOriginal 用)
// 4. 创建 replacement ArtMethod (native, jniCode=thunk, quickCode=jni_trampoline)
// 5. 修改 original flags
// 6. Nterp 降级 (如果 quickCode == nterp → 改写为 interpreter_bridge)
// 7. 确保 artController 初始化 (Layer 1 + Layer 2)
// 8. 注册 replacedMethods 映射
// 9. 编译方法: 安装 per-method 路由 hook (Layer 3)
// 10. backup_clone: 编译方法设置 quickCode = trampoline
// 11. 注册 JAVA_HOOK_REGISTRY
// ============================================================================

pub(super) unsafe extern "C" fn js_java_hook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 4 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.hook() requires 4 arguments: class, method, signature, callback\0".as_ptr()
                as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));
    let callback_arg = JSValue(*argv.add(3));

    // 提取字符串参数
    let class_name = match extract_string_arg(
        ctx,
        class_arg,
        b"Java.hook() first argument must be a class name string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let method_name = match extract_string_arg(
        ctx,
        method_arg,
        b"Java.hook() second argument must be a method name string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let sig_str = match extract_string_arg(
        ctx,
        sig_arg,
        b"Java.hook() third argument must be a signature string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    if let Err(err) = ensure_function_arg(
        ctx,
        callback_arg,
        b"Java.hook() fourth argument must be a function\0",
    ) {
        return err;
    }

    // 解析 "static:" 前缀
    let (actual_sig, force_static) = if let Some(stripped) = sig_str.strip_prefix("static:") {
        (stripped.to_string(), true)
    } else {
        (sig_str.clone(), false)
    };

    // 初始化 JNI
    let env = match ensure_jni_initialized() {
        Ok(e) => e,
        Err(msg) => return throw_internal_error(ctx, msg),
    };

    // 解析 ArtMethod
    let (art_method, is_static) =
        match resolve_art_method(env, &class_name, &method_name, &actual_sig, force_static) {
            Ok(r) => r,
            Err(msg) => return throw_internal_error(ctx, msg),
        };

    // 检查是否已 hook — 如果是，直接替换回调（无需 unhook+rehook）
    init_java_registry();
    if with_registry(&JAVA_HOOK_REGISTRY, |r| r.contains_key(&art_method)).unwrap_or(false) {
        let new_callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());

        let old_callback_bytes = with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
            if let Some(hook_data) = registry.get_mut(&art_method) {
                let old_bytes = hook_data.callback_bytes;
                hook_data.callback_bytes = new_callback_bytes;
                hook_data.ctx = ctx as usize;
                Some(old_bytes)
            } else {
                None
            }
        })
        .flatten();

        if let Some(old_bytes) = old_callback_bytes {
            let old_callback: ffi::JSValue =
                std::ptr::read(old_bytes.as_ptr() as *const ffi::JSValue);
            ffi::qjs_free_value(ctx, old_callback);
        }

        output_message(&format!(
            "[java hook] 回调已替换: {}.{}{}",
            class_name, method_name, actual_sig
        ));

        return JSValue::bool(true).raw();
    }

    // 探测 ArtMethod 布局（惰性，一次性）
    let spec = get_art_method_spec(env, art_method);
    let ep_offset = spec.entry_point_offset;
    let data_off = spec.data_offset;

    // ================================================================
    // Step 1: fetchArtMethod — 读取原始方法的 4 个关键字段
    // ================================================================
    let original_access_flags =
        std::ptr::read_volatile((art_method as usize + spec.access_flags_offset) as *const u32);
    let original_data = std::ptr::read_volatile((art_method as usize + data_off) as *const u64);
    let original_entry_point = read_entry_point(art_method, ep_offset);

    output_message(&format!(
        "[java hook] Step 1 fetchArtMethod: art_method={:#x}, flags={:#x}, data_={:#x}, ep={:#x}",
        art_method, original_access_flags, original_data, original_entry_point
    ));

    // ================================================================
    // Step 2: 检查 Xposed (kAccXposedHookedMethod = 0x10000000)
    // 注意: 0x10000000 在 Android 12+ (API 30+) 等于 kAccIntrinsic，
    // 所有内部方法 (String.length, Integer.parseInt 等) 都设置了此标志。
    // 仅在 API < 30 时检查以避免误报。
    // ================================================================
    {
        let api_level = get_android_api_level();
        if api_level < 30 && (original_access_flags & K_ACC_XPOSED_HOOKED_METHOD) != 0 {
            output_message(&format!(
                "[java hook] Step 2: Xposed hooked method detected (flags={:#x}), proceeding with caution",
                original_access_flags
            ));
        }
    }

    // ================================================================
    // Step 3: cloneArtMethod — 堆分配 backup clone (callOriginal 用)
    // ================================================================
    let clone_size = spec.size;
    let clone_addr = {
        let ptr = libc::malloc(clone_size);
        if ptr.is_null() {
            return throw_internal_error(ctx, "malloc failed for ArtMethod backup clone");
        }
        std::ptr::copy_nonoverlapping(art_method as *const u8, ptr as *mut u8, clone_size);
        ptr as u64
    };

    output_message(&format!(
        "[java hook] Step 3 clone: backup={:#x} (size={})",
        clone_addr, clone_size
    ));

    // 发现 ART bridge 函数（惰性，一次性）
    let bridge = find_art_bridge_functions(env, ep_offset);

    let jni_trampoline = bridge.quick_generic_jni_trampoline;
    if jni_trampoline == 0 {
        libc::free(clone_addr as *mut std::ffi::c_void);
        return throw_internal_error(ctx, "failed to find art_quick_generic_jni_trampoline");
    }

    // 创建 JNI global ref（callOriginal 用）
    let class_global_ref = {
        let cls = find_class_safe(env, &class_name);
        if cls.is_null() {
            libc::free(clone_addr as *mut std::ffi::c_void);
            return throw_internal_error(
                ctx,
                format!("FindClass('{}') failed for global ref", class_name),
            );
        }
        let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
        let delete_local_ref: DeleteLocalRefFn =
            jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
        let gref = new_global_ref(env, cls);
        delete_local_ref(env, cls);
        gref as usize
    };

    let return_type = get_return_type_from_sig(&actual_sig);

    // ================================================================
    // Step 4: 创建 replacement ArtMethod (统一: native, jniCode=thunk, quickCode=jni_trampoline)
    // ================================================================

    // 判断是否为编译方法 (quickCode 不在 libart.so 内)
    let has_independent_code = !is_art_quick_entrypoint(original_entry_point, bridge);

    output_message(&format!(
        "[java hook] Step 4: has_independent_code={} (ep={:#x})",
        has_independent_code, original_entry_point
    ));

    // 创建 native thunk (callback when method is called via JNI trampoline)
    let thunk = hook_ffi::hook_create_native_trampoline(
        art_method,
        Some(java_hook_callback),
        art_method as *mut std::ffi::c_void,
    );

    if thunk.is_null() {
        libc::free(clone_addr as *mut std::ffi::c_void);
        if class_global_ref != 0 {
            if let Ok(env) = get_thread_env() {
                let delete_global_ref: DeleteGlobalRefFn =
                    jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
                delete_global_ref(env, class_global_ref as *mut std::ffi::c_void);
            }
        }
        return throw_internal_error(ctx, "hook_create_native_trampoline failed");
    }

    // 创建 replacement ArtMethod (native method with our thunk)
    let replacement_addr = {
        let ptr = libc::malloc(clone_size);
        if ptr.is_null() {
            libc::free(clone_addr as *mut std::ffi::c_void);
            hook_ffi::hook_remove_redirect(art_method);
            if class_global_ref != 0 {
                if let Ok(env) = get_thread_env() {
                    let delete_global_ref: DeleteGlobalRefFn =
                        jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
                    delete_global_ref(env, class_global_ref as *mut std::ffi::c_void);
                }
            }
            return throw_internal_error(ctx, "malloc failed for replacement ArtMethod");
        }
        std::ptr::copy_nonoverlapping(art_method as *const u8, ptr as *mut u8, clone_size);

        let repl = ptr as usize;

        let repl_flags = (original_access_flags
            & !(K_ACC_CRITICAL_NATIVE | K_ACC_FAST_NATIVE | K_ACC_NTERP_ENTRY_POINT_FAST_PATH))
            | K_ACC_NATIVE
            | k_acc_compile_dont_bother();
        std::ptr::write_volatile((repl + spec.access_flags_offset) as *mut u32, repl_flags);
        std::ptr::write_volatile((repl + data_off) as *mut u64, thunk as u64);
        std::ptr::write_volatile((repl + ep_offset) as *mut u64, jni_trampoline);
        hook_ffi::hook_flush_cache(ptr, clone_size);

        output_message(&format!(
            "[java hook] Step 4 replacement: addr={:#x}, flags={:#x}, data_={:#x}, ep={:#x}",
            repl, repl_flags, thunk as u64, jni_trampoline
        ));

        repl
    };

    // ================================================================
    // Step 5: 修改 ORIGINAL — accessFlags (所有方法)
    //
    // 清除:
    //   kAccFastInterpreterToInterpreterInvoke — 阻止解释器走快速路径绕过 entry_point
    //   kAccSingleImplementation — 阻止虚调用去虚化优化
    //   kAccNterpEntryPointFastPath — 阻止 Nterp 快速路径
    //   kAccSkipAccessChecks — 阻止 access check 跳过 (非 native 方法)
    // 设置:
    //   kAccCompileDontBother — 阻止 JIT 重编译/内联
    //
    // 关键: kAccFastInterpreterToInterpreterInvoke (0x40000000) 必须清除，否则
    // 解释器会直接调用 artInterpreterToInterpreterBridge() 而不经过
    // entry_point 分发，导致 Layer 1 hook 被完全绕过。
    // ================================================================
    {
        let mut removed_flags = K_ACC_FAST_INTERP_TO_INTERP
            | K_ACC_SINGLE_IMPLEMENTATION
            | K_ACC_NTERP_ENTRY_POINT_FAST_PATH;
        if (original_access_flags & K_ACC_NATIVE) == 0 {
            removed_flags |= K_ACC_SKIP_ACCESS_CHECKS;
        }
        let new_flags = (original_access_flags & !removed_flags) | k_acc_compile_dont_bother();
        std::ptr::write_volatile(
            (art_method as usize + spec.access_flags_offset) as *mut u32,
            new_flags,
        );
        output_message(&format!(
            "[java hook] Step 5 original flags: {:#x} → {:#x}",
            original_access_flags, new_flags
        ));
    }

    // ================================================================
    // Step 7: 确保 artController 已初始化 (Layer 1 + Layer 2)
    // ================================================================
    ensure_art_controller_initialized(bridge, ep_offset, env as *mut std::ffi::c_void);

    // ================================================================
    // Step 8: 注册 replacedMethods 映射 (所有方法统一注册)
    // ================================================================
    set_replacement_method(art_method, replacement_addr as u64);
    output_message(&format!(
        "[java hook] Step 8: replacedMethods.set({:#x}, {:#x})",
        art_method, replacement_addr
    ));

    // Debug: verify table was populated and scan works
    hook_ffi::hook_art_router_table_dump();
    hook_ffi::hook_art_router_debug_scan(art_method);

    // ================================================================
    // Step 9: 拦截方法调用
    //
    // 编译方法 (has_independent_code=true):
    //   安装 Layer 3 per-method 路由 hook (inline patch 独立编译代码)
    //   backup_clone.quickCode = trampoline (绕过路由 hook)
    //
    // 共享 stub 方法 (has_independent_code=false):
    //   不做 inline patch (避免破坏 libart.so 共享代码)
    //   原子写入 entry_point = jni_trampoline (Layer 1 router 拦截)
    //   backup_clone 保持原始 quickCode (不在 replacedMethods 中，router 不拦截)
    // ================================================================
    let per_method_hook_target = if has_independent_code {
        // --- 编译方法: Layer 3 inline hook ---
        let mut hooked_target: *mut std::ffi::c_void = std::ptr::null_mut();
        let trampoline = hook_ffi::hook_install_art_router(
            original_entry_point as *mut std::ffi::c_void,
            ep_offset as u32,
            stealth_flag(),
            env as *mut std::ffi::c_void,
            &mut hooked_target,
        );

        if trampoline.is_null() {
            delete_replacement_method(art_method);
            hook_ffi::hook_remove_redirect(art_method);
            libc::free(replacement_addr as *mut std::ffi::c_void);
            libc::free(clone_addr as *mut std::ffi::c_void);
            std::ptr::write_volatile(
                (art_method as usize + spec.access_flags_offset) as *mut u32,
                original_access_flags,
            );
            if class_global_ref != 0 {
                if let Ok(env) = get_thread_env() {
                    let delete_global_ref: DeleteGlobalRefFn =
                        jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
                    delete_global_ref(env, class_global_ref as *mut std::ffi::c_void);
                }
            }
            return throw_internal_error(ctx, "hook_install_art_router failed");
        }

        // backup_clone.quickCode = trampoline (绕过路由 hook, callOriginal 用)
        std::ptr::write_volatile(
            (clone_addr as usize + ep_offset) as *mut u64,
            trampoline as u64,
        );
        hook_ffi::hook_flush_cache(
            (clone_addr as usize + ep_offset) as *mut std::ffi::c_void,
            8,
        );

        // 使用实际被 hook 的地址 (可能经过 resolve_art_trampoline 解析)
        let actual_hook_target = if !hooked_target.is_null() {
            hooked_target as u64
        } else {
            original_entry_point
        };
        output_message(&format!(
            "[java hook] Step 9: Layer 3 installed: ep={:#x} (hooked={:#x}), trampoline={:#x}",
            original_entry_point, actual_hook_target, trampoline as u64
        ));

        Some(actual_hook_target)
    } else {
        // --- 共享 stub 方法: Frida 风格 nterp 降级 ---
        // Nterp 特判: nterp → interpreter_bridge (libart → libart，无非 ART 地址暴露)
        // 其他共享 stub (jni_trampoline, interpreter_bridge, resolution_trampoline)
        // 不改 entry_point，完全依赖 Layer 1 + Layer 2 路由
        if bridge.nterp_entry_point != 0 && original_entry_point == bridge.nterp_entry_point {
            let interp_bridge = bridge.quick_to_interpreter_bridge;
            if interp_bridge != 0 {
                std::ptr::write_volatile(
                    (art_method as usize + ep_offset) as *mut u64,
                    interp_bridge,
                );
                hook_ffi::hook_flush_cache(
                    (art_method as usize + ep_offset) as *mut std::ffi::c_void,
                    8,
                );
                output_message(&format!(
                    "[java hook] Step 9: nterp 降级: ep {:#x} → interpreter_bridge {:#x}",
                    original_entry_point, interp_bridge
                ));
            }
        } else {
            output_message(&format!(
                "[java hook] Step 9: 共享 stub, 依赖 Layer 1+2 路由: ep={:#x}",
                original_entry_point
            ));
        }
        None
    };

    // ================================================================
    // Step 11: 注册 JAVA_HOOK_REGISTRY
    // ================================================================
    let callback_bytes = dup_callback_to_bytes(ctx, callback_arg.raw());

    with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.insert(
            art_method,
            JavaHookData {
                art_method,
                original_access_flags,
                original_entry_point,
                original_data,
                hook_type: HookType::Replaced {
                    replacement_addr,
                    per_method_hook_target,
                },
                clone_addr,
                class_global_ref,
                return_type,
                return_type_sig: get_return_type_sig(&actual_sig),
                ctx: ctx as usize,
                callback_bytes,
                method_key: method_key(&class_name, &method_name, &actual_sig),
                is_static,
                param_count: count_jni_params(&actual_sig),
                param_types: parse_jni_param_types(&actual_sig),
                class_name: class_name.clone(),
            },
        );
    });

    // 预缓存字段信息
    cache_fields_for_class(env, &class_name);

    let strategy = if has_independent_code {
        "compiled+router"
    } else {
        "shared_stub"
    };
    output_message(&format!(
        "[java hook] 完成: {}.{}{} (ArtMethod={:#x}, strategy={})",
        class_name, method_name, actual_sig, art_method, strategy
    ));

    JSValue::bool(true).raw()
}

// ============================================================================
// JS API: Java.unhook(class, method, sig)
//
// 统一 unhook 流程:
// 1. 有 per_method_hook: hook_remove(quickCode)
// 2. hook_remove_redirect (移除 native trampoline)
// 3. 恢复全部 ArtMethod 字段 (accessFlags, data_, entry_point_)
// 4. 删除 replacedMethods 映射
// 5. 释放 replacement ArtMethod
// 6. 释放资源 (clone, global ref, JS callback)
// ============================================================================

pub(super) unsafe extern "C" fn js_java_unhook(
    ctx: *mut ffi::JSContext,
    _this: ffi::JSValue,
    argc: i32,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    if argc < 3 {
        return ffi::JS_ThrowTypeError(
            ctx,
            b"Java.unhook() requires 3 arguments: class, method, signature\0".as_ptr() as *const _,
        );
    }

    let class_arg = JSValue(*argv);
    let method_arg = JSValue(*argv.add(1));
    let sig_arg = JSValue(*argv.add(2));

    let class_name = match extract_string_arg(
        ctx,
        class_arg,
        b"Java.unhook() first argument must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let method_name = match extract_string_arg(
        ctx,
        method_arg,
        b"Java.unhook() second argument must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    let sig_str = match extract_string_arg(
        ctx,
        sig_arg,
        b"Java.unhook() third argument must be a string\0",
    ) {
        Ok(value) => value,
        Err(err) => return err,
    };

    // 处理 "static:" 前缀
    let actual_sig = if let Some(stripped) = sig_str.strip_prefix("static:") {
        stripped.to_string()
    } else {
        sig_str
    };

    let key = method_key(&class_name, &method_name, &actual_sig);

    // 查找 art_method 地址
    let art_method_addr = with_registry(&JAVA_HOOK_REGISTRY, |registry| {
        registry
            .iter()
            .find(|(_, v)| v.method_key == key)
            .map(|(k, _)| *k)
    })
    .flatten();

    let art_method_addr = match art_method_addr {
        Some(am) => am,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"method not hooked\0".as_ptr() as *const _);
        }
    };

    // 从 registry 移除 entry
    let hook_data = with_registry_mut(&JAVA_HOOK_REGISTRY, |registry| {
        registry.remove(&art_method_addr)
    })
    .flatten();

    let hook_data = match hook_data {
        Some(d) => d,
        None => {
            return ffi::JS_ThrowInternalError(ctx, b"method not hooked\0".as_ptr() as *const _);
        }
    };

    // 统一 unhook 流程
    match &hook_data.hook_type {
        HookType::Replaced {
            replacement_addr,
            per_method_hook_target,
        } => {
            output_message(&format!(
                "[java unhook] 开始: art_method={:#x}, replacement={:#x}, per_method={:?}",
                hook_data.art_method, replacement_addr, per_method_hook_target
            ));

            // Step 1: 删除 replacedMethods 映射 (先删，防止路由到已释放的 replacement)
            delete_replacement_method(hook_data.art_method);
            output_message("[java unhook] Step 1: replacedMethods 已删除");

            // Step 2: 移除 per-method 路由 hook (Layer 3, if any)
            if let Some(target) = per_method_hook_target {
                hook_ffi::hook_remove(*target as *mut std::ffi::c_void);
                output_message(&format!(
                    "[java unhook] Step 2: Layer 3 hook 已移除: {:#x}",
                    target
                ));
            }

            // Step 3: 恢复全部 ArtMethod 字段
            if let Some(spec) = ART_METHOD_SPEC.get() {
                let ep_offset = spec.entry_point_offset;
                let data_off = spec.data_offset;

                // 恢复 access_flags_
                std::ptr::write_volatile(
                    (hook_data.art_method as usize + spec.access_flags_offset) as *mut u32,
                    hook_data.original_access_flags,
                );

                // 恢复 data_ (jniCode)
                std::ptr::write_volatile(
                    (hook_data.art_method as usize + data_off) as *mut u64,
                    hook_data.original_data,
                );

                // 恢复 entry_point_ (quickCode)
                std::ptr::write_volatile(
                    (hook_data.art_method as usize + ep_offset) as *mut u64,
                    hook_data.original_entry_point,
                );

                hook_ffi::hook_flush_cache(
                    (hook_data.art_method as usize) as *mut std::ffi::c_void,
                    ep_offset + 8,
                );
                output_message("[java unhook] Step 3: ArtMethod 字段已恢复");
            }

            // Step 4: 移除 native trampoline (redirect entry)
            hook_ffi::hook_remove_redirect(hook_data.art_method);
            output_message("[java unhook] Step 4: native trampoline 已移除");

            // Step 5: 释放 replacement ArtMethod
            // NOTE: 延迟释放 — 其他线程可能仍在 ART 栈帧中引用 replacement
            // 暂不释放，避免 use-after-free (32 bytes 泄漏可接受)
            // if *replacement_addr != 0 {
            //     libc::free(*replacement_addr as *mut std::ffi::c_void);
            // }
            output_message("[java unhook] Step 5: replacement 保留 (避免 UAF)");
        }
    }

    // Step 6: 释放 backup clone (callOriginal)
    if hook_data.clone_addr != 0 {
        libc::free(hook_data.clone_addr as *mut std::ffi::c_void);
    }

    // 删除 JNI global ref
    if hook_data.class_global_ref != 0 {
        if let Ok(env) = get_thread_env() {
            let delete_global_ref: DeleteGlobalRefFn =
                jni_fn!(env, DeleteGlobalRefFn, JNI_DELETE_GLOBAL_REF);
            delete_global_ref(env, hook_data.class_global_ref as *mut std::ffi::c_void);
        }
    }

    // 释放 JS callback
    let js_ctx = hook_data.ctx as *mut ffi::JSContext;
    let callback: ffi::JSValue =
        std::ptr::read(hook_data.callback_bytes.as_ptr() as *const ffi::JSValue);
    ffi::qjs_free_value(js_ctx, callback);

    output_message(&format!(
        "[java unhook] 完成: {}.{}{}",
        class_name, method_name, actual_sig
    ));

    JSValue::bool(true).raw()
}
