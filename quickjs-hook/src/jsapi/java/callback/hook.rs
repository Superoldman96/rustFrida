// ============================================================================
// Argument marshalling — convert raw JNI register values to JS values
// ============================================================================

/// Convert a raw JNI argument (from register) to a JS value based on its JNI type descriptor.
///
/// Primitive types become JS numbers/booleans/bigints.
/// String objects become JS strings (read via GetStringUTFChars).
/// Other objects become wrapped `{__jptr, __jclass}` for Proxy-based field access.
/// Falls back to BigUint64 if type info is unavailable.
///
/// `fp_raw`: value from the corresponding d-register (for float/double args).
unsafe fn marshal_jni_arg_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    raw: u64,
    fp_raw: u64,
    type_sig: Option<&str>,
) -> ffi::JSValue {
    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => return ffi::JS_NewBigUint64(ctx, raw),
    };

    match sig.as_bytes()[0] {
        b'Z' => JSValue::bool(raw != 0).raw(),
        b'B' => JSValue::int(raw as i8 as i32).raw(),
        b'C' => {
            // char → JS string (single UTF-16 character)
            let ch = std::char::from_u32(raw as u32).unwrap_or('\0');
            let s = ch.to_string();
            JSValue::string(ctx, &s).raw()
        }
        b'S' => JSValue::int(raw as i16 as i32).raw(),
        b'I' => JSValue::int(raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, raw),
        b'F' => {
            // ARM64 ABI: floats are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let f = f32::from_bits(fp_raw as u32);
            JSValue::float(f as f64).raw()
        }
        b'D' => {
            // ARM64 ABI: doubles are passed in d0-d7 (FP registers).
            // fp_raw comes from HookContext.d[fp_index].
            let d = f64::from_bits(fp_raw);
            JSValue::float(d).raw()
        }
        b'L' | b'[' => {
            // Object or array — raw is a jobject local ref
            let obj = raw as *mut std::ffi::c_void;
            if obj.is_null() {
                return ffi::qjs_null();
            }
            marshal_borrowed_java_object_to_js(ctx, env, obj, Some(sig))
        }
        _ => ffi::JS_NewBigUint64(ctx, raw),
    }
}

// ============================================================================
// Hook callback (runs in hooked thread, called by ART JNI trampoline)
// ============================================================================

/// Callback invoked by the native hook trampoline when a hooked Java method is called.
/// After "replace with native", ART's JNI trampoline calls our thunk which calls this.
///
/// HookContext contains JNI calling convention registers:
///   x0 = JNIEnv*, x1 = jobject this (instance) or jclass (static), x2-x7 = Java args
///
/// user_data = ArtMethod* address (used for registry lookup).
pub(super) unsafe extern "C" fn java_hook_callback(
    ctx_ptr: *mut hook_ffi::HookContext,
    user_data: *mut std::ffi::c_void,
) {
    if ctx_ptr.is_null() || user_data.is_null() {
        return;
    }

    // user_data is ArtMethod* address (used as registry key)
    let art_method_addr = user_data as u64;

    // Copy callback data then release lock before QuickJS operations.
    // Also extract clone info for fallback callOriginal when JS engine is busy.
    let (
        ctx_usize,
        callback_bytes,
        is_static,
        param_count,
        return_type,
        return_type_sig,
        param_types,
        clone_addr,
        class_global_ref,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(_) => {
                // Lock poisoned during cleanup — zero x0 to prevent returning garbage
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                // Registry taken during cleanup — zero x0 to prevent returning JNIEnv* as object
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        let hook_data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                // Hook data removed during cleanup — zero x0
                (*ctx_ptr).x[0] = 0;
                return;
            }
        };
        (
            hook_data.ctx,
            hook_data.callback_bytes,
            hook_data.is_static,
            hook_data.param_count,
            hook_data.return_type,
            hook_data.return_type_sig.clone(),
            hook_data.param_types.clone(),
            hook_data.clone_addr,
            hook_data.class_global_ref,
        )
    }; // lock released

    // Set callback state globals for js_call_original
    CURRENT_HOOK_CTX_PTR.store(ctx_ptr as usize, Ordering::Relaxed);
    CURRENT_HOOK_ART_METHOD.store(art_method_addr, Ordering::Relaxed);

    // Push local frame to protect JNI local refs from overflowing the table.
    // Each marshal_jni_arg_to_js call may create local refs (GetStringUTFChars, NewObject, etc.).
    let hook_ctx_env: JniEnv = (*ctx_ptr).x[0] as JniEnv;
    let has_local_frame = if !hook_ctx_env.is_null() {
        let push_frame: PushLocalFrameFn =
            jni_fn!(hook_ctx_env, PushLocalFrameFn, JNI_PUSH_LOCAL_FRAME);
        push_frame(hook_ctx_env, (2 + param_count * 2) as i32) == 0
    } else {
        false
    };

    // Track whether handle_result was called (false if JS exception occurred)
    let mut result_was_set = false;

    invoke_hook_callback_common(
        ctx_usize,
        &callback_bytes,
        "java hook",
        art_method_addr,
        // 构建 JS 上下文对象：thisObj, args[], env, orig()
        |ctx| {
            let js_ctx = ffi::JS_NewObject(ctx);
            let hook_ctx = &*ctx_ptr;
            let env: JniEnv = hook_ctx.x[0] as JniEnv;

            // thisObj for instance methods (x1 = jobject this)
            if !is_static {
                set_js_u64_property(ctx, js_ctx, "thisObj", hook_ctx.x[1]);
            }

            // args[] — ARM64 JNI calling convention (GP x2-x7, FP d0-d7 independent)
            {
                let arr = ffi::JS_NewArray(ctx);
                let mut gp_index: usize = 0;
                let mut fp_index: usize = 0;
                for i in 0..param_count {
                    let type_sig = param_types.get(i).map(|s| s.as_str());
                    let (raw, fp_raw) = extract_jni_arg(
                        hook_ctx,
                        is_floating_point_type(type_sig),
                        &mut gp_index,
                        &mut fp_index,
                    );
                    let val = marshal_jni_arg_to_js(ctx, env, raw, fp_raw, type_sig);
                    ffi::JS_SetPropertyUint32(ctx, arr, i as u32, val);
                }
                JSValue(js_ctx).set_property(ctx, "args", JSValue(arr));
            }

            // env (JNIEnv* — from x0)
            set_js_u64_property(ctx, js_ctx, "env", hook_ctx.x[0]);

            // Bind per-callback state to the JS context object so orig()
            // remains valid across nested hook callbacks and JS-side wrappers.
            set_js_u64_property(ctx, js_ctx, "__hookCtxPtr", ctx_ptr as usize as u64);
            set_js_u64_property(ctx, js_ctx, "__hookArtMethod", art_method_addr);

            // orig()
            set_js_cfunction_property(ctx, js_ctx, "orig", js_call_original, 0);

            js_ctx
        },
        // 处理返回值：根据 return_type 将 JS 返回值写入 HookContext.x[0]
        |ctx, _js_ctx, result| {
            result_was_set = true;
            if return_type != b'V' {
                let result_val = JSValue(result);
                let ret_u64 = match return_type {
                    b'F' => {
                        if let Some(f) = result_val.to_float() {
                            (f as f32).to_bits() as u64
                        } else {
                            0u64
                        }
                    }
                    b'D' => {
                        if let Some(f) = result_val.to_float() {
                            f.to_bits()
                        } else {
                            0u64
                        }
                    }
                    b'L' | b'[' => {
                        // Object/array return: marshal JS value back to JNI ref.
                        // Handles: JS string → NewStringUTF, __jptr wrapper → raw ref,
                        // BigUint64 → raw ref, null/undefined → 0.
                        let env: JniEnv = hook_ctx_env;
                        if !env.is_null() {
                            marshal_js_to_jvalue(ctx, env, result_val, Some(&return_type_sig))
                        } else {
                            js_value_to_u64_or_zero(ctx, result_val)
                        }
                    }
                    _ => {
                        js_value_to_u64_or_zero(ctx, result_val)
                    }
                };
                (*ctx_ptr).x[0] = ret_u64;
            }
        },
    );

    // Fallback: if JS callback was skipped (engine busy) or threw an exception,
    // handle_result was NOT called. We must still invoke the original method.
    //
    // For non-void methods, this avoids returning the entry JNIEnv* as if it were
    // a real return value. For void methods this is still required because skipping
    // the original call silently drops side effects; for constructors that means
    // the object may be returned without its <init> body having run.
    if !result_was_set {
        let hook_ctx = &*ctx_ptr;
        let env: JniEnv = hook_ctx.x[0] as JniEnv;
        if !env.is_null() && clone_addr != 0 {
            let jargs = build_jargs_from_registers(hook_ctx, param_count, &param_types);
            let jargs_ptr = if param_count > 0 {
                jargs.as_ptr() as *const std::ffi::c_void
            } else {
                std::ptr::null()
            };
            (*ctx_ptr).x[0] = invoke_clone_jni(
                env,
                art_method_addr,
                clone_addr,
                class_global_ref,
                hook_ctx.x[1],
                return_type,
                is_static,
                jargs_ptr,
            );
        } else {
            (*ctx_ptr).x[0] = 0;
        }
    }

    // Always PopLocalFrame to keep IRT segments balanced.
    // For object returns (L/[): PopLocalFrame(env, ret_obj) transfers the local ref
    // to the outer frame (ART's JNI transition frame) so GenericJniMethodEnd can find it.
    // For other types: PopLocalFrame(env, null) just cleans up.
    if has_local_frame && !hook_ctx_env.is_null() {
        let pop_frame: PopLocalFrameFn =
            jni_fn!(hook_ctx_env, PopLocalFrameFn, JNI_POP_LOCAL_FRAME);
        if return_type == b'L' || return_type == b'[' {
            let ret_obj = (*ctx_ptr).x[0] as *mut std::ffi::c_void;
            let preserved = pop_frame(hook_ctx_env, ret_obj);
            (*ctx_ptr).x[0] = preserved as u64;
        } else {
            pop_frame(hook_ctx_env, std::ptr::null_mut());
        }
    }

    // Clear callback state globals
    CURRENT_HOOK_CTX_PTR.store(0, Ordering::Relaxed);
    CURRENT_HOOK_ART_METHOD.store(0, Ordering::Relaxed);
}
