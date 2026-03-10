// ============================================================================
// callOriginal() — JS CFunction invoked from user's hook callback
// ============================================================================

/// Dispatch a JNI call via either static or nonvirtual variant, based on `$is_static`.
/// Consolidates the static/instance arms into one match expression.
macro_rules! dispatch_call {
    ($env:expr, $static_idx:expr, $nonvirt_idx:expr,
     $cls:expr, $this:expr, $mid:expr, $args:expr, $is_static:expr, $ret_ty:ty) => {{
        if $is_static {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> $ret_ty;
            let f: F = jni_fn!($env, F, $static_idx);
            f($env, $cls, $mid, $args)
        } else {
            type F = unsafe extern "C" fn(
                JniEnv,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *mut std::ffi::c_void,
                *const std::ffi::c_void,
            ) -> $ret_ty;
            let f: F = jni_fn!($env, F, $nonvirt_idx);
            f($env, $this, $cls, $mid, $args)
        }
    }};
}

/// Convert a JS value to a JNI jvalue (u64) based on the parameter type descriptor.
///
/// Handles: primitives (Z/B/C/S/I/J/F/D), String (JS string → NewStringUTF),
/// objects ({__jptr} or Proxy → extract raw pointer), BigUint64 (raw pointer),
/// null/undefined → 0.
unsafe fn marshal_js_to_jvalue(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    val: JSValue,
    type_sig: Option<&str>,
) -> u64 {
    if val.is_null() || val.is_undefined() {
        return 0;
    }

    let sig = match type_sig {
        Some(s) if !s.is_empty() => s,
        _ => {
            // No type info — try number or bigint
            return js_value_to_u64_or_zero(ctx, val);
        }
    };

    match sig.as_bytes()[0] {
        b'Z' => {
            if let Some(b) = val.to_bool() {
                b as u64
            } else if let Some(n) = val.to_i64(ctx) {
                (n != 0) as u64
            } else {
                0
            }
        }
        b'B' | b'S' | b'I' => {
            if let Some(n) = val.to_i64(ctx) {
                n as u64
            } else {
                0
            }
        }
        b'C' => {
            // char: JS string (first char) or number
            if let Some(s) = val.to_string(ctx) {
                s.chars().next().map(|c| c as u64).unwrap_or(0)
            } else if let Some(n) = val.to_i64(ctx) {
                n as u64
            } else {
                0
            }
        }
        b'J' => {
            js_value_to_u64_or_zero(ctx, val)
        }
        b'F' => {
            if let Some(f) = val.to_float() {
                (f as f32).to_bits() as u64
            } else {
                0
            }
        }
        b'D' => {
            if let Some(f) = val.to_float() {
                f.to_bits()
            } else {
                0
            }
        }
        b'L' | b'[' => {
            // JS string → NewStringUTF (must check before to_u64, which coerces strings to NaN→0)
            if val.is_string() {
                if sig == "Ljava/lang/String;" {
                    if let Some(s) = val.to_string(ctx) {
                        let cstr = match CString::new(s) {
                            Ok(c) => c,
                            Err(_) => return 0,
                        };
                        let new_str: NewStringUtfFn =
                            jni_fn!(env, NewStringUtfFn, JNI_NEW_STRING_UTF);
                        let jstr = new_str(env, cstr.as_ptr());
                        return jstr as u64;
                    }
                }
                // Non-String object param with string value — toString won't help, return 0
                return 0;
            }
            // JS object → try __jptr property (Proxy-wrapped or {__jptr, __jclass})
            if val.is_object() {
                let jptr_val = val.get_property(ctx, "__jptr");
                if !jptr_val.is_undefined() && !jptr_val.is_null() {
                    let result = js_value_to_u64_or_zero(ctx, jptr_val);
                    jptr_val.free(ctx);
                    return result;
                }
                jptr_val.free(ctx);
            }
            // BigUint64 or number (raw jobject pointer)
            js_value_to_u64_or_zero(ctx, val)
        }
        _ => js_value_to_u64_or_zero(ctx, val),
    }
}

/// Invoke cloned ArtMethod via JNI using provided jvalue args.
///
/// Shared by `js_call_original` (JS callback) and fallback path (JS engine busy).
/// Returns the raw u64 return value for writing to HookContext.x[0].
/// For void methods, returns 0.
unsafe fn invoke_clone_jni(
    env: JniEnv,
    art_method_addr: u64,
    clone_addr: u64,
    class_global_ref: usize,
    this_obj: u64,
    return_type: u8,
    is_static: bool,
    jargs_ptr: *const std::ffi::c_void,
) -> u64 {
    // Sync declaring_class_ (offset 0, 4B GcRoot): original → clone
    let declaring_class = std::ptr::read_volatile(art_method_addr as *const u32);
    std::ptr::write_volatile(clone_addr as *mut u32, declaring_class);
    jni_check_exc(env);

    let clone_mid = clone_addr as *mut std::ffi::c_void;
    let cls = class_global_ref as *mut std::ffi::c_void;
    let this_ptr = this_obj as *mut std::ffi::c_void;

    match return_type {
        b'V' => {
            dispatch_call!(
                env,
                JNI_CALL_STATIC_VOID_METHOD_A,
                JNI_CALL_NONVIRTUAL_VOID_METHOD_A,
                cls,
                this_ptr,
                clone_mid,
                jargs_ptr,
                is_static,
                ()
            );
            jni_check_exc(env);
            0
        }
        b'Z' => {
            let ret: u8 = dispatch_call!(
                env,
                JNI_CALL_STATIC_BOOLEAN_METHOD_A,
                JNI_CALL_NONVIRTUAL_BOOLEAN_METHOD_A,
                cls,
                this_ptr,
                clone_mid,
                jargs_ptr,
                is_static,
                u8
            );
            jni_check_exc(env);
            ret as u64
        }
        b'I' | b'B' | b'C' | b'S' => {
            let ret: i32 = dispatch_call!(
                env,
                JNI_CALL_STATIC_INT_METHOD_A,
                JNI_CALL_NONVIRTUAL_INT_METHOD_A,
                cls,
                this_ptr,
                clone_mid,
                jargs_ptr,
                is_static,
                i32
            );
            jni_check_exc(env);
            ret as u64
        }
        b'J' => {
            let ret: i64 = dispatch_call!(
                env,
                JNI_CALL_STATIC_LONG_METHOD_A,
                JNI_CALL_NONVIRTUAL_LONG_METHOD_A,
                cls,
                this_ptr,
                clone_mid,
                jargs_ptr,
                is_static,
                i64
            );
            jni_check_exc(env);
            ret as u64
        }
        b'F' => {
            let ret: f32 = dispatch_call!(
                env,
                JNI_CALL_STATIC_FLOAT_METHOD_A,
                JNI_CALL_NONVIRTUAL_FLOAT_METHOD_A,
                cls,
                this_ptr,
                clone_mid,
                jargs_ptr,
                is_static,
                f32
            );
            jni_check_exc(env);
            ret.to_bits() as u64
        }
        b'D' => {
            let ret: f64 = dispatch_call!(
                env,
                JNI_CALL_STATIC_DOUBLE_METHOD_A,
                JNI_CALL_NONVIRTUAL_DOUBLE_METHOD_A,
                cls,
                this_ptr,
                clone_mid,
                jargs_ptr,
                is_static,
                f64
            );
            jni_check_exc(env);
            ret.to_bits()
        }
        b'L' | b'[' => {
            let ret: *mut std::ffi::c_void = dispatch_call!(
                env,
                JNI_CALL_STATIC_OBJECT_METHOD_A,
                JNI_CALL_NONVIRTUAL_OBJECT_METHOD_A,
                cls,
                this_ptr,
                clone_mid,
                jargs_ptr,
                is_static,
                *mut std::ffi::c_void
            );
            jni_check_exc(env);
            ret as u64
        }
        _ => 0,
    }
}

/// Build jvalue args from HookContext registers (ARM64 JNI calling convention).
unsafe fn build_jargs_from_registers(
    hook_ctx: &hook_ffi::HookContext,
    param_count: usize,
    param_types: &[String],
) -> Vec<u64> {
    let mut jargs: Vec<u64> = Vec::with_capacity(param_count);
    let mut gp_index: usize = 0;
    let mut fp_index: usize = 0;
    for i in 0..param_count {
        let type_sig = param_types.get(i).map(|s| s.as_str());
        let (gp_val, fp_val) = extract_jni_arg(
            hook_ctx,
            is_floating_point_type(type_sig),
            &mut gp_index,
            &mut fp_index,
        );
        jargs.push(if is_floating_point_type(type_sig) {
            fp_val
        } else {
            gp_val
        });
    }
    jargs
}

/// JS CFunction: ctx.orig() or ctx.orig(arg0, arg1, ...)
///
/// No arguments: invokes the clone with the original register arguments.
/// With arguments: invokes the clone with user-specified arguments (JS → jvalue conversion).
///
/// Invokes the cloned ArtMethod via JNI CallNonvirtual*MethodA / CallStatic*MethodA.
/// Returns the method's return value as a JS value.
///
/// Must be called from within a java_hook_callback (reads CURRENT_HOOK_* globals).
unsafe extern "C" fn js_call_original(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    _argc: i32,
    _argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let art_method_addr = {
        let value = get_js_u64_property(ctx, this_val, "__hookArtMethod");
        if value != 0 {
            value
        } else {
            CURRENT_HOOK_ART_METHOD.load(Ordering::Relaxed)
        }
    };
    let ctx_ptr = {
        let value = get_js_u64_property(ctx, this_val, "__hookCtxPtr") as *mut hook_ffi::HookContext;
        if !value.is_null() {
            value
        } else {
            CURRENT_HOOK_CTX_PTR.load(Ordering::Relaxed) as *mut hook_ffi::HookContext
        }
    };
    if ctx_ptr.is_null() || art_method_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"orig() can only be called inside a hook callback\0".as_ptr() as *const _,
        );
    }

    // Look up hook data for clone info
    let (
        clone_addr,
        class_global_ref,
        return_type,
        return_type_sig,
        param_count,
        is_static,
        param_types,
    ) = {
        let guard = match JAVA_HOOK_REGISTRY.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        let registry = match guard.as_ref() {
            Some(r) => r,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"orig: hook registry not initialized\0".as_ptr() as *const _,
                );
            }
        };
        let data = match registry.get(&art_method_addr) {
            Some(d) => d,
            None => {
                return ffi::JS_ThrowInternalError(
                    ctx,
                    b"orig: hook data not found\0".as_ptr() as *const _,
                );
            }
        };
        (
            data.clone_addr,
            data.class_global_ref,
            data.return_type,
            data.return_type_sig.clone(),
            data.param_count,
            data.is_static,
            data.param_types.clone(),
        )
    }; // lock released

    if clone_addr == 0 {
        return ffi::JS_ThrowInternalError(
            ctx,
            b"orig: no ArtMethod clone available\0".as_ptr() as *const _,
        );
    }

    let hook_ctx = &*ctx_ptr;

    // Unified JNI calling convention: x0=JNIEnv*, x1=this/class, x2+=args
    let env: JniEnv = {
        let e = hook_ctx.x[0] as JniEnv;
        if e.is_null() {
            return ffi::JS_ThrowInternalError(
                ctx,
                b"orig: JNIEnv* is null\0".as_ptr() as *const _,
            );
        }
        e
    };

    // Build jvalue args: from user-specified JS args (if provided), or from registers.
    let jargs = if _argc > 0 && !_argv.is_null() {
        // User-specified arguments: convert JS values → jvalue
        let mut args: Vec<u64> = Vec::with_capacity(param_count);
        for i in 0..param_count {
            let type_sig = param_types.get(i).map(|s| s.as_str());
            if (i as i32) < _argc {
                let js_arg = JSValue(*_argv.add(i));
                args.push(marshal_js_to_jvalue(ctx, env, js_arg, type_sig));
            } else {
                // 不足的参数用原始寄存器值补齐
                let mut gp = i;
                let mut fp = i;
                let (gp_val, fp_val) =
                    extract_jni_arg(hook_ctx, is_floating_point_type(type_sig), &mut gp, &mut fp);
                args.push(if is_floating_point_type(type_sig) {
                    fp_val
                } else {
                    gp_val
                });
            }
        }
        args
    } else {
        // No arguments: use original register values
        build_jargs_from_registers(hook_ctx, param_count, &param_types)
    };
    let jargs_ptr = if param_count > 0 {
        jargs.as_ptr() as *const std::ffi::c_void
    } else {
        std::ptr::null()
    };

    // Invoke clone via shared JNI helper
    let ret_raw = invoke_clone_jni(
        env,
        art_method_addr,
        clone_addr,
        class_global_ref,
        hook_ctx.x[1],
        return_type,
        is_static,
        jargs_ptr,
    );

    // Convert raw return value to JS value
    match return_type {
        b'V' => ffi::qjs_undefined(),
        b'Z' => JSValue::bool(ret_raw != 0).raw(),
        b'I' | b'B' | b'C' | b'S' => JSValue::int(ret_raw as i32).raw(),
        b'J' => ffi::JS_NewBigUint64(ctx, ret_raw),
        b'F' => JSValue::float(f32::from_bits(ret_raw as u32) as f64).raw(),
        b'D' => JSValue::float(f64::from_bits(ret_raw)).raw(),
        b'L' | b'[' => {
            if ret_raw == 0 {
                ffi::qjs_null()
            } else {
                // Convert to readable JS value (String → JS string, objects → wrapped)
                // using the same logic as arg marshalling.
                marshal_jni_arg_to_js(ctx, env, ret_raw, 0, Some(&return_type_sig))
            }
        }
        _ => ffi::qjs_undefined(),
    }
}
