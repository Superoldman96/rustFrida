// ============================================================================
// ARM64 JNI calling convention helpers
// ============================================================================

/// 判断 JNI 类型签名是否表示浮点类型 (float/double)
#[inline]
fn is_floating_point_type(sig: Option<&str>) -> bool {
    matches!(sig, Some(s) if s.starts_with('F') || s.starts_with('D'))
}

/// 从 HookContext 中按 ARM64 JNI 调用约定提取单个参数值。
///
/// ARM64 JNI: GP 寄存器 (x2-x7) 和 FP 寄存器 (d0-d7) 有独立计数器。
/// 返回 (gp_value, fp_value) — 只有一个有意义。
#[inline]
unsafe fn extract_jni_arg(
    hook_ctx: &hook_ffi::HookContext,
    is_fp: bool,
    gp_index: &mut usize,
    fp_index: &mut usize,
) -> (u64, u64) {
    if is_fp {
        let fp_val = if *fp_index < 8 {
            hook_ctx.d[*fp_index]
        } else {
            0u64
        };
        *fp_index += 1;
        (0u64, fp_val)
    } else {
        let gp_val = if *gp_index < 6 {
            hook_ctx.x[2 + *gp_index]
        } else {
            let sp = hook_ctx.sp as usize;
            *((sp + (*gp_index - 6) * 8) as *const u64)
        };
        *gp_index += 1;
        (gp_val, 0u64)
    }
}

#[inline]
fn jni_object_sig_to_class_name(jni_sig: &str) -> String {
    if jni_sig.starts_with('L') && jni_sig.ends_with(';') && jni_sig.len() >= 2 {
        jni_sig[1..jni_sig.len() - 1].replace('/', ".")
    } else {
        jni_sig.replace('/', ".")
    }
}

unsafe fn get_runtime_class_name(env: JniEnv, obj: *mut std::ffi::c_void) -> Option<String> {
    let reflect = REFLECT_IDS.get()?;
    let get_object_class: GetObjectClassFn = jni_fn!(env, GetObjectClassFn, JNI_GET_OBJECT_CLASS);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
    let rel_str: ReleaseStringUtfCharsFn =
        jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let cls_obj = get_object_class(env, obj);
    if cls_obj.is_null() || jni_check_exc(env) {
        return None;
    }

    let name_jstr = call_obj(env, cls_obj, reflect.class_get_name_mid, std::ptr::null());
    delete_local_ref(env, cls_obj);
    if name_jstr.is_null() || jni_check_exc(env) {
        return None;
    }

    let chars = get_str(env, name_jstr, std::ptr::null_mut());
    if chars.is_null() {
        delete_local_ref(env, name_jstr);
        jni_check_exc(env);
        return None;
    }

    let name = std::ffi::CStr::from_ptr(chars)
        .to_string_lossy()
        .to_string();
    rel_str(env, name_jstr, chars);
    delete_local_ref(env, name_jstr);
    Some(name)
}

unsafe fn wrap_java_object_value(
    ctx: *mut ffi::JSContext,
    raw_ptr: u64,
    class_name: &str,
) -> ffi::JSValue {
    let wrapper = ffi::JS_NewObject(ctx);
    let wrapper_val = JSValue(wrapper);

    let ptr_val = ffi::JS_NewBigUint64(ctx, raw_ptr);
    wrapper_val.set_property(ctx, "__jptr", JSValue(ptr_val));

    let cls_val = JSValue::string(ctx, class_name);
    wrapper_val.set_property(ctx, "__jclass", cls_val);

    wrapper
}

const MAX_JAVA_CONTAINER_DEPTH: usize = 16;

unsafe fn wrap_java_object_ref(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name: &str,
    globalize: bool,
) -> ffi::JSValue {
    if obj.is_null() {
        return ffi::qjs_null();
    }

    if !globalize {
        return wrap_java_object_value(ctx, obj as u64, class_name);
    }

    let new_global_ref: NewGlobalRefFn = jni_fn!(env, NewGlobalRefFn, JNI_NEW_GLOBAL_REF);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);
    let global_ref = new_global_ref(env, obj);
    delete_local_ref(env, obj);
    if global_ref.is_null() || jni_check_exc(env) {
        return ffi::qjs_null();
    }

    wrap_java_object_value(ctx, global_ref as u64, class_name)
}

unsafe fn is_java_list_instance(env: JniEnv, obj: *mut std::ffi::c_void) -> bool {
    if obj.is_null() {
        return false;
    }

    let reflect = match REFLECT_IDS.get() {
        Some(ids) if !ids.list_class.is_null() => ids,
        _ => return false,
    };
    let is_instance_of: IsInstanceOfFn = jni_fn!(env, IsInstanceOfFn, JNI_IS_INSTANCE_OF);
    is_instance_of(env, obj, reflect.list_class) != 0 && !jni_check_exc(env)
}

unsafe fn try_unbox_boxed_primitive(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name: &str,
    release_local: bool,
) -> Option<ffi::JSValue> {
    let reflect = REFLECT_IDS.get()?;
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let value = match class_name {
        "java.lang.Boolean" => {
            if reflect.boolean_value_mid.is_null() {
                return None;
            }
            let f: CallBooleanMethodAFn =
                jni_fn!(env, CallBooleanMethodAFn, JNI_CALL_BOOLEAN_METHOD_A);
            JSValue::bool(f(env, obj, reflect.boolean_value_mid, std::ptr::null()) != 0).raw()
        }
        "java.lang.Byte" => {
            if reflect.byte_value_mid.is_null() {
                return None;
            }
            let f: CallByteMethodAFn = jni_fn!(env, CallByteMethodAFn, JNI_CALL_BYTE_METHOD_A);
            JSValue::int(f(env, obj, reflect.byte_value_mid, std::ptr::null()) as i32).raw()
        }
        "java.lang.Character" => {
            if reflect.char_value_mid.is_null() {
                return None;
            }
            let f: CallCharMethodAFn = jni_fn!(env, CallCharMethodAFn, JNI_CALL_CHAR_METHOD_A);
            let ch = std::char::from_u32(f(env, obj, reflect.char_value_mid, std::ptr::null()) as u32)
                .unwrap_or('\0')
                .to_string();
            JSValue::string(ctx, &ch).raw()
        }
        "java.lang.Short" => {
            if reflect.short_value_mid.is_null() {
                return None;
            }
            let f: CallShortMethodAFn =
                jni_fn!(env, CallShortMethodAFn, JNI_CALL_SHORT_METHOD_A);
            JSValue::int(f(env, obj, reflect.short_value_mid, std::ptr::null()) as i32).raw()
        }
        "java.lang.Integer" => {
            if reflect.int_value_mid.is_null() {
                return None;
            }
            let f: CallIntMethodAFn = jni_fn!(env, CallIntMethodAFn, JNI_CALL_INT_METHOD_A);
            JSValue::int(f(env, obj, reflect.int_value_mid, std::ptr::null())).raw()
        }
        "java.lang.Long" => {
            if reflect.long_value_mid.is_null() {
                return None;
            }
            let f: CallLongMethodAFn = jni_fn!(env, CallLongMethodAFn, JNI_CALL_LONG_METHOD_A);
            ffi::JS_NewBigUint64(ctx, f(env, obj, reflect.long_value_mid, std::ptr::null()) as u64)
        }
        "java.lang.Float" => {
            if reflect.float_value_mid.is_null() {
                return None;
            }
            let f: CallFloatMethodAFn = jni_fn!(env, CallFloatMethodAFn, JNI_CALL_FLOAT_METHOD_A);
            JSValue::float(f(env, obj, reflect.float_value_mid, std::ptr::null()) as f64).raw()
        }
        "java.lang.Double" => {
            if reflect.double_value_mid.is_null() {
                return None;
            }
            let f: CallDoubleMethodAFn =
                jni_fn!(env, CallDoubleMethodAFn, JNI_CALL_DOUBLE_METHOD_A);
            JSValue::float(f(env, obj, reflect.double_value_mid, std::ptr::null())).raw()
        }
        _ => return None,
    };

    if release_local {
        delete_local_ref(env, obj);
    }

    if jni_check_exc(env) {
        return Some(ffi::qjs_null());
    }

    Some(value)
}

unsafe fn marshal_java_object_to_js_inner(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name_hint: Option<&str>,
    release_local: bool,
    globalize_wrappers: bool,
    depth: usize,
) -> ffi::JSValue {
    if obj.is_null() {
        return ffi::qjs_null();
    }

    let class_name = get_runtime_class_name(env, obj).unwrap_or_else(|| {
        class_name_hint
            .map(jni_object_sig_to_class_name)
            .unwrap_or_else(|| "java.lang.Object".to_string())
    });

    if class_name == "java.lang.String" {
        let get_str: GetStringUtfCharsFn = jni_fn!(env, GetStringUtfCharsFn, JNI_GET_STRING_UTF_CHARS);
        let rel_str: ReleaseStringUtfCharsFn =
            jni_fn!(env, ReleaseStringUtfCharsFn, JNI_RELEASE_STRING_UTF_CHARS);
        let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

        let chars = get_str(env, obj, std::ptr::null_mut());
        if !chars.is_null() {
            let s = std::ffi::CStr::from_ptr(chars)
                .to_string_lossy()
                .to_string();
            rel_str(env, obj, chars);
            if release_local {
                delete_local_ref(env, obj);
            }
            return JSValue::string(ctx, &s).raw();
        }

        jni_check_exc(env);
    }

    if let Some(value) = try_unbox_boxed_primitive(ctx, env, obj, &class_name, release_local) {
        return value;
    }

    if depth < MAX_JAVA_CONTAINER_DEPTH {
        if class_name.starts_with('[') {
            if let Some(value) = convert_java_array_to_js(
                ctx,
                env,
                obj,
                release_local,
                globalize_wrappers,
                depth + 1,
            ) {
                return value;
            }
        } else if is_java_list_instance(env, obj) {
            if let Some(value) = convert_java_list_to_js(
                ctx,
                env,
                obj,
                release_local,
                globalize_wrappers,
                depth + 1,
            ) {
                return value;
            }
        }
    }

    if release_local {
        return wrap_java_object_ref(ctx, env, obj, &class_name, globalize_wrappers);
    }

    wrap_java_object_value(ctx, obj as u64, &class_name)
}

unsafe fn convert_java_array_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    array_obj: *mut std::ffi::c_void,
    release_local: bool,
    globalize_wrappers: bool,
    depth: usize,
) -> Option<ffi::JSValue> {
    let reflect = REFLECT_IDS.get()?;
    if reflect.array_class.is_null()
        || reflect.array_get_length_mid.is_null()
        || reflect.array_get_mid.is_null()
    {
        return None;
    }

    let call_static_int: CallStaticIntMethodAFn =
        jni_fn!(env, CallStaticIntMethodAFn, JNI_CALL_STATIC_INT_METHOD_A);
    let call_static_obj: CallStaticObjectMethodAFn =
        jni_fn!(env, CallStaticObjectMethodAFn, JNI_CALL_STATIC_OBJECT_METHOD_A);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let len_args = [array_obj as u64];
    let len = call_static_int(
        env,
        reflect.array_class,
        reflect.array_get_length_mid,
        len_args.as_ptr() as *const std::ffi::c_void,
    );
    if jni_check_exc(env) {
        if release_local {
            delete_local_ref(env, array_obj);
        }
        return None;
    }

    let arr = ffi::JS_NewArray(ctx);
    for i in 0..len.max(0) {
        let elem_args = [array_obj as u64, i as u64];
        let elem = call_static_obj(
            env,
            reflect.array_class,
            reflect.array_get_mid,
            elem_args.as_ptr() as *const std::ffi::c_void,
        );
        if jni_check_exc(env) {
            if !elem.is_null() {
                delete_local_ref(env, elem);
            }
            if release_local {
                delete_local_ref(env, array_obj);
            }
            return None;
        }

        let value = marshal_java_object_to_js_inner(
            ctx,
            env,
            elem,
            None,
            true,
            globalize_wrappers,
            depth,
        );
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, value);
    }

    if release_local {
        delete_local_ref(env, array_obj);
    }

    Some(arr)
}

unsafe fn convert_java_list_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    list_obj: *mut std::ffi::c_void,
    release_local: bool,
    globalize_wrappers: bool,
    depth: usize,
) -> Option<ffi::JSValue> {
    let reflect = REFLECT_IDS.get()?;
    if reflect.list_size_mid.is_null() || reflect.list_get_mid.is_null() {
        return None;
    }

    let call_int: CallIntMethodAFn = jni_fn!(env, CallIntMethodAFn, JNI_CALL_INT_METHOD_A);
    let call_obj: CallObjectMethodAFn = jni_fn!(env, CallObjectMethodAFn, JNI_CALL_OBJECT_METHOD_A);
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    let len = call_int(env, list_obj, reflect.list_size_mid, std::ptr::null());
    if jni_check_exc(env) {
        if release_local {
            delete_local_ref(env, list_obj);
        }
        return None;
    }

    let arr = ffi::JS_NewArray(ctx);
    for i in 0..len.max(0) {
        let elem_args = [i as u64];
        let elem = call_obj(
            env,
            list_obj,
            reflect.list_get_mid,
            elem_args.as_ptr() as *const std::ffi::c_void,
        );
        if jni_check_exc(env) {
            if !elem.is_null() {
                delete_local_ref(env, elem);
            }
            if release_local {
                delete_local_ref(env, list_obj);
            }
            return None;
        }

        let value = marshal_java_object_to_js_inner(
            ctx,
            env,
            elem,
            None,
            true,
            globalize_wrappers,
            depth,
        );
        ffi::JS_SetPropertyUint32(ctx, arr, i as u32, value);
    }

    if release_local {
        delete_local_ref(env, list_obj);
    }

    Some(arr)
}

unsafe fn marshal_borrowed_java_object_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name_hint: Option<&str>,
) -> ffi::JSValue {
    marshal_java_object_to_js_inner(ctx, env, obj, class_name_hint, false, false, 0)
}

pub(super) unsafe fn marshal_local_java_object_to_js(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    class_name_hint: Option<&str>,
) -> ffi::JSValue {
    marshal_java_object_to_js_inner(ctx, env, obj, class_name_hint, true, true, 0)
}

#[inline]
unsafe fn js_throw_type_error(ctx: *mut ffi::JSContext, msg: &[u8]) -> ffi::JSValue {
    throw_type_error(ctx, msg)
}

#[inline]
unsafe fn js_throw_internal_error(
    ctx: *mut ffi::JSContext,
    message: impl AsRef<str>,
) -> ffi::JSValue {
    throw_internal_error(ctx, message)
}

unsafe fn read_invoke_target_ptr(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
) -> Result<u64, ffi::JSValue> {
    let obj_ptr = extract_pointer_address(ctx, arg, "Java._invokeMethod").map_err(|_| {
        ffi::JS_ThrowTypeError(
            ctx,
            b"Java._invokeMethod() first argument must be a pointer (BigUint64/Number/NativePointer)\0"
                .as_ptr() as *const _,
        )
    })?;

    if obj_ptr == 0 {
        return Err(ffi::JS_ThrowTypeError(
            ctx,
            b"Java._invokeMethod() objPtr is null\0".as_ptr() as *const _,
        ));
    }

    Ok(obj_ptr)
}

unsafe fn read_string_arg(
    ctx: *mut ffi::JSContext,
    arg: JSValue,
    error_msg: &[u8],
) -> Result<String, ffi::JSValue> {
    extract_string_arg(ctx, arg, error_msg)
}

unsafe fn cleanup_local_refs(
    env: JniEnv,
    local_obj: *mut std::ffi::c_void,
    cls: *mut std::ffi::c_void,
) {
    let delete_local_ref: DeleteLocalRefFn = jni_fn!(env, DeleteLocalRefFn, JNI_DELETE_LOCAL_REF);

    if !local_obj.is_null() {
        delete_local_ref(env, local_obj);
    }
    if !cls.is_null() {
        delete_local_ref(env, cls);
    }
}

unsafe fn cleanup_and_throw_internal(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    local_obj: *mut std::ffi::c_void,
    cls: *mut std::ffi::c_void,
    message: impl AsRef<str>,
) -> ffi::JSValue {
    cleanup_local_refs(env, local_obj, cls);
    throw_internal_error(ctx, message)
}

unsafe fn cleanup_and_throw_type(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    local_obj: *mut std::ffi::c_void,
    cls: *mut std::ffi::c_void,
    msg: &[u8],
) -> ffi::JSValue {
    cleanup_local_refs(env, local_obj, cls);
    ffi::JS_ThrowTypeError(ctx, msg.as_ptr() as *const _)
}

unsafe fn build_invoke_jargs(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    argv: *mut ffi::JSValue,
    param_types: &[String],
) -> Vec<u64> {
    build_jargs_from_argv(ctx, env, argv, 4, param_types)
}

unsafe fn build_jargs_from_argv(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    argv: *mut ffi::JSValue,
    start_index: usize,
    param_types: &[String],
) -> Vec<u64> {
    let mut jargs = Vec::with_capacity(param_types.len());
    for (i, type_sig) in param_types.iter().enumerate() {
        let js_arg = JSValue(*argv.add(start_index + i));
        jargs.push(marshal_js_to_jvalue(
            ctx,
            env,
            js_arg,
            Some(type_sig.as_str()),
        ));
    }
    jargs
}

unsafe fn wrap_invoke_return_object(
    ctx: *mut ffi::JSContext,
    env: JniEnv,
    obj: *mut std::ffi::c_void,
    return_type_sig: &str,
) -> Result<ffi::JSValue, String> {
    if obj.is_null() {
        return Ok(ffi::qjs_null());
    }
    let value = marshal_local_java_object_to_js(ctx, env, obj, Some(return_type_sig));
    if JSValue(value).is_null() && !jni_check_exc(env) {
        return Err("Java._invokeMethod: failed to marshal return object".to_string());
    }
    Ok(value)
}
