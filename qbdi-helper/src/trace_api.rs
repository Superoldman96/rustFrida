use crate::data::{
    DynamicExecChunk, ExternalReturn, MemAccess, TraceBundleEvent, TraceBundleEventKind,
    TraceContext,
};
use crate::state::{
    clear_last_error, helper_log, set_last_error, set_trace_output_dir, ExecMap,
    ADDED_DYNAMIC_RANGES, DUMPED_DYNAMIC_RANGES, TRACE_EXECUTED_INSTRUCTIONS,
    DYNAMIC_EXEC_CHUNK_SIZE, TRACE_MAX_INSTRUCTIONS, TRACE_PROGRESS_EVERY, TRACE_STACK_SIZE,
};
use crate::writer::{finalize_trace_session_async, shutdown_trace_writer, start_trace_writer, trace_send};
use qbdi::ffi::{
    qbdi_addInstrumentedRange, InstPosition_QBDI_PREINST, MemoryAccessType_QBDI_MEMORY_READ,
    VMAction_QBDI_CONTINUE, VMAction_QBDI_STOP, VMEvent_QBDI_EXEC_TRANSFER_CALL,
    VMEvent_QBDI_EXEC_TRANSFER_RETURN, VMInstanceRef,
};
use qbdi::{simulate_call, FPRState, GPRState, VMAction, VMRef, VM, VirtualStack};
use std::ffi::{c_char, c_void, CStr};
use std::os::unix::fs::FileExt;
use std::ptr::null_mut;
use std::sync::atomic::Ordering;

extern "C" fn qbdicb(
    _vm: VMInstanceRef,
    gpr_state: *mut GPRState,
    _fpr_state: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if !gpr_state.is_null() {
            let count = TRACE_EXECUTED_INSTRUCTIONS.fetch_add(1, Ordering::Relaxed) + 1;
            trace_send(TraceBundleEvent {
                kind: Some(TraceBundleEventKind::InstructionAddr((*gpr_state).pc)),
            });
            if count % TRACE_PROGRESS_EVERY == 0 {
                helper_log(&format!(
                    "[qbdi-helper] trace progress: instructions={} pc={:#x}",
                    count, (*gpr_state).pc
                ));
            }
            if count >= TRACE_MAX_INSTRUCTIONS {
                helper_log(&format!(
                    "[qbdi-helper] trace stopped at instruction cap {} (pc={:#x})",
                    TRACE_MAX_INSTRUCTIONS,
                    (*gpr_state).pc
                ));
                return VMAction_QBDI_STOP;
            }
        }
    }
    VMAction_QBDI_CONTINUE
}

extern "C" fn mem_acc_cb(
    vm: VMInstanceRef,
    _gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        let accesses = VMRef::from_raw(vm).get_inst_memory_access();
        for acc in accesses {
            if !acc.is_read() {
                continue;
            }
            trace_send(TraceBundleEvent {
                kind: Some(TraceBundleEventKind::MemAccess(MemAccess {
                    inst_addr: acc.inst_address(),
                    access_addr: acc.access_address(),
                    value: acc.value(),
                    size: acc.size() as u32,
                })),
            });
        }
    }
    VMAction_QBDI_CONTINUE
}

extern "C" fn exec_transfer_return_cb(
    _vm: VMInstanceRef,
    event: *const qbdi::ffi::VMState,
    gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if !event.is_null() && !gpr.is_null() {
            trace_send(TraceBundleEvent {
                kind: Some(TraceBundleEventKind::ExternalReturn(ExternalReturn {
                    return_addr: (*gpr).pc,
                    return_value: (*gpr).x0,
                })),
            });
        }
    }
    VMAction_QBDI_CONTINUE
}

fn read_proc_self_maps() -> Option<String> {
    let bytes = std::fs::read("/proc/self/maps").ok()?;
    Some(
        String::from_utf8(bytes)
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned()),
    )
}

fn is_executable(perms: &str) -> bool {
    perms.as_bytes().get(2) == Some(&b'x')
}

fn read_exec_maps() -> Result<Vec<ExecMap>, String> {
    let maps = read_proc_self_maps().ok_or_else(|| "failed to read /proc/self/maps".to_string())?;
    Ok(maps
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let range = fields.next()?;
            let perms = fields.next()?;
            let _offset = fields.next()?;
            let _dev = fields.next()?;
            let _inode = fields.next()?;
            let path = fields.next().unwrap_or("");

            if !is_executable(perms) {
                return None;
            }

            let mut parts = range.splitn(2, '-');
            let start = u64::from_str_radix(parts.next()?, 16).ok()?;
            let end = u64::from_str_radix(parts.next()?, 16).ok()?;
            Some(ExecMap {
                start,
                end,
                perms: perms.to_string(),
                path: path.to_string(),
            })
        })
        .collect())
}

fn find_exec_map(target: u64) -> Option<ExecMap> {
    read_exec_maps()
        .ok()?
        .into_iter()
        .find(|entry| target >= entry.start && target < entry.end)
}

fn is_special_kernel_map(path: &str) -> bool {
    matches!(path, "[vdso]" | "[vectors]" | "[vsyscall]" | "[sigpage]")
}

fn is_dynamic_exec_map(map: &ExecMap) -> bool {
    if !is_executable(&map.perms) {
        return false;
    }
    if map.path.is_empty() {
        return true;
    }
    if map.path.starts_with("[anon:")
        || map.path.starts_with("/dev/ashmem")
        || map.path.contains("memfd:")
        || map.path.ends_with(" (deleted)")
    {
        return true;
    }
    map.path.starts_with('[') && !is_special_kernel_map(&map.path)
}

pub(crate) fn collect_exec_ranges(target: u64) -> Result<Vec<ExecMap>, String> {
    let entries = read_exec_maps()?;
    let containing = entries
        .iter()
        .find(|entry| target >= entry.start && target < entry.end)
        .ok_or_else(|| format!("target {:#x} not found in /proc/self/maps", target))?;

    let mut ranges: Vec<ExecMap> = if !containing.path.is_empty() && !is_dynamic_exec_map(containing)
    {
        entries
            .iter()
            .filter(|entry| entry.path == containing.path && is_executable(&entry.perms))
            .cloned()
            .collect()
    } else {
        vec![containing.clone()]
    };

    for entry in entries.into_iter().filter(is_dynamic_exec_map) {
        if !ranges
            .iter()
            .any(|existing| existing.start == entry.start && existing.end == entry.end)
        {
            ranges.push(entry);
        }
    }

    if ranges.is_empty() {
        Err(format!("no executable range found for target {:#x}", target))
    } else {
        Ok(ranges)
    }
}

fn perms_to_u32(perms: &str) -> u32 {
    let bytes = perms.as_bytes();
    let mut prot = 0u32;
    if bytes.first() == Some(&b'r') {
        prot |= 1;
    }
    if bytes.get(1) == Some(&b'w') {
        prot |= 2;
    }
    if bytes.get(2) == Some(&b'x') {
        prot |= 4;
    }
    prot
}

fn sanitize_path_component(path: &str) -> String {
    let trimmed = if path.is_empty() { "anon" } else { path };
    trimmed
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn dump_dynamic_exec_map(map: &ExecMap) {
    if !is_dynamic_exec_map(map) {
        return;
    }
    {
        let mut dumped = DUMPED_DYNAMIC_RANGES.lock().unwrap_or_else(|e| e.into_inner());
        if !dumped.insert((map.start, map.end)) {
            return;
        }
    }
    let Some(base) = crate::state::TRACE_OUTPUT_DIR.get() else {
        return;
    };
    let Ok(mem_file) = std::fs::File::open("/proc/self/mem") else {
        return;
    };
    let size = (map.end - map.start) as usize;
    let mut data = vec![0u8; size];
    let mut offset = 0usize;
    while offset < size {
        match mem_file.read_at(&mut data[offset..], map.start + offset as u64) {
            Ok(0) => break,
            Ok(n) => offset += n,
            Err(_) => return,
        }
    }
    data.truncate(offset);

    let perm = perms_to_u32(&map.perms);
    for (chunk_index, chunk) in data.chunks(DYNAMIC_EXEC_CHUNK_SIZE).enumerate() {
        trace_send(TraceBundleEvent {
            kind: Some(TraceBundleEventKind::DynamicExecChunk(DynamicExecChunk {
                start_addr: map.start,
                end_addr: map.end,
                perm,
                path: map.path.clone(),
                chunk_offset: (chunk_index * DYNAMIC_EXEC_CHUNK_SIZE) as u64,
                data: chunk.to_vec(),
            })),
        });
    }

    let file_path = format!(
        "{}/qbdi_mmap_{:x}_{:x}_{}.bin",
        base,
        map.start,
        map.end,
        sanitize_path_component(&map.path)
    );
    let _ = std::fs::write(&file_path, &data);
}

pub(crate) fn ensure_dynamic_exec_range_instrumented(vm: VMInstanceRef, map: &ExecMap) {
    if !is_dynamic_exec_map(map) {
        return;
    }
    let mut added = ADDED_DYNAMIC_RANGES.lock().unwrap_or_else(|e| e.into_inner());
    if added.insert((map.start, map.end)) {
        unsafe {
            qbdi_addInstrumentedRange(vm, map.start, map.end);
        }
    }
}

extern "C" fn exec_transfer_call_cb(
    vm: VMInstanceRef,
    event: *const qbdi::ffi::VMState,
    _gpr: *mut GPRState,
    _fpr: *mut FPRState,
    _data: *mut c_void,
) -> VMAction {
    unsafe {
        if event.is_null() {
            return VMAction_QBDI_CONTINUE;
        }
        let dest = (*event).basicBlockStart;
        if let Some(map) = find_exec_map(dest) {
            if !is_dynamic_exec_map(&map) {
                return VMAction_QBDI_CONTINUE;
            }
            ensure_dynamic_exec_range_instrumented(vm, &map);
            dump_dynamic_exec_map(&map);
        }
    }
    VMAction_QBDI_CONTINUE
}

fn setup_simulated_call_context(vm: &VM, args: &[u64]) -> Result<VirtualStack, String> {
    let gpr = vm.gpr_state().ok_or_else(|| "QBDI GPRState is null".to_string())?;
    *gpr = GPRState::new();

    let stack = VirtualStack::new(gpr as *mut GPRState, TRACE_STACK_SIZE)
        .ok_or_else(|| format!("QBDI allocateVirtualStack({:#x}) failed", TRACE_STACK_SIZE))?;

    simulate_call(gpr, 0, args);

    let fpr = vm.fpr_state();
    *fpr = FPRState::new();

    Ok(stack)
}

fn snapshot_trace_context(vm: &VM, target: u64) -> Result<TraceContext, String> {
    let gpr = vm.gpr_state().ok_or_else(|| "QBDI GPRState is null".to_string())?;
    let fpr = vm.fpr_state();

    let x = vec![
        gpr.x0, gpr.x1, gpr.x2, gpr.x3, gpr.x4, gpr.x5, gpr.x6, gpr.x7, gpr.x8, gpr.x9, gpr.x10,
        gpr.x11, gpr.x12, gpr.x13, gpr.x14, gpr.x15, gpr.x16, gpr.x17, gpr.x18, gpr.x19, gpr.x20,
        gpr.x21, gpr.x22, gpr.x23, gpr.x24, gpr.x25, gpr.x26, gpr.x27, gpr.x28, gpr.x29, gpr.lr,
    ];
    let q_regs = [
        fpr.v0, fpr.v1, fpr.v2, fpr.v3, fpr.v4, fpr.v5, fpr.v6, fpr.v7, fpr.v8, fpr.v9, fpr.v10,
        fpr.v11, fpr.v12, fpr.v13, fpr.v14, fpr.v15, fpr.v16, fpr.v17, fpr.v18, fpr.v19, fpr.v20,
        fpr.v21, fpr.v22, fpr.v23, fpr.v24, fpr.v25, fpr.v26, fpr.v27, fpr.v28, fpr.v29, fpr.v30,
        fpr.v31,
    ];
    let mut q = Vec::with_capacity(64);
    for value in q_regs {
        q.push(value as u64);
        q.push((value >> 64) as u64);
    }

    Ok(TraceContext {
        x,
        sp: gpr.sp,
        pc: target,
        nzcv: gpr.nzcv,
        tpidr_el0: 0,
        q,
        fpcr: fpr.fpcr,
        fpsr: fpr.fpsr,
    })
}

fn run_hook_trace_impl(args: &[u64], target: u64) -> Result<u64, String> {
    {
        ADDED_DYNAMIC_RANGES.lock().unwrap_or_else(|e| e.into_inner()).clear();
        DUMPED_DYNAMIC_RANGES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
    let ranges = collect_exec_ranges(target)?;
    let vm = VM::new();
    for map in &ranges {
        vm.add_instrumented_range(map.start, map.end);
        if is_dynamic_exec_map(map) {
            ADDED_DYNAMIC_RANGES
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert((map.start, map.end));
            dump_dynamic_exec_map(map);
        }
    }
    let _stack = setup_simulated_call_context(&vm, args)?;
    trace_send(TraceBundleEvent {
        kind: Some(TraceBundleEventKind::TraceContext(snapshot_trace_context(&vm, target)?)),
    });
    vm.add_code_cb(InstPosition_QBDI_PREINST, Some(qbdicb), null_mut(), 0);
    let _ = vm.record_memory_access(MemoryAccessType_QBDI_MEMORY_READ);
    vm.add_mem_access_cb(
        MemoryAccessType_QBDI_MEMORY_READ,
        Some(mem_acc_cb),
        null_mut(),
        0,
    );
    vm.add_vm_event_cb(
        VMEvent_QBDI_EXEC_TRANSFER_CALL,
        Some(exec_transfer_call_cb),
        null_mut(),
    );
    vm.add_vm_event_cb(
        VMEvent_QBDI_EXEC_TRANSFER_RETURN,
        Some(exec_transfer_return_cb),
        null_mut(),
    );
    if !vm.run(target, 0) {
        return Err(format!("QBDI vm.run({:#x}) failed", target));
    }
    vm.gpr_state()
        .map(|gpr| gpr.x0)
        .ok_or_else(|| "QBDI GPRState missing after run".to_string())
}

#[no_mangle]
pub extern "C" fn qbdi_trace_run(
    args_ptr: *const u64,
    args_len: u32,
    target: u64,
    output_dir: *const c_char,
    result_out: *mut u64,
) -> i32 {
    clear_last_error();
    if output_dir.is_null() || result_out.is_null() {
        set_last_error("invalid arguments");
        return -1;
    }
    let args = match crate::state::decode_args(args_ptr, args_len) {
        Ok(args) => args,
        Err(err) => {
            set_last_error(err);
            return -1;
        }
    };
    let output_dir = unsafe { CStr::from_ptr(output_dir) }
        .to_str()
        .map_err(|_| "invalid output_dir")
        .and_then(|path| if path.is_empty() { Err("empty output_dir") } else { Ok(path) });
    let output_dir = match output_dir {
        Ok(path) => path,
        Err(msg) => {
            set_last_error(msg);
            return -1;
        }
    };
    set_trace_output_dir(output_dir);
    if let Err(err) = start_trace_writer() {
        set_last_error(err);
        return -1;
    }
    match run_hook_trace_impl(args, target) {
        Ok(value) => {
            finalize_trace_session_async();
            unsafe { *result_out = value; }
            0
        }
        Err(err) => {
            finalize_trace_session_async();
            set_last_error(&err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_trace_shutdown() {
    shutdown_trace_writer();
}

#[no_mangle]
pub extern "C" fn qbdi_vm_register_trace_callbacks(
    handle: u64,
    target: u64,
    output_dir: *const c_char,
) -> i32 {
    clear_last_error();
    if output_dir.is_null() {
        set_last_error("output_dir is null");
        return -1;
    }
    let output_dir = match unsafe { CStr::from_ptr(output_dir) }.to_str() {
        Ok(path) if !path.is_empty() => path,
        Ok(_) => {
            set_last_error("empty output_dir");
            return -1;
        }
        Err(_) => {
            set_last_error("invalid output_dir");
            return -1;
        }
    };
    set_trace_output_dir(output_dir);
    if let Err(err) = start_trace_writer() {
        set_last_error(err);
        return -1;
    }

    let result = crate::state::with_vm(handle, |managed| {
        managed.vm.delete_all_instrumentations();
        managed.trace_callback_ids.clear();
        ADDED_DYNAMIC_RANGES.lock().unwrap_or_else(|e| e.into_inner()).clear();
        DUMPED_DYNAMIC_RANGES
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();

        let ranges = collect_exec_ranges(target)?;
        for map in &ranges {
            managed.vm.add_instrumented_range(map.start, map.end);
            if is_dynamic_exec_map(map) {
                ADDED_DYNAMIC_RANGES
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert((map.start, map.end));
                dump_dynamic_exec_map(map);
            }
        }

        trace_send(TraceBundleEvent {
            kind: Some(TraceBundleEventKind::TraceContext(snapshot_trace_context(&managed.vm, target)?)),
        });

        let code_cb = managed
            .vm
            .add_code_cb(InstPosition_QBDI_PREINST, Some(qbdicb), null_mut(), 0);
        let _ = managed.vm.record_memory_access(MemoryAccessType_QBDI_MEMORY_READ);
        let mem_cb = managed.vm.add_mem_access_cb(
            MemoryAccessType_QBDI_MEMORY_READ,
            Some(mem_acc_cb),
            null_mut(),
            0,
        );
        let call_cb = managed.vm.add_vm_event_cb(
            VMEvent_QBDI_EXEC_TRANSFER_CALL,
            Some(exec_transfer_call_cb),
            null_mut(),
        );
        let ret_cb = managed.vm.add_vm_event_cb(
            VMEvent_QBDI_EXEC_TRANSFER_RETURN,
            Some(exec_transfer_return_cb),
            null_mut(),
        );
        managed.trace_callback_ids = vec![code_cb, mem_cb, call_cb, ret_cb];
        Ok(())
    });

    match result {
        Ok(()) => 0,
        Err(err) => {
            finalize_trace_session_async();
            set_last_error(err);
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn qbdi_vm_unregister_trace_callbacks(handle: u64) -> i32 {
    clear_last_error();
    match crate::state::with_vm(handle, |managed| {
        for id in managed.trace_callback_ids.drain(..) {
            let _ = managed.vm.delete_instrumentation(id);
        }
        Ok(())
    }) {
        Ok(()) => 0,
        Err(err) => {
            set_last_error(err);
            -1
        }
    }
}
