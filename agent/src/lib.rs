#![cfg(all(target_os = "android", target_arch = "aarch64"))]

mod gumlibc;
mod jhook;
mod relocater;
mod trace;
mod writer;

#[cfg(feature = "qbdi")]
mod qbdi_trace;
#[cfg(feature = "quickjs")]
mod quickjs_loader;
#[cfg(feature = "frida-gum")]
mod stalker;

use crate::jhook::jhook;
use libc::{
    c_char, c_int, close, kill, mmap, munmap, pid_t, sockaddr, sockaddr_un, sysconf, AF_UNIX,
    MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, SIGSTOP, SIGTRAP, _SC_PAGESIZE,
};
use libc::{
    sigaction, siginfo_t, SA_ONSTACK, SA_SIGINFO, SIGABRT, SIGBUS, SIGFPE, SIGILL, SIGSEGV,
};
use std::ffi::{c_void, CStr};
use std::io::{BufRead, BufReader, Error, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::unix::io::FromRawFd;
use std::os::unix::net::UnixStream;
use std::process;
use std::ptr;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

#[cfg(feature = "frida-gum")]
use frida_gum::ModuleMap;

// 定义我们自己的Result类型，错误统一为String
type Result<T> = std::result::Result<T, String>;

// StringTable 结构定义（需要和 main.rs 中的定义完全一致）
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct StringTable {
    pub socket_name: u64,
    pub socket_name_len: u32,
    pub hello_msg: u64,
    pub hello_msg_len: u32,
    pub sym_name: u64,
    pub sym_name_len: u32,
    pub pthread_err: u64,
    pub pthread_err_len: u32,
    pub dlsym_err: u64,
    pub dlsym_err_len: u32,
    pub proc_path: u64,
    pub proc_path_len: u32,
    pub cmdline: u64,
    pub cmdline_len: u32,
    pub output_path: u64,
    pub output_path_len: u32,
}

impl StringTable {
    /// 从指针地址读取字符串（不包含末尾的 NULL）
    unsafe fn read_string(&self, addr: u64, len: u32) -> Option<String> {
        if addr == 0 || len == 0 {
            return None;
        }
        let ptr = addr as *const u8;
        let slice = std::slice::from_raw_parts(ptr, len as usize);
        // 去掉末尾的 NULL 字符
        let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        String::from_utf8(slice[..end].to_vec()).ok()
    }

    /// 获取 socket_name
    pub unsafe fn get_socket_name(&self) -> Option<String> {
        self.read_string(self.socket_name, self.socket_name_len)
    }

    /// 获取 cmdline
    pub unsafe fn get_cmdline(&self) -> Option<String> {
        self.read_string(self.cmdline, self.cmdline_len)
    }

    /// 获取 output_path
    pub unsafe fn get_output_path(&self) -> Option<String> {
        self.read_string(self.output_path, self.output_path_len)
    }
}

pub struct ExecMem {
    ptr: *mut u8,
    size: usize,
    used: usize,
    page_size: usize,
}

impl ExecMem {
    /// 新建一块可读写可执行内存（自动按页分配）
    pub fn new() -> Result<Self> {
        let page_size = unsafe { sysconf(_SC_PAGESIZE) as usize };
        unsafe {
            let ptr = mmap(
                ptr::null_mut(),
                page_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(Error::last_os_error().to_string());
            }
            Ok(ExecMem {
                ptr: ptr as *mut u8,
                size: page_size,
                used: 0,
                page_size,
            })
        }
    }

    /// 写入数据（容量不足时返回错误）
    pub fn write(&mut self, data: &[u8]) -> Result<*mut u8> {
        if self.used + data.len() > self.size {
            return Err(String::from("剩余exe_mem耗尽"));
        }
        unsafe {
            let start = self.ptr.add(self.used);
            ptr::copy_nonoverlapping(data.as_ptr(), start, data.len());
            self.used += data.len();
            Ok(start)
        }
    }

    pub fn reset(&mut self) {
        self.used = 0;
    }

    pub fn write_u32(&mut self, value: u32) -> Result<*mut u8> {
        let bytes = value.to_le_bytes(); // ARM64 小端
        self.write(&bytes)
    }

    pub fn current_addr(&self) -> usize {
        unsafe { self.ptr.add(self.used) as usize }
    }

    pub fn external_write_instruct(&mut self) -> usize {
        unsafe {
            let result = self.ptr.add(self.used) as usize;
            self.used += 4;
            result
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.ptr
    }
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }
    pub fn used(&self) -> usize {
        self.used
    }
    pub fn capacity(&self) -> usize {
        self.size
    }
    pub fn page_size(&self) -> usize {
        self.page_size
    }
}

impl Drop for ExecMem {
    fn drop(&mut self) {
        unsafe {
            munmap(self.ptr as *mut _, self.size);
        }
    }
}

fn connect_socket() -> Result<UnixStream> {
    // 优先使用 hello_entry() 从 StringTable 读取的动态 socket 名（rust_frida_{pid}），
    // 回退到旧的硬编码值（仅用于兼容老版本 host）
    let name_str = SOCKET_NAME
        .get()
        .map(|s| s.as_bytes().to_vec())
        .unwrap_or_else(|| b"rust_frida_socket".to_vec());
    let name = name_str.as_slice();

    let fd = unsafe { libc::socket(AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(format!("创建 socket 失败: {}", Error::last_os_error()));
    }

    // 构造 abstract sockaddr_un
    let mut addr: sockaddr_un = unsafe { zeroed() };
    addr.sun_family = AF_UNIX as u16;
    addr.sun_path[0] = 0; // abstract namespace
    for (i, &b) in name.iter().enumerate() {
        addr.sun_path[i + 1] = b as c_char;
    }

    // 计算 sockaddr_un 长度
    let addr_len = (size_of::<libc::sa_family_t>() + 1 + name.len()) as u32;

    // 连接
    let ret = unsafe { libc::connect(fd, &addr as *const _ as *const sockaddr, addr_len) };
    if ret != 0 {
        let err = Error::last_os_error();
        unsafe { close(fd) };
        return Err(format!("连接到套接字失败: {}", err));
    }

    // 用 Rust 的 UnixStream 包装 fd，方便写数据
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    Ok(stream)
}

/// agent 主循环退出标志，由 shutdown 命令设置
static SHOULD_EXIT: AtomicBool = AtomicBool::new(false);

static GLOBAL_STREAM: OnceLock<UnixStream> = OnceLock::new();
/// 动态 socket 名，由 hello_entry() 从 StringTable 读取后保存
static SOCKET_NAME: OnceLock<String> = OnceLock::new();
static CACHE_LOG: Mutex<Vec<String>> = Mutex::new(Vec::new());
pub static OUTPUT_PATH: OnceLock<String> = OnceLock::new();

/// 内存映射信息
struct MapEntry {
    start: usize,
    end: usize,
    name: String,
}

/// 根据地址查找所属的映射
fn find_map_for_addr(addr: usize, maps: &[MapEntry]) -> Option<&MapEntry> {
    maps.iter().find(|m| addr >= m.start && addr < m.end)
}

/// 判断是否是 memfd（agent 代码）
fn is_memfd(name: &String) -> bool {
    name.contains("memfd:")
}

// _Unwind_Backtrace 相关定义
type UnwindReasonCode = c_int;
type UnwindContext = c_void;

extern "C" {
    fn _Unwind_Backtrace(
        trace_fn: extern "C" fn(*mut UnwindContext, *mut c_void) -> UnwindReasonCode,
        data: *mut c_void,
    ) -> UnwindReasonCode;
    fn _Unwind_GetIP(ctx: *mut UnwindContext) -> usize;
}

/// dladdr 返回的符号信息结构体
#[repr(C)]
struct DlInfo {
    dli_fname: *const c_char, // 包含地址的共享库路径
    dli_fbase: *mut c_void,   // 共享库的基地址
    dli_sname: *const c_char, // 最近符号的名称
    dli_saddr: *mut c_void,   // 最近符号的地址
}

extern "C" {
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
}

/// 使用 dladdr 解析地址的符号信息
fn resolve_symbol(addr: usize) -> (Option<String>, Option<String>, usize) {
    unsafe {
        let mut info: DlInfo = zeroed();
        if dladdr(addr as *const c_void, &mut info) != 0 {
            // 获取库名
            let lib_name = if !info.dli_fname.is_null() {
                CStr::from_ptr(info.dli_fname)
                    .to_str()
                    .ok()
                    .map(|s| s.rsplit('/').next().unwrap_or(s).to_string())
            } else {
                None
            };

            // 获取符号名
            let sym_name = if !info.dli_sname.is_null() {
                CStr::from_ptr(info.dli_sname)
                    .to_str()
                    .ok()
                    .map(|s| s.to_string())
            } else {
                None
            };

            // 计算相对偏移（相对于库基址或符号地址）
            let offset = if !info.dli_saddr.is_null() {
                addr.saturating_sub(info.dli_saddr as usize)
            } else if !info.dli_fbase.is_null() {
                addr.saturating_sub(info.dli_fbase as usize)
            } else {
                0
            };

            (lib_name, sym_name, offset)
        } else {
            (None, None, 0)
        }
    }
}

struct BacktraceData {
    frames: Vec<usize>,
    max_frames: usize,
}

extern "C" fn unwind_callback(ctx: *mut UnwindContext, data: *mut c_void) -> UnwindReasonCode {
    unsafe {
        let bt_data = &mut *(data as *mut BacktraceData);
        if bt_data.frames.len() >= bt_data.max_frames {
            return 5; // _URC_END_OF_STACK
        }
        let ip = _Unwind_GetIP(ctx);
        if ip != 0 {
            bt_data.frames.push(ip);
        }
        0 // _URC_NO_REASON (continue)
    }
}

/// 使用 _Unwind_Backtrace 获取调用栈
fn collect_backtrace() -> Vec<usize> {
    let mut data = BacktraceData {
        frames: Vec::with_capacity(64),
        max_frames: 64,
    };
    unsafe {
        _Unwind_Backtrace(unwind_callback, &mut data as *mut _ as *mut c_void);
    }
    data.frames
}

/// abort_msg_t 结构体，与 bionic 中的定义一致
#[repr(C)]
struct AbortMsgT {
    size: usize,
    // msg[0] 紧随其后，是变长字符数组
}

/// 获取 Android abort message
/// Android bionic 在 abort() 时会将消息存储在 __abort_message
fn get_abort_message() -> Option<String> {
    unsafe {
        let libc_name = std::ffi::CString::new("libc.so").ok()?;
        let handle = libc::dlopen(libc_name.as_ptr(), libc::RTLD_NOLOAD);
        if handle.is_null() {
            return None;
        }

        // 方法1：尝试使用 android_get_abort_message() API (API 21+)
        let api_name = std::ffi::CString::new("android_get_abort_message").ok()?;
        let api_ptr = libc::dlsym(handle, api_name.as_ptr());

        if !api_ptr.is_null() {
            let get_abort_msg: extern "C" fn() -> *const c_char = std::mem::transmute(api_ptr);
            let msg_ptr = get_abort_msg();
            libc::dlclose(handle);
            if !msg_ptr.is_null() {
                let c_str = CStr::from_ptr(msg_ptr);
                return c_str.to_str().ok().map(|s| s.to_string());
            }
            return None;
        }

        // 方法2：直接读取 __abort_message 全局变量
        let sym_name = std::ffi::CString::new("__abort_message").ok()?;
        let ptr = libc::dlsym(handle, sym_name.as_ptr());
        libc::dlclose(handle);

        if ptr.is_null() {
            return None;
        }

        // __abort_message 是 abort_msg_t** 类型（全局变量的地址）
        let msg_ptr_ptr = ptr as *const *const AbortMsgT;
        let msg_ptr = *msg_ptr_ptr;

        if msg_ptr.is_null() {
            return None;
        }

        let msg_size = (*msg_ptr).size;
        if msg_size == 0 {
            return None;
        }

        // msg 字符串紧跟在 size 字段之后
        let msg_data = (msg_ptr as *const u8).add(std::mem::size_of::<usize>()) as *const c_char;
        let c_str = CStr::from_ptr(msg_data);
        c_str.to_str().ok().map(|s| s.to_string())
    }
}

/// 信号处理函数 - 打印崩溃信息和backtrace
extern "C" fn crash_signal_handler(sig: c_int, info: *mut siginfo_t, _ucontext: *mut c_void) {
    unsafe {
        let sig_name = match sig {
            SIGSEGV => "SIGSEGV (Segmentation Fault)",
            SIGBUS => "SIGBUS (Bus Error)",
            SIGABRT => "SIGABRT (Abort)",
            SIGFPE => "SIGFPE (Floating Point Exception)",
            SIGILL => "SIGILL (Illegal Instruction)",
            SIGTRAP => "SIGTRAP (Trap)",
            _ => "Unknown signal",
        };

        let fault_addr = if !info.is_null() {
            (*info).si_addr() as usize
        } else {
            0
        };

        // 构建崩溃信息
        let mut crash_msg = format!(
            "\n\n=== CRASH DETECTED ===\n\
             Signal: {} ({})\n\
             Fault Address: 0x{:x}\n\
             PID: {}\n\
             TID: {}\n",
            sig_name,
            sig,
            fault_addr,
            process::id(),
            libc::gettid()
        );

        // 如果是 SIGABRT，尝试获取 abort message
        if sig == SIGABRT {
            if let Some(abort_msg) = get_abort_message() {
                crash_msg.push_str(&format!("Abort Message: {}\n", abort_msg));
            }
        }

        crash_msg.push_str("\n=== BACKTRACE ===\n");

        // 使用 _Unwind_Backtrace 获取调用栈
        let frames = collect_backtrace();

        #[cfg(feature = "frida-gum")]
        {
            // 解析内存映射（需要 frida-gum）
            let mut mdmap = ModuleMap::new();
            mdmap.update();

            for (idx, &addr) in frames.iter().enumerate() {
                crash_msg.push_str(&format!("#{:<3} 0x{:016x}", idx, addr));

                if let Some(map) = mdmap.find(addr as u64) {
                    let offset = addr - map.range().base_address().0 as usize;
                    let mdname = map.name();
                    if is_memfd(&mdname) {
                        crash_msg.push_str(&format!(" (memfd+0x{:x})", offset));
                    } else {
                        let lib_name = mdname.rsplit('/').next().unwrap_or(mdname.as_str());
                        crash_msg.push_str(&format!(" {} +0x{:x}", lib_name, offset));
                    }
                } else {
                    crash_msg.push_str(" <unknown mapping>");
                }
                crash_msg.push('\n');
            }
        }

        #[cfg(not(feature = "frida-gum"))]
        {
            // 使用 dladdr 获取符号信息
            for (idx, &addr) in frames.iter().enumerate() {
                crash_msg.push_str(&format!("#{:<3} 0x{:016x}", idx, addr));

                let (lib_name, sym_name, offset) = resolve_symbol(addr);

                match (lib_name, sym_name) {
                    (Some(lib), Some(sym)) => {
                        if is_memfd(&lib) {
                            crash_msg.push_str(&format!(" (memfd) {}+0x{:x}", sym, offset));
                        } else {
                            crash_msg.push_str(&format!(" {} ({}+0x{:x})", lib, sym, offset));
                        }
                    }
                    (Some(lib), None) => {
                        if is_memfd(&lib) {
                            crash_msg.push_str(&format!(" (memfd+0x{:x})", offset));
                        } else {
                            crash_msg.push_str(&format!(" {} +0x{:x}", lib, offset));
                        }
                    }
                    _ => {
                        crash_msg.push_str(" <unknown>");
                    }
                }
                crash_msg.push('\n');
            }
        }

        crash_msg.push_str("=== END BACKTRACE ===\n\n");

        // 尝试通过 socket 发送
        if let Some(mut stream) = GLOBAL_STREAM.get() {
            let _ = stream.write_all(crash_msg.as_bytes());
        }

        // 重新抛出信号以便系统处理
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// 安装崩溃信号处理器
fn install_crash_handlers() {
    let signals = [SIGSEGV, SIGBUS, SIGABRT, SIGFPE, SIGILL, SIGTRAP];

    for &sig in &signals {
        unsafe {
            let mut sa: sigaction = std::mem::zeroed();
            sa.sa_sigaction = crash_signal_handler as usize;
            sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
            libc::sigemptyset(&mut sa.sa_mask);

            if sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                log_msg(format!("Failed to install handler for signal {}\n", sig));
            }
        }
    }

    // log_msg("Crash signal handlers installed\n".to_string());
}

/// 安装Rust panic hook，捕获panic并输出带符号的backtrace
fn install_panic_hook() {
    use std::backtrace::Backtrace;

    std::panic::set_hook(Box::new(|panic_info| {
        // 强制捕获backtrace，无视环境变量
        let bt = Backtrace::force_capture();

        // 获取panic位置
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        // 获取panic消息
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
            })
            .unwrap_or("unknown panic");

        let msg = format!(
            "\n\n=== RUST PANIC ===\n\
             Location: {}\n\
             Message: {}\n\
             PID: {}, TID: {}\n\n\
             Backtrace:\n{}\n\
             =================\n\n",
            location,
            payload,
            process::id(),
            unsafe { libc::gettid() },
            bt
        );

        log_msg(msg);
    }));
}

/// 日志函数：socket未连接时缓存，已连接时直接发送
/// 不添加 [agent] 前缀（host 侧 log_agent! 宏已添加）
fn log_msg(msg: String) {
    match GLOBAL_STREAM.get() {
        Some(mut stream) => {
            let _ = stream.write_all(msg.as_bytes());
        }
        None => {
            // Socket未连接，缓存日志
            if let Ok(mut cache) = CACHE_LOG.lock() {
                cache.push(msg);
            }
        }
    }
}

/// 刷新缓存的日志，在socket连接后调用
fn flush_cached_logs() {
    if let Some(mut stream) = GLOBAL_STREAM.get() {
        if let Ok(mut cache) = CACHE_LOG.lock() {
            for msg in cache.drain(..) {
                let _ = stream.write_all(msg.as_bytes());
            }
        }
    }
}
#[no_mangle]
pub extern "C" fn hello_entry(string_table: *mut c_void) -> *mut c_void {
    // 安装Rust panic hook（需要在最前面，捕获Rust层面的panic）
    install_panic_hook();
    // 安装崩溃信号处理器（捕获SIGSEGV等信号）
    install_crash_handlers();

    unsafe {
        // 解析 StringTable 结构
        let string_table = string_table as *const StringTable;
        let table = &*string_table;

        // 读取动态 socket 名（rust_frida_{pid}）并保存，connect_socket() 将使用它
        if let Some(sock) = table.get_socket_name() {
            if sock != "novalue" {
                let _ = SOCKET_NAME.set(sock);
            }
        }

        // 读取 output_path 并保存到全局变量
        if let Some(output) = table.get_output_path() {
            if output != "novalue" {
                let _ = OUTPUT_PATH.set(output.clone());
                // log_msg(format!("Output path: {}\n", output));
            }
        }

        // 读取 cmdline 参数
        if let Some(cmd) = table.get_cmdline() {
            if cmd != "novalue" {
                process_cmd(&cmd);
            }
        }
    }

    unsafe {
        let name = std::ffi::CString::new("wwb").unwrap();
        libc::pthread_setname_np(libc::pthread_self(), name.as_ptr());
    }

    // GLOBAL_STREAM.lock().unwrap().set(connect_socket().unwrap()).unwrap();
    GLOBAL_STREAM
        .set(connect_socket().expect("wwb connect socket failed!!!"))
        .unwrap();
    let mut stream = GLOBAL_STREAM.get().unwrap();
    let _ = stream.write("HELLO_AGENT\n".as_bytes()).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    flush_cached_logs();

    // 循环等待命令：BufReader + read_line 确保任意长度命令完整接收（无截断）
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                // 连接关闭（EOF）
                break;
            }
            Ok(_) => {
                let trimmed = line.trim();
                if !trimmed.is_empty() {
                    process_cmd(trimmed);
                }
                if SHOULD_EXIT.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(e) => {
                // 读取错误
                if let Some(mut s) = GLOBAL_STREAM.get() {
                    let _ = s.write_all(format!("读取命令错误: {}\n", e).as_bytes());
                }
                break;
            }
        }
    }
    null_mut()
}

fn process_cmd(command: &str) {
    match command.split_whitespace().next() {
        Some("trace") => {
            let tid = match command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<usize>().ok())
                .filter(|&t| t != 0)
            {
                Some(t) => t,
                None => {
                    log_msg("[trace] 用法: trace <tid>，tid 不能为 0\n".to_string());
                    return;
                }
            };
            std::thread::spawn(move || {
                match trace::gum_modify_thread(tid) {
                    Ok(pid) => {
                        if let Some(mut s) = GLOBAL_STREAM.get() {
                            let _ = s.write_all(format!("clone success {}", pid).as_bytes());
                        }
                    }
                    Err(e) => {
                        if let Some(mut s) = GLOBAL_STREAM.get() {
                            let _ = s.write_all(format!("error: {}", e).as_bytes());
                        }
                    }
                }
                unsafe { kill(process::id() as pid_t, SIGSTOP) }
            });
        }
        Some("jhook") => {
            std::thread::spawn(|| match jhook() {
                Ok(_) => {}
                Err(e) => {
                    if let Some(mut s) = GLOBAL_STREAM.get() {
                        let _ = s.write_all(format!("{}", e).as_bytes());
                    }
                }
            });
        }
        #[cfg(feature = "frida-gum")]
        Some("stalker") => {
            let tid = command
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            stalker::follow(tid)
        }
        #[cfg(feature = "frida-gum")]
        Some("hfl") => {
            let mut cmds = command.split_whitespace();
            let md = match cmds.nth(1) {
                Some(m) => m,
                None => {
                    log_msg("[hfl] 用法: hfl <module> <offset>\n".to_string());
                    return;
                }
            };
            let offset = cmds
                .next()
                .and_then(|s| {
                    let s = s.strip_prefix("0x").unwrap_or(s);
                    usize::from_str_radix(s, 16).ok()
                })
                .unwrap_or(0);
            stalker::hfollow(md, offset)
        }
        #[cfg(not(feature = "frida-gum"))]
        Some("hfl") | Some("stalker") => {
            log_msg("[agent] 当前构建不支持该命令，需要 frida-gum feature\n".to_string());
        }
        #[cfg(feature = "qbdi")]
        Some("qfl") => {
            let mut cmds = command.split_whitespace();
            let md = match cmds.nth(1) {
                Some(m) => m,
                None => {
                    log_msg("[qfl] 用法: qfl <module> <offset>\n".to_string());
                    return;
                }
            };
            let offset = cmds
                .next()
                .and_then(|s| {
                    let s = s.strip_prefix("0x").unwrap_or(s);
                    usize::from_str_radix(s, 16).ok()
                })
                .unwrap_or(0);
            qbdi_trace::qfollow(md, offset)
        }
        #[cfg(not(feature = "qbdi"))]
        Some("qfl") => {
            log_msg("[agent] 当前构建不支持该命令，需要 qbdi feature\n".to_string());
        }
        #[cfg(feature = "quickjs")]
        Some("jsinit") => {
            // Fix #2: 通过 EVAL:/EVAL_ERR: 协议应答，host 可用 eval_state 同步等待
            match quickjs_loader::init() {
                Ok(_) => {
                    if let Some(mut stream) = GLOBAL_STREAM.get() {
                        let _ = stream.write_all(b"EVAL:initialized\n");
                    }
                }
                Err(e) => {
                    if let Some(mut stream) = GLOBAL_STREAM.get() {
                        let _ = stream.write_all(format!("EVAL_ERR:{}\n", e).as_bytes());
                    }
                }
            }
        }
        #[cfg(feature = "quickjs")]
        Some("jsclean") => {
            if !quickjs_loader::is_initialized() {
                if let Some(mut stream) = GLOBAL_STREAM.get() {
                    let _ = stream.write_all("EVAL_ERR:[quickjs] JS 引擎未初始化\n".as_bytes());
                }
            } else {
                quickjs_loader::cleanup();
                if let Some(mut stream) = GLOBAL_STREAM.get() {
                    let _ = stream.write_all(b"EVAL:cleaned up\n");
                }
            }
        }
        #[cfg(feature = "quickjs")]
        Some("loadjs") => {
            // 同步执行并通过 EVAL:/EVAL_ERR: 协议返回结果
            let script = command
                .strip_prefix("loadjs")
                .unwrap_or("")
                .trim()
                .to_string();
            if script.is_empty() {
                if let Some(mut stream) = GLOBAL_STREAM.get() {
                    let _ = stream.write_all(b"EVAL_ERR:[quickjs] Error: empty script\n");
                }
            } else if !quickjs_loader::is_initialized() {
                if let Some(mut stream) = GLOBAL_STREAM.get() {
                    let _ = stream.write_all(
                        "EVAL_ERR:[quickjs] JS 引擎未初始化，请先执行 jsinit\n".as_bytes(),
                    );
                }
            } else {
                match quickjs_loader::execute_script(&script) {
                    Ok(result) => {
                        if let Some(mut stream) = GLOBAL_STREAM.get() {
                            let _ = stream.write_all(format!("EVAL:{}\n", result).as_bytes());
                        }
                    }
                    Err(e) => {
                        // 用 \r 替换 \n，避免多行错误（含堆栈）被 \n 协议分割
                        let e = e.replace('\n', "\r");
                        if let Some(mut stream) = GLOBAL_STREAM.get() {
                            let _ = stream.write_all(format!("EVAL_ERR:{}\n", e).as_bytes());
                        }
                    }
                }
            }
        }
        #[cfg(feature = "quickjs")]
        Some("jseval") => {
            let expr = command
                .strip_prefix("jseval")
                .unwrap_or("")
                .trim()
                .to_string();
            if expr.is_empty() {
                if let Some(mut stream) = GLOBAL_STREAM.get() {
                    let _ = stream
                        .write_all("EVAL_ERR:[quickjs] 用法: jseval <expression>\n".as_bytes());
                }
            } else if !quickjs_loader::is_initialized() {
                if let Some(mut stream) = GLOBAL_STREAM.get() {
                    let _ = stream.write_all(
                        "EVAL_ERR:[quickjs] JS 引擎未初始化，请先执行 jsinit\n".as_bytes(),
                    );
                }
            } else {
                match quickjs_loader::execute_script(&expr) {
                    Ok(result) => {
                        if let Some(mut stream) = GLOBAL_STREAM.get() {
                            let _ = stream.write_all(format!("EVAL:{}\n", result).as_bytes());
                        }
                    }
                    Err(e) => {
                        // 用 \r 替换 \n，避免多行错误（含堆栈）被 \n 协议分割
                        let e = e.replace('\n', "\r");
                        if let Some(mut stream) = GLOBAL_STREAM.get() {
                            let _ = stream.write_all(format!("EVAL_ERR:{}\n", e).as_bytes());
                        }
                    }
                }
            }
        }
        #[cfg(feature = "quickjs")]
        Some("jscomplete") => {
            let prefix = command.strip_prefix("jscomplete").unwrap_or("").trim();
            let result = quickjs_loader::complete(prefix);
            // 直接写 socket，不走 log_msg（避免 [agent] 前缀干扰 host 解析）
            if let Some(mut stream) = GLOBAL_STREAM.get() {
                let _ = stream.write_all(format!("COMPLETE:{}\n", result).as_bytes());
            }
        }
        // Fix #4: shutdown — 清理资源并退出 agent 主循环
        Some("shutdown") => {
            #[cfg(feature = "quickjs")]
            if quickjs_loader::is_initialized() {
                quickjs_loader::cleanup();
            }
            SHOULD_EXIT.store(true, Ordering::Relaxed);
        }
        _ => {
            let cmd_name = command.split_whitespace().next().unwrap_or("(empty)");
            log_msg(format!(
                "无效命令 '{}'，输入 help 查看可用命令列表\n",
                cmd_name
            ));
        }
    }
}
