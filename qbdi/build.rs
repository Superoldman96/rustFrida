use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let lib_path = PathBuf::from(&manifest_dir);
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // Generate FFI bindings with bindgen
    let bindings = bindgen::Builder::default()
        .header(format!("{}/QBDI.h", manifest_dir))
        .clang_arg(format!("-I{}", manifest_dir))
        // Use C mode to avoid C++ code
        .clang_arg("-xc")
        // Generate comments from headers
        .generate_comments(true)
        // Derive traits
        .derive_debug(true)
        .derive_default(true)
        .derive_copy(true)
        // Layout tests can fail on cross-compilation
        .layout_tests(false)
        // Allowlist QBDI types and functions
        .allowlist_function("qbdi_.*")
        .allowlist_type("QBDI_.*")
        .allowlist_type("qbdi_.*")
        .allowlist_type("GPRState")
        .allowlist_type("FPRState")
        .allowlist_type("VMState")
        .allowlist_type("VMAction")
        .allowlist_type("VMEvent")
        .allowlist_type("VMInstance.*")
        .allowlist_type("InstPosition")
        .allowlist_type("InstCallback")
        .allowlist_type("VMCallback")
        .allowlist_type("InstAnalysis")
        .allowlist_type("OperandAnalysis")
        .allowlist_type("MemoryAccess.*")
        .allowlist_type("InstrRuleCallbackC")
        .allowlist_type("InstrRuleDataVec")
        .allowlist_type("AnalysisType")
        .allowlist_type("CPUMode")
        .allowlist_type("Options")
        .allowlist_type("LogPriority")
        .allowlist_type("ConditionType")
        .allowlist_type("OperandType")
        .allowlist_type("OperandFlag")
        .allowlist_type("RegisterAccessType")
        .allowlist_type("CallbackPriority")
        .allowlist_type("rword")
        .allowlist_type("sword")
        .allowlist_var("QBDI_.*")
        .allowlist_var("NUM_GPR")
        .allowlist_var("AVAILABLE_GPR")
        .allowlist_var("REG_.*")
        .allowlist_var("NO_REGISTRATION")
        .allowlist_var("NOT_FOUND")
        .allowlist_var("ANY")
        // Block C++ types
        .blocklist_type("std::.*")
        // Use core types
        .use_core()
        // Handle u128 type - blocklist FPRState since it uses __uint128_t
        .blocklist_type("__uint128_t")
        .blocklist_type("__int128_t")
        .blocklist_type("FPRState")
        // We generate these types manually for better Rust ergonomics
        .blocklist_type("VMInstance")
        .blocklist_type("VMInstanceRef")
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    // Native link directives are intentionally emitted by the final cdylib
    // consumer (currently qbdi-helper). Propagating static archives from this
    // rlib causes Android's linker to pull libc.a internals into the helper.

    // Rerun if headers change
    println!("cargo:rerun-if-changed={}/libQBDI.a", lib_path.display());
    println!("cargo:rerun-if-changed={}/QBDI.h", manifest_dir);
    println!("cargo:rerun-if-changed={}/QBDI/", manifest_dir);
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=NDK_PATH");
    println!("cargo:rerun-if-env-changed=ANDROID_NDK_HOME");
}
