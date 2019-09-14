#![allow(unused_variables)]

use std::env;
use std::path::Path;
use std::process::Command;

fn build_stable() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let syscall_file = format!("src/syscalls/syscall_{}.c", target_arch);

    // TODO(Shaohua): Read compiler name from environment.
    Command::new("gcc")
        .args(&["src/syscall.c", "-c", "-fPIC", "-o"])
        .arg(&format!("{}/syscall.o", out_dir))
        .status()
        .unwrap();

    Command::new("ar")
        .args(&["crus", "libsyscall.a", "syscall.o"])
        .current_dir(&Path::new(&out_dir))
        .status()
        .unwrap();

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=syscall");
}

fn main() {
    let rustc_toolchain = env::var("RUSTUP_TOOLCHAIN").unwrap();
    if rustc_toolchain.starts_with("nightly") {
        println!("cargo:rustc-cfg=nightly");
    } else {
        println!("cargo:rustc-cfg=stable");
        build_stable();
    }
}
