#![allow(unused_variables)]

use std::env;
use std::path::Path;
use std::process::Command;

fn build_stable() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR undefined in env");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("TARGET_ARCH undefined in env");
    let syscall_file = format!("src/syscalls/syscall_{}.c", target_arch);
    let obj_file = format!("{}/syscall.o", out_dir);
    println!("syscall file: {}", syscall_file);
    println!("obj file: {}", obj_file);

    // TODO(Shaohua): Read compiler name from environment.
    Command::new("gcc")
        .args(&[&syscall_file, "-c", "-fPIC", "-o"])
        .arg(&obj_file)
        .status()
        .expect("gcc returns error");

    Command::new("ar")
        .args(&["crs", "libsyscall.a", "syscall.o"])
        .current_dir(&Path::new(&out_dir))
        .status()
        .expect("ar returns error");

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=syscall");
}

fn main() {
    let rustc_toolchain = env::var("RUSTUP_TOOLCHAIN").expect("TOOLCHAIN undefined in env");
    if rustc_toolchain.starts_with("nightly") {
        println!("cargo:rustc-cfg=nightly");
    } else {
        println!("cargo:rustc-cfg=stable");
        build_stable();
    }
}
