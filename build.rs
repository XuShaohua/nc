// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use std::env;
use std::path::Path;
use std::process::Command;

fn build_syscalls() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let syscall_file = format!("src/syscalls/syscall_{}.c", target_arch);
    let obj_file = format!("{}/syscall.o", out_dir);
    println!("syscall file: {}", syscall_file);
    println!("obj file: {}", obj_file);

    Command::new("cc")
        .args(&[&syscall_file, "-c", "-fPIC", "-o"])
        .arg(&obj_file)
        .status()
        .unwrap();

    Command::new("ar")
        .args(&["crs", "libsyscall.a", "syscall.o"])
        .current_dir(&Path::new(&out_dir))
        .status()
        .unwrap();

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=syscall");
}

fn main() {
    let rustc_toolchain = env::var("RUSTUP_TOOLCHAIN").expect("TOOLCHAIN undefined in env");
    if rustc_toolchain.starts_with("nightly") {
        println!("cargo:rustc-cfg=nightly");
    } else {
        println!("cargo:rustc-cfg=stable");
        build_syscalls();
    }
}
