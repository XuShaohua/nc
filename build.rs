// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use std::env;

fn build_syscalls() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let syscall_file = format!("src/syscalls/syscall_{}.c", target_arch);
    println!("syscall file: {}", syscall_file);

    cc::Build::new().file(syscall_file).compile("syscall");
}

fn main() {
    let rustc_toolchain = env::var("RUSTUP_TOOLCHAIN").unwrap_or("stable".to_string());
    if rustc_toolchain.starts_with("nightly") {
        println!("cargo:rustc-cfg=nightly");
    } else {
        println!("cargo:rustc-cfg=stable");
        build_syscalls();
    }
}
