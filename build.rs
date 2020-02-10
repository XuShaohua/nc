extern crate cc;

use std::env;

fn build_stable() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("TARGET_ARCH undefined in env");
    let syscall_file = format!("src/syscalls/syscall_{}.c", target_arch);
    cc::Build::new().file(syscall_file).compile("syscall");
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
