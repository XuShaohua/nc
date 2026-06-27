// Copyright (c) 2024 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[cfg(all(
    not(target_os = "macos"),
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
        target_arch = "x86",
        target_arch = "x86_64",
    )
))]
use core::arch::global_asm;

#[cfg(target_os = "macos")]
#[path = "darwin.rs"]
mod imp;

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64",
    target_arch = "x86",
    target_arch = "x86_64",
)))]
#[path = "c.rs"]
mod imp;

#[cfg(all(not(target_os = "macos"), target_arch = "aarch64"))]
global_asm!(include_str!("restore_aarch64.s"));

#[cfg(all(not(target_os = "macos"), target_arch = "arm"))]
global_asm!(include_str!("restore_arm.s"));

#[cfg(all(not(target_os = "macos"), target_arch = "riscv64"))]
global_asm!(include_str!("restore_riscv64.s"));

#[cfg(all(not(target_os = "macos"), target_arch = "x86"))]
global_asm!(include_str!("restore_x86.s"));

#[cfg(all(not(target_os = "macos"), target_arch = "x86_64"))]
global_asm!(include_str!("restore_x86_64.s"));

#[cfg(all(
    not(target_os = "macos"),
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
        target_arch = "x86",
        target_arch = "x86_64",
    )
))]
#[path = "native.rs"]
mod imp;

pub use imp::*;
