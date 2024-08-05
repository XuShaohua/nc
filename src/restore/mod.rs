// Copyright (c) 2024 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64",
    target_arch = "x86",
    target_arch = "x86_64",
)))]
#[path = "c.rs"]
mod imp;

#[cfg(any(
    target_arch = "aarch64",
    target_arch = "arm",
    target_arch = "riscv64",
    target_arch = "x86",
    target_arch = "x86_64",
))]
#[path = "native.rs"]
mod imp;

pub use imp::*;
