// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[cfg(test_arch = "loongarch64")]
mod stat;
#[cfg(test_arch = "loongarch64")]
pub use stat::*;

mod mman;
mod mman_common;
mod sockios;
mod statfs;
mod termbits;
mod termios;

pub use mman::*;
pub use mman_common::*;
pub use sockios::*;
pub use statfs::*;
pub use termbits::*;
pub use termios::*;
