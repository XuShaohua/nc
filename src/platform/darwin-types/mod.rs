// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[cfg(target_arch = "x86_64")]
#[path = "i386/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "aarch64")]
#[path = "arm/mod.rs"]
mod arch;
pub use arch::*;

mod sys;

pub use sys::*;
