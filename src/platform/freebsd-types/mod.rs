// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod arch;
pub use arch::*;

mod _types;
mod fcntl;
mod limits;
mod syslimits;
mod types;

pub use _types::*;
pub use fcntl::*;
pub use limits::*;
pub use syslimits::*;
pub use types::*;
