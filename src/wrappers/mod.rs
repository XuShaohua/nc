// Copyright (c) 2024 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod fork;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub use fork::*;
