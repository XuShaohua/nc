// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `/usr/include/sys/timespec.h`

use super::time_t;

#[repr(C)]
pub struct timespec_t {
    /// seconds
    pub tv_sec: time_t,
    /// and nanoseconds
    pub tv_nsec: isize,
}
