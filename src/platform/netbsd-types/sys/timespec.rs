// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From `/usr/include/sys/timespec.h`

#[repr(C)]
pub struct timespec_t {
    /// seconds
    pub tv_sec: time_t,
    /// and nanoseconds
    pub tv_nsec: isize,
}
