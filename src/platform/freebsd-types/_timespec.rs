// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From sys/sys/_timespec.h

#[repr(C)]
#[derive(Debug, Default)]
pub struct timespec_t {
    /// seconds
    pub tv_sec: time_t,
    /// and nanoseconds
    pub tv_nsec: isize,
}
