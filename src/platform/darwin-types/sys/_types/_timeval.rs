// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `sys/_types/_timeval.h`

use crate::{__darwin_suseconds_t, __darwin_time_t};

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct timeval_t {
    /// seconds
    pub tv_sec: __darwin_time_t,
    /// and microseconds
    pub tv_usec: __darwin_suseconds_t,
}
