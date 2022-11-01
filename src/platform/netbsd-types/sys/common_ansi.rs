// Copyright (c) 2022 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From `/usr/include/sys/common_ansi.h`

/// clock()
pub type clock_t = u32;
/// ptr1 - ptr2
pub type ptrdiff_t = isize;
/// byte count or error
pub type ssize_t = isize;
/// sizeof()
pub type size_t = usize;
/// time()
pub type time_t = i64;
/// clockid_t
pub type clockid_t = i32;
/// timer_t
pub type timer_t = i32;
/// suseconds_t
pub type suseconds_t = i32;
/// useconds_t
pub type useconds_t = u32;
