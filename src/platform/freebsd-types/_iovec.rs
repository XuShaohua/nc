// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `sys/sys/_iovec.h`

use crate::size_t;

#[repr(C)]
#[derive(Debug, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct iovec_t {
    /// Base address.
    pub iov_base: usize,

    /// Length.
    pub iov_len: size_t,
}
