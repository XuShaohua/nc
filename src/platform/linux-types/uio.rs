// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use super::basic_types::*;

/// Berkeley style UIO structures
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct iovec_t {
    /// BSD uses caddr_t (1003.1g requires void *)
    pub iov_base: usize,
    /// Must be size_t (1003.1g)
    pub iov_len: size_t,
}

/// UIO_MAXIOV shall be at least 16 1003.1g (5.4.1.1)
pub const UIO_FASTIOV: i32 = 8;
pub const UIO_MAXIOV: i32 = 1024;
