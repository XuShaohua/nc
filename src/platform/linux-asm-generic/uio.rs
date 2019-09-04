use super::types::*;

/// Berkeley style UIO structures	-	Alan Cox 1994.
///
/// This program is free software; you can redistribute it and/or
/// modify it under the terms of the GNU General Public License
/// as published by the Free Software Foundation; either version
/// 2 of the License, or (at your option) any later version.

#[repr(C)]
pub struct iovec_t {
    /// BSD uses caddr_t (1003.1g requires void *)
    iov_base: usize,
    /// Must be size_t (1003.1g)
    pub iov_len: size_t,
}

/// UIO_MAXIOV shall be at least 16 1003.1g (5.4.1.1)
pub const UIO_FASTIOV: i32 = 8;
pub const UIO_MAXIOV: i32 = 1024;
