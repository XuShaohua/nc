// Copyright (c) 2023 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `sys/_domainset.h`

use core::mem::size_of;

pub const DOMAINSET_MAXSIZE: usize = 256;
pub const DOMAINSET_SETSIZE: usize = DOMAINSET_MAXSIZE;

pub const _BITSET_BITS: usize = size_of::<isize>() * 8;

#[inline]
#[must_use]
pub const fn __howmany(x: usize, y: usize) -> usize {
    (x + (y - 1)) / y
}

#[inline]
#[must_use]
pub const fn __bitset_words(s: usize) -> usize {
    __howmany(s, _BITSET_BITS)
}

#[repr(C)]
pub struct _domainset_t {
    pub __bits: [isize; __bitset_words(DOMAINSET_SETSIZE)],
}

pub type domainset_t = _domainset_t;
