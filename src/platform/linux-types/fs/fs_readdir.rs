// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `fs/readir.c`

use core::{fmt, mem, ptr, slice};

use crate::{ino64_t, loff_t, PATH_MAX};

#[repr(C)]
pub struct linux_dirent_t {
    /// Inode number
    pub d_ino: ino64_t,

    /// Offset to next `linux_dirent`
    pub d_off: loff_t,

    /// Length of this `linux_dirent`
    pub d_reclen: u16,

    /// Filename (null-terminated)
    pub d_name: *mut u8,
}

impl Default for linux_dirent_t {
    fn default() -> Self {
        Self {
            d_ino: 0,
            d_off: 0,
            d_reclen: 0,
            d_name: core::ptr::null_mut(),
        }
    }
}

impl linux_dirent_t {
    /// Read d_type from struct.
    ///
    /// d_type located at last byte of dirent.
    #[must_use]
    #[inline]
    pub fn d_type(&self) -> u8 {
        let self_ptr = self as *const Self as *const u8;
        let d_type_ptr: *const u8 = self_ptr
            .wrapping_add(self.d_reclen as usize)
            .wrapping_sub(1);
        unsafe { d_type_ptr.read() }
    }

    #[must_use]
    #[inline]
    pub const fn name_max_len(&self) -> usize {
        // FIXME(Shaohua): offset_of d_name is different from linux_dirent in C, which is 18.
        // Also `repr(packed)` is ok, which makes it harder to use this struct.
        //self.d_reclen as usize - 2 - mem::offset_of!(Self, d_name)
        self.d_reclen as usize - 2 - mem::offset_of!(Self, d_reclen) - 2
    }

    #[must_use]
    #[inline]
    pub fn name(&self) -> &[u8] {
        let max_len = self.name_max_len();
        let d_name_ptr: *const u8 = (ptr::addr_of!(self.d_reclen) as *const u8).wrapping_add(2);
        unsafe { slice::from_raw_parts(d_name_ptr, max_len) }
    }
}

impl fmt::Debug for linux_dirent_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("linux_dirent_t")
            .field("d_ino", &self.d_ino)
            .field("d_off", &self.d_off)
            .field("d_reclen", &self.d_reclen)
            .field("d_name", &self.name())
            .finish()
    }
}
