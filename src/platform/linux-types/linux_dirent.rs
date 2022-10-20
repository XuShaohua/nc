// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#![allow(clippy::module_name_repetitions)]

use alloc::string::String;
use core::fmt;

use super::basic_types::{ino64_t, loff_t};
use super::limits::PATH_MAX;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct linux_dirent64_t {
    /// 64-bit inode number.
    pub d_ino: ino64_t,

    /// 64-bit offset to next structure.
    pub d_off: loff_t,

    /// Size of this dirent.
    pub d_reclen: u16,

    /// File type.
    pub d_type: u8,

    /// Filename (null-terminated).
    //pub d_name: [u8; 0],
    pub d_name: [u8; PATH_MAX as usize],
}

impl fmt::Debug for linux_dirent64_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("linux_dirent64_t")
            .field("d_ino", &self.d_ino)
            .field("d_off", &self.d_off)
            .field("d_reclen", &self.d_reclen)
            .field("d_type", &self.d_type)
            .field("d_name", &&self.d_name[0..32])
            .finish()
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct linux_dirent64_extern_t {
    /// 64-bit inode number.
    pub d_ino: ino64_t,

    /// 64-bit offset to next structure.
    pub d_off: loff_t,

    /// File type.
    pub d_type: u8,

    // TODO(Shaohua): Replace String with CString
    /// Filename.
    pub d_name: String,
}
