// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use super::limits::*;
use super::basic_types::*;
use alloc::string::String;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
