// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use core::fmt;

use super::basic_types::{ino_t, off_t};
use super::limits::PATH_MAX;

/// From fs/readir.c

#[repr(C)]
#[derive(Clone, Copy)]
pub struct linux_dirent_t {
    /// Inode number
    pub d_ino: ino_t,

    /// Offset to next `linux_dirent`
    pub d_off: off_t,

    /// Length of this `linux_dirent`
    pub d_reclen: u16,

    /// Filename (null-terminated)
    //pub d_name: [u8; 1],
    //pub d_name: usize,
    pub d_name: [u8; PATH_MAX as usize],
    // FIXME(Shaohua): Really bad idea.
}

impl fmt::Debug for linux_dirent_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("linux_dirent_t")
            .field("d_ino", &self.d_ino)
            .field("d_off", &self.d_off)
            .field("d_reclen", &self.d_reclen)
            .field("d_name", &&self.d_name[0..32])
            .finish()
    }
}
