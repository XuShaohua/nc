// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From `fs/readir.c`

use core::{fmt, mem, ptr};

use crate::{ino_t, off_t, PATH_MAX};

const NAME_MAX_LEN: usize = 256;

#[repr(C)]
pub struct linux_dirent_t {
    /// Inode number
    pub d_ino: ino_t,

    /// Offset to next `linux_dirent`
    pub d_off: off_t,

    /// Length of this `linux_dirent`
    pub d_reclen: u16,

    /// Filename (null-terminated)
    pub d_name: [u8; NAME_MAX_LEN],
}

impl Default for linux_dirent_t {
    fn default() -> Self {
        Self {
            d_ino: 0,
            d_off: 0,
            d_reclen: 0,
            d_name: [0; NAME_MAX_LEN];
        }
    }
}

impl linux_dirent_t {
    #[must_use]
    #[inline]
    pub const fn name_max_len(&self) -> usize {
        self.d_reclen as usize - 2 - mem::offset_of!(linux_dirent_t, d_name)
    }

    #[must_use]
    #[inline]
    pub fn name(&self) -> &[u8] {
        let max_len = self.name_max_len();
        for i in 0..max_len {
            if self.d_name[i] == b'\0' {
                return &self.d_name[..i];
            }
        }
        &self.d_name[..max_len]
    }
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
