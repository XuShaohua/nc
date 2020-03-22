// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use super::types::*;
use super::uapi_stat::*;

/// This is a header for the common implementation of dirent
/// to fs on-disk file type conversion.  Although the fs on-disk
/// bits are specific to every file system, in practice, many
/// file systems use the exact same on-disk format to describe
/// the lower 3 file type bits that represent the 7 POSIX file
/// types.
///
/// It is important to note that the definitions in this
/// header MUST NOT change. This would break both the
/// userspace ABI and the on-disk format of filesystems
/// using this code.
///
/// All those file systems can use this generic code for the
/// conversions.

/// struct dirent file types
/// exposed to user via getdents(2), readdir(3)
///
/// These match bits 12..15 of stat.st_mode
/// (ie "(i_mode >> 12) & 15").
pub const S_DT_SHIFT: mode_t = 12;

#[inline]
pub const fn S_DT(mode: mode_t) -> mode_t {
    (mode & S_IFMT) >> S_DT_SHIFT
}

pub const S_DT_MASK: mode_t = S_IFMT >> S_DT_SHIFT;

/// these are defined by POSIX and also present in glibc's dirent.h
pub const DT_UNKNOWN: mode_t = 0;
pub const DT_FIFO: mode_t = 1;
pub const DT_CHR: mode_t = 2;
pub const DT_DIR: mode_t = 4;
pub const DT_BLK: mode_t = 6;
pub const DT_REG: mode_t = 8;
pub const DT_LNK: mode_t = 10;
pub const DT_SOCK: mode_t = 12;
pub const DT_WHT: mode_t = 14;

/// 16
pub const DT_MAX: mode_t = S_DT_MASK + 1;

/// fs on-disk file types.
/// Only the low 3 bits are used for the POSIX file types.
/// Other bits are reserved for fs private use.
/// These definitions are shared and used by multiple filesystems,
/// and MUST NOT change under any circumstances.
///
/// Note that no fs currently stores the whiteout type on-disk,
/// so whiteout dirents are exposed to user as DT_CHR.
pub const FT_UNKNOWN: mode_t = 0;
pub const FT_REG_FILE: mode_t = 1;
pub const FT_DIR: mode_t = 2;
pub const FT_CHRDEV: mode_t = 3;
pub const FT_BLKDEV: mode_t = 4;
pub const FT_FIFO: mode_t = 5;
pub const FT_SOCK: mode_t = 6;
pub const FT_SYMLINK: mode_t = 7;
pub const FT_MAX: mode_t = 8;
