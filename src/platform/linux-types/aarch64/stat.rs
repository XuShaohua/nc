// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

pub const STAT_HAVE_NSEC: i32 = 0;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct stat_t {
    pub st_dev: usize,  // Device.
    pub st_ino: usize,  // File serial number.
    pub st_mode: u32,   // File mode.
    pub st_nlink: i32,  // Link count.
    pub st_uid: u32,    // User ID of the file's owner.
    pub st_gid: u32,    // Group ID of the file's group.
    pub st_rdev: usize, // Device number, if device.
    pad1: usize,
    pub st_size: isize,  // Size of file, in bytes.
    pub st_blksize: i32, // Optimal block size for I/O.
    pad2: i32,
    pub st_blocks: isize, // Number 512-byte blocks allocated.
    pub st_atime: isize,  // Time of last access.
    pub st_atime_nsec: usize,
    pub st_mtime: isize, // Time of last modification.
    pub st_mtime_nsec: usize,
    pub st_ctime: isize, // Time of last status change.
    pub st_ctime_nsec: usize,
    unused4: u32,
    unused5: u32,
}

/// This matches struct stat64 in glibc2.1, hence the absolutely
/// insane amounts of padding around dev_t's.
/// Note: The kernel zero's the padded region because glibc might read them
/// in the hope that the kernel has stretched to using larger sizes.
#[repr(C)]
#[derive(Debug, Default)]
pub struct stat64_t {
    pub st_dev: u64,
    pad0: [u8; 4],

    pub __st_ino: usize,
    pub st_mode: u32,
    pub st_nlink: u32,

    pub st_uid: usize,
    pub st_gid: usize,

    pub st_rdev: u64,
    pad3: [u8; 4],

    pub st_size: i64,
    pub st_blksize: usize,
    /// Number 512-byte blocks allocated.
    pub st_blocks: u64,

    pub st_atime: usize,
    pub st_atime_nsec: usize,

    pub st_mtime: usize,
    pub st_mtime_nsec: usize,

    pub st_ctime: usize,
    pub st_ctime_nsec: usize,

    pub st_ino: u64,
}

pub const STAT64_HAS_BROKEN_ST_INO: i32 = 1;
