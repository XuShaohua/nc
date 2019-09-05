use super::types::*;

pub const STAT_HAVE_NSEC: i32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct stat_t {
    // TODO(Shaohua): Add another pad
    pub st_dev: dev_t,     // Device.
    pub st_ino: ino_t,     // File serial number.
    pub st_mode: mode_t,   // File mode.
    pub st_nlink: nlink_t, // Link count.
    pub st_uid: uid_t,     // User ID of the file's owner.
    pub st_gid: gid_t,     // Group ID of the file's group.
    pub st_rdev: dev_t,    // Device number, if device.
    pad1: usize,
    pub st_size: off_t,        // Size of file, in bytes.
    pub st_blksize: blksize_t, // Optimal block size for I/O.
    pad2: i32,
    pub st_blocks: blkcnt_t, // Number 512-byte blocks allocated.
    // TODO(Shaohua): Merge into timespec_t struct.
    pub st_atime: isize, // Time of last access.
    pub st_atime_nsec: usize,
    pub st_mtime: isize, // Time of last modification.
    pub st_mtime_nsec: usize,
    pub st_ctime: isize, // Time of last status change.
    pub st_ctime_nsec: usize,
    unused4: u32,
    unused5: u32,
}

/// This matches struct stat64 in glibc2.1. Only used for 32 bit.
#[repr(C)]
pub struct stat64_t {
    pub st_dev: dev_t,     // Device.
    pub st_ino: ino_t,     // File serial number.
    pub st_mode: mode_t,   // File mode.
    pub st_nlink: nlink_t, // Link count.
    pub st_uid: uid_t,     // User ID of the file's owner.
    pub st_gid: gid_t,     // Group ID of the file's group.
    pub st_rdev: dev_t,    // Device number, if device.
    pad1: u64,
    pub st_size: off_t,        // Size of file, in bytes.
    pub st_blksize: blksize_t, // Optimal block size for I/O.
    pad2: i32,
    pub st_blocks: blkcnt_t, // Number 512-byte blocks allocated.
    // TODO(Shaohua): Convert to timespec_t
    pub st_atime: i32, // Time of last access.
    pub st_atime_nsec: u32,
    pub st_mtime: i32, // Time of last modification.
    pub st_mtime_nsec: u32,
    pub st_ctime: i32, // Time of last status change.
    pub st_ctime_nsec: u32,
    unused4: u32,
    unused5: u32,
}
