use super::super::types::*;

#[repr(C)]
pub struct stat_t {
    pub st_dev: dev_t,
    pub st_ino: ino_t,
    pub st_nlink: nlink_t,
    pub st_mode: mode_t,
    pub st_uid: uid_t,
    pub st_gid: gid_t,
    pad1: u32,
    pub st_rdev: dev_t,
    pub st_size: off_t,
    pub st_atime: usize,
    pub st_atime_nsec: usize,
    pub st_mtime: usize,
    pub st_mtime_nsec: usize,
    pub st_ctime: usize,
    pub st_ctime_nsec: usize,
    pub st_blksize: blksize_t,
    pub st_blocks: blkcnt_t,
    unused: [usize; 3],
}

pub const STAT_HAVE_NSEC: i32 = 1;
