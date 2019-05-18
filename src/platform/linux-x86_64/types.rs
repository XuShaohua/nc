
pub type blksize_t = i64;
pub type blkcnt_t = i64;
pub type dev_t = u64;
pub type gid_t = u32;
pub type ino_t = u64;
pub type mode_t = usize;
pub type nlink_t = u64;
pub type off_t = i64;
pub type pid_t = isize;
pub type size_t = u64;
pub type ssize_t = i64;
pub type time_t = i64;
pub type uid_t = u32;

/// POSIX.1b structure for a time value. 
/// This is like a `timeval_t' but has nanoseconds instead of microseconds.
#[derive(Debug)]
#[derive(Default)]
pub struct timespec_t {
    pub tv_sec: time_t,  // Seconds
    pub tv_nsec: i64, // Nanoseconds
}

#[derive(Debug)]
#[derive(Default)]
pub struct stat_t {
    pub st_dev: dev_t,         // ID of device containing file
    pub st_ino: ino_t,         // Inode number
    pub st_nlink: nlink_t,     // Number of hard links
    pub st_mode: mode_t,       // File type and mode
    pub st_uid: uid_t,         // User ID of owner
    pub st_gid: gid_t,         // Group ID of owner
    __pad0: isize,
    pub st_rdev: dev_t,        // Device ID (if special file)
    pub st_size: off_t,        // Total size, in bytes
    pub st_blksize: blksize_t,     // Block size for filesystem I/O
    pub st_blocks: blkcnt_t,       // Number of 512B blocks allocated

    pub st_atim: timespec_t,  // Time of last access
    pub st_mtim: timespec_t,  // Time of last modification
    pub st_ctim: timespec_t,  // Time of last status change

    // TODO(Shaohua): Add another pad
}

