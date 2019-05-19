
/// C types represented in Rust:
/// * long -> isize, 4 bytes on x86, 8 bytes on x86_64.
/// * unsigned long -> usize, 4 bytes on x86, 8 bytes on x86_64.
/// * unsigned long int -> usize, 4 bytes on x86, 8 bytes on x86_64.
/// * long int -> isize, 4 bytes on x86, 8 bytes on x86_64.
/// * void* -> usize, pointer address, 4 bytes on x86, 8 bytes on x86_64.
/// * int -> i32, 4 bytes.
/// * unsigned int -> u32, 4 bytes.
/// * unsigned short int -> u16, 2 bytes.
/// * short int -> i16, 2 bytes.

pub type blksize_t = isize;
pub type blkcnt_t = isize;
pub type dev_t = usize;
pub type gid_t = u32;
pub type ino_t = usize;
pub type key_t = i32;
pub type mode_t = u32;
pub type nlink_t = usize;
pub type off_t = isize;
pub type pid_t = i32;
pub type size_t = usize;
pub type ssize_t = isize;
pub type time_t = isize;
pub type nfds_t = usize;
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

/// Data structure describing a polling request.
#[derive(Debug)]
#[derive(Default)]
pub struct pollfd_t {
    fd: i32,      // File descriptor to poll
    events: i16,  // Types of events poller cares about
    revents: i16, // Types of events that actually occurred
}


#[derive(Debug)]
#[derive(Default)]
pub struct iovec_t {
    pub iov_base: usize,
    pub iov_len: size_t,
}

