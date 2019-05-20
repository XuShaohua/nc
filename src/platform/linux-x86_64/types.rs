
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

pub type be16_t = u16;
pub type be32_t = u32;
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
pub type sa_family_t = u16;
pub type size_t = usize;
pub type socklen_t = u32;
pub type ssize_t = isize;
pub type time_t = isize;
pub type nfds_t = usize;
pub type uid_t = u32;
pub type shmatt_t = usize; // Type to count number of shared memory attaches.
pub type suseconds_t = isize; // Signed count of microseconds.

/// POSIX.1b structure for a time value.
/// This is like a `timeval_t' but has nanoseconds instead of microseconds.
#[derive(Debug)]
#[derive(Default)]
pub struct timespec_t {
    pub tv_sec: time_t, // Seconds
    pub tv_nsec: isize, // Nanoseconds
}


/// A time value that is accurate to the nearest microsecond
/// but also has a range of years.
#[derive(Debug)]
#[derive(Default)]
pub struct timeval_t {
  pub tv_sec: time_t, // Seconds.
  pub tv_usec: suseconds_t, // Microseconds.
}

#[derive(Debug)]
#[derive(Default)]
pub struct itimerval_t {
    pub it_interval: timeval_t, // Value to put into `it_value' when the timer expires.
    pub it_value: timeval_t,    // Time to the next timer expiration.
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

/// Data structure used to pass permission information to IPC operations.
#[derive(Debug)]
#[derive(Default)]
pub struct ipc_perm_t {
    key: key_t,                 // Key.
    pub uid: uid_t,             // Owner's user ID.
    pub gid: gid_t,             // Owner's group ID.
    pub cuid: uid_t,            // Creator's user ID.
    pub cgid: gid_t,            // Creator's group ID.
    pub mode: u16,              // Read/write permission.
    pad1: u16,
    seq: u16,                   // Sequence number.
    pad2: u16,
}

/// Data structure describing a shared memory segment
#[derive(Debug)]
#[derive(Default)]
pub struct shmid_ds {
    pub shm_perm: ipc_perm_t, // operation permission struct
    pub shm_segsz: size_t,    // size of segment in bytes
    pub shm_atime: time_t,    // time of last shmat()
    pub shm_dtime: time_t,    // time of last shmdt()
    pub shm_ctime: time_t,    // time of last change by shmctl()
    pub shm_cpid: pid_t,      //pid of creator
    pub shm_lpid: pid_t,      // pid of last shmop
    pub shm_nattch: shmatt_t, // number of current attaches
}

/// Internet address.
#[derive(Debug)]
#[derive(Default)]
pub struct in_addr_t {
    pub s_addr: be32_t,
}

/// Structure describing an Internet (IP) socket address.
#[derive(Debug)]
#[derive(Default)]
pub struct sockaddr_in_t {
    pub sin_family: sa_family_t,    // Address family
    pub sin_port: be16_t,           // Port number
    pub sin_addr: in_addr_t,        // Internet address
    pad: [u8; 16 - 2 - 2 - 4],         // Pad to size of `struct sockaddr_t'.
}

/// Structure describing messages sent by `sendmsg` and received by `recvmsg`.
#[derive(Debug)]
#[derive(Default)]
pub struct msghdr_t {
    pub msg_name:       usize,      // Address to send to/receive from.
    pub msg_namelen:    socklen_t,  // Length of address data.
    pub msg_iov:        iovec_t,    // Vector of data to send/receive into.
    pub msg_iovlen:     size_t,     // Number of elements in the vector.
    pub msg_control:    usize,      // Ancillary data (eg BSD filedesc passing).
    pub msg_controllen: size_t,     // Ancillary data buffer length.
    msg_flags:          i32,        // Flags on received message.
}
