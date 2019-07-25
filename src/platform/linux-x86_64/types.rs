
/// C types represented in Rust:
/// * long -> isize, 4 bytes on x86, 8 bytes on x86_64.
/// * unsigned long -> usize, 4 bytes on x86, 8 bytes on x86_64.
/// * unsigned long int -> usize, 4 bytes on x86, 8 bytes on x86_64.
/// * long int -> isize, 4 bytes on x86, 8 bytes on x86_64.
/// * void* -> usize, pointer address, 4 bytes on x86, 8 bytes on x86_64.
/// * int -> i32, 4 bytes.
/// * unsigned int -> u32, 4 bytes.
/// * unsigned -> u32, 4 bytes.
/// * unsigned short int -> u16, 2 bytes.
/// * short int -> i16, 2 bytes.

pub type be16_t = u16;
pub type be32_t = u32;
pub type blksize_t = isize;
pub type blkcnt_t = isize;
pub type compat_fsid_t = [i32; 2];
pub type clock_t = isize;
pub type clockid_t = i32;
pub type daddr_t = i32;
pub type dev_t = usize;
pub type gid_t = u32;
pub type ino_t = usize;
pub type key_t = i32;
pub type loff_t = i64;
pub type mode_t = u32;
pub type msglen_t = usize;
pub type msgqnum_t = usize;
pub type nfds_t = usize;
pub type nlink_t = usize;
pub type off_t = isize;
pub type pid_t = i32;
pub type poll_t = u32;
pub type rwf_t = i32;
pub type sa_family_t = u16;
pub type sigset_t = usize;
pub type size_t = usize;
pub type socklen_t = u32;
pub type ssize_t = isize;
pub type time_t = isize;
pub type uid_t = u32;
pub type rlimit_t = usize;
pub type shmatt_t = usize; // Type to count number of shared memory attaches.
pub type suseconds_t = isize; // Signed count of microseconds.

/// POSIX.1b structure for a time value.
/// This is like a `timeval_t' but has nanoseconds instead of microseconds.
#[derive(Debug)]
#[derive(Default)]
pub struct timespec_t {
    pub tv_sec:  time_t, // Seconds
    pub tv_nsec: isize,  // Nanoseconds
}


/// A time value that is accurate to the nearest microsecond
/// but also has a range of years.
#[derive(Debug)]
#[derive(Default)]
pub struct timeval_t {
  pub tv_sec:  time_t,      // Seconds.
  pub tv_usec: suseconds_t, // Microseconds.
}

#[derive(Debug)]
#[derive(Default)]
pub struct itimerspec_t {
    pub it_interval: timespec_t, // timer period
    pub it_value:    timespec_t, // timer expiration
}

#[derive(Debug)]
#[derive(Default)]
pub struct itimerval_t {
    pub it_interval: timeval_t, // Value to put into `it_value' when the timer expires.
    pub it_value:    timeval_t, // Time to the next timer expiration.
}

#[derive(Debug)]
#[derive(Default)]
pub struct stat_t {
    pub st_dev:     dev_t,      // ID of device containing file
    pub st_ino:     ino_t,      // Inode number
    pub st_nlink:   nlink_t,    // Number of hard links
    pub st_mode:    mode_t,     // File type and mode
    pub st_uid:     uid_t,      // User ID of owner
    pub st_gid:     gid_t,      // Group ID of owner
    pad0:           isize,
    pub st_rdev:    dev_t,      // Device ID (if special file)
    pub st_size:    off_t,      // Total size, in bytes
    pub st_blksize: blksize_t,  // Block size for filesystem I/O
    pub st_blocks:  blkcnt_t,   // Number of 512B blocks allocated
    pub st_atim:    timespec_t, // Time of last access
    pub st_mtim:    timespec_t, // Time of last modification
    pub st_ctim:    timespec_t, // Time of last status change

    // TODO(Shaohua): Add another pad
}

/// Timestamp structure for the timestamps in struct statx_t.
#[derive(Debug)]
#[derive(Default)]
pub struct statx_timestamp_t {
    pub tv_sec:  i64,
    pub tv_nsec: u32,
    reserved:    i32,
}

/// Structures for the extended file attribute retrieval system call `statx`.
#[derive(Debug)]
#[derive(Default)]
pub struct statx_t {
    /* 0x00 */
    pub stx_mask:       u32, // What results were written [uncond]
    pub stx_blksize:    u32, // Preferred general I/O size [uncond]
    pub stx_attributes: u64, // Flags conveying information about the file [uncond]
    /* 0x10 */
    pub stx_nlink: u32, // Number of hard links
    pub stx_uid:   u32, // User ID of owner
    pub stx_gid:   u32, // Group ID of owner
    pub stx_mode:  u16, // File mode
    spare0:        [u16; 1],
    /* 0x20 */
    pub stx_ino:             u64, // Inode number
    pub stx_size:            u64, // File size 
    pub stx_blocks:          u64, // Number of 512-byte blocks allocated
    pub stx_attributes_mask: u64,// Mask to show what's supported in stx_attributes
    /* 0x40 */
    pub stx_atime: statx_timestamp_t, // Last access time
    pub stx_btime: statx_timestamp_t, // File creation time
    pub stx_ctime: statx_timestamp_t, // Last attribute change time
    pub stx_mtime: statx_timestamp_t, // Last data modification time
    /* 0x80 */
    pub stx_rdev_major: u32, // Device ID of special file [if bdev/cdev]
    pub stx_rdev_minor: u32,
    pub stx_dev_major:  u32, // ID of device containing file [uncond]
    pub stx_dev_minor:  u32,
    /* 0x90 */
    pub spare2: [u64; 14], // Spare space for future expansion
    /* 0x100 */
}

/// Data structure describing a polling request.
#[derive(Debug)]
#[derive(Default)]
pub struct pollfd_t {
    fd:      i32, // File descriptor to poll
    events:  i16, // Types of events poller cares about
    revents: i16, // Types of events that actually occurred
}

#[derive(Debug)]
#[derive(Default)]
pub struct iovec_t {
    pub iov_base: usize,
    pub iov_len:  size_t,
}

/// Data structure describing a shared memory segment
#[derive(Debug)]
#[derive(Default)]
pub struct shmid_ds {
    pub shm_perm:   ipc_perm_t, // operation permission struct
    pub shm_segsz:  size_t,     // size of segment in bytes
    pub shm_atime:  time_t,     // time of last shmat()
    pub shm_dtime:  time_t,     // time of last shmdt()
    pub shm_ctime:  time_t,     // time of last change by shmctl()
    pub shm_cpid:   pid_t,      // pid of creator
    pub shm_lpid:   pid_t,      // pid of last shmop
    pub shm_nattch: shmatt_t,   // number of current attaches
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
    pub sin_port:   be16_t,         // Port number
    pub sin_addr:   in_addr_t,      // Internet address
    pad:            [u8; 16-2-2-4], // Pad to size of `struct sockaddr_t'.
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

/// Resource usage
#[derive(Debug)]
#[derive(Default)]
pub struct rusage_t {
    pub ru_utime:    timeval_t, // Total amount of user time used.
    pub ru_stime:    timeval_t, // Total amount of system time used.
    pub ru_maxrss:   usize, // Maximum resident set size (in kilobytes).
    pub ru_ixrss:    usize, // Maximum resident set size (in kilobytes).
    pub ru_idrss:    usize, // Amount of data segment memory used (kilobyte-seconds).
    pub ru_isrss:    usize, // Amount of stack memory used (kilobyte-seconds).
    pub ru_minflt:   usize, // Number of soft page faults.
    pub ru_majflt:   usize, // Number of hard page faults (i.e. those that required I/O).
    pub ru_nswap:    usize, // Number of times a process was swapped out of physical memory.
    pub ru_inblock:  usize, // Number of input operations via the file system.
    pub ru_oublock:  usize, // Number of output operations via the file system.
    pub ru_msgsnd:   usize, // Number of IPC messages sent.
    pub ru_msgrcv:   usize, // Number of IPC messages received.
    pub ru_nsignals: usize, // Number of signals delivered.
    pub ru_nvcsw:    usize, // Number of voluntary context switches.
    pub ru_nivcsw:   usize, // Number of involuntary context switches
}

// Length of the entries in `struct utsname_t` is 65.
const UTSNAME_LENGTH: usize = 65;

/// Structure describing the system and machine.
pub struct utsname_t {
    pub sysname:    [u8; UTSNAME_LENGTH], // Name of the implementation of the operating system.
    pub nodename:   [u8; UTSNAME_LENGTH], // Name of this node on the network.
    pub release:    [u8; UTSNAME_LENGTH], // Current release level of this implementation.
    pub version:    [u8; UTSNAME_LENGTH], // Current version level of this release.
    pub machine:    [u8; UTSNAME_LENGTH], // Name of the hardware type the system is running on.
    pub domainname: [u8; UTSNAME_LENGTH],
}

impl core::fmt::Debug for utsname_t {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        unsafe{
        write!(f, "utsname_t {{ sysname: {}, nodename: {}, release: {}, \
               version: {}, machine: {}, domainname: {} }}",
               core::str::from_utf8_unchecked(&self.sysname),
               core::str::from_utf8_unchecked(&self.nodename),
               core::str::from_utf8_unchecked(&self.release),
               core::str::from_utf8_unchecked(&self.version),
               core::str::from_utf8_unchecked(&self.machine),
               core::str::from_utf8_unchecked(&self.domainname)
               )
        }
    }
}

impl Default for utsname_t {
    fn default() -> Self {
        utsname_t {
            sysname: [0; UTSNAME_LENGTH],
            nodename: [0; UTSNAME_LENGTH],
            release: [0; UTSNAME_LENGTH],
            version: [0; UTSNAME_LENGTH],
            machine: [0; UTSNAME_LENGTH],
            domainname: [0; UTSNAME_LENGTH],
        }
    }
}

/// Structure used for argument to `semop' to describe operations.
#[derive(Debug)]
#[derive(Default)]
pub struct sembuf_t {
    pub sem_num: u16, // semaphore number
    pub sem_op:  i16, // semaphore operation
    pub sem_flg: i16, // operation flag
}

/// message buffer for `msgsnd` and `msgrcv` calls.
pub struct msgbuf_t {
    pub mtype: isize,   // type of message
    pub mtext: [u8; 1], // message text
}

impl core::fmt::Debug for msgbuf_t {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        unsafe{
        write!(f, "msgbuf_t {{ mtype: {}, mtext: {} }}",
               self.mtype, core::str::from_utf8_unchecked(&self.mtext),
               )
        }
    }
}

impl Default for msgbuf_t {
    fn default() -> Self {
        msgbuf_t {
            mtype: 0,
            mtext: [0; 1],
        }
    }
}


/// Buffer for `msgctl` calls `IPC_INFO`, `MSG_INFO`.
#[derive(Debug)]
#[derive(Default)]
pub struct msginfo_t {
    pub msgpool: i32,
    pub msgmap:  i32,
    pub msgmax:  i32,
    pub msgmnb:  i32,
    pub msgmni:  i32,
    pub msgssz:  i32,
    pub msgtql:  i32,
    pub msgseg:  u16,
}

/// Data structure used to pass permission information to IPC operations.
#[derive(Debug)]
#[derive(Default)]
pub struct ipc_perm_t {
    key:        key_t, // Key.
    pub uid:    uid_t, // Owner's user ID.
    pub gid:    gid_t, // Owner's group ID.
    pub cuid:   uid_t, // Creator's user ID.
    pub cgid:   gid_t, // Creator's group ID.
    pub mode:   u16,   // Read/write permission.
    pad1:       u16,
    seq:        u16,   // Sequence number.
    pad2:       u16,
    reserved1:  usize,
    reserved2:  usize,
}

/// Structure of record for one message inside the kernel.
#[derive(Debug)]
#[derive(Default)]
pub struct msqid_ds {
    pub msg_perm:   ipc_perm_t, // structure describing operation permission
    pub msg_stime:  time_t,     // time of last msgsnd command
    pub msg_rtime:  time_t,     // time of last msgrcv command
    pub msg_ctime:  time_t,     // time of last change
    msg_cbytes:     usize,      // current number of bytes on queue
    pub msg_qnum:   msgqnum_t,  // number of messages currently on queue
    pub msg_qbytes: msglen_t,   // max number of bytes allowed on queue
    pub msg_lspid:  pid_t,      // pid of last msgsnd()
    pub msg_lrpid:  pid_t,      // pid of last msgrcv()
    reserved4:      usize,
    reserved5:      usize,
}

#[derive(Debug)]
#[derive(Default)]
pub struct sysinfo_t {
   pub uptime:    isize,      // Seconds since boot
   pub loads:     [usize; 3], // 1, 5, and 15 minute load averages
   pub totalram:  usize,      // Total usable main memory size
   pub freeram:   usize,      // Available memory size
   pub sharedram: usize,      // Amount of shared memory
   pub bufferram: usize,      // Memory used by buffers
   pub totalswap: usize,      // Total swap space size
   pub freeswap:  usize,      // Swap space still available
   pub procs:     u16,        // Number of current processes
   pad:           [u8; 22],   // Pads structure to 64 bytes
}

/// Structure describing CPU time used by a process and its children.
#[derive(Debug)]
#[derive(Default)]
pub struct tms_t {
    pub tms_utime:  clock_t, // User CPU time.
    pub tms_stime:  clock_t, // System CPU time.
    pub tms_cutime: clock_t, // User CPU time of dead children.
    pub tms_cstime: clock_t, // System CPU time of dead children.
}

/// Structure representing a timezone.
#[derive(Debug)]
#[derive(Default)]
pub struct timezone_t {
    pub tz_minuteswest: i32, // minutes west of Greenwich
    pub tz_dsttime:     i32, // type of dst correction
}

#[derive(Debug)]
#[derive(Default)]
pub struct statfs_t {
    pub f_type:     isize,
    pub f_bsize:    isize,
	pub f_frsize:   isize,
	pub f_blocks:   isize,
	pub f_bfree:    isize,
	pub f_files:    isize,
	pub f_ffree:    isize,
	pub f_bavail:   isize,
	pub f_fsid:     compat_fsid_t,
	pub f_namelen:  isize,
	pub _flags:     isize,
	pub f_spare:    [isize; 5],
}

#[derive(Debug)]
#[derive(Default)]
pub struct sysctl_args_t {
    pub name:    usize, // to int
	pub nlen:    i32,
	pub oldval:  usize,
    pub oldlenp: usize, // to size_t
	pub newval:  usize,
	pub newlen:  size_t,
    unused:      [usize; 4],
}

/// To discipline kernel clock oscillator
#[derive(Debug)]
#[derive(Default)]
pub struct timex_t {
    pub modes:     u32,   // mode selector
    pub offset:    isize, // time offset (usec)
    pub freq:      isize, // frequency offset (scaled ppm)
    pub maxerror:  isize, // maximum error (usec)
    pub esterror:  isize, // estimated error (usec)
    pub status:    i32,   // clock command/status
    pub constant:  isize, // pll time constant
    pub precision: isize, // clock precision (usec) (read only)
    pub tolerance: isize, // clock frequency tolerance (ppm), (read only)
    pub time:      timeval_t, // (read only, except for ADJ_SETOFFSET)
    pub tick:      isize, // (modified) usecs between clock ticks
    pub ppsfreq:   isize, // pps frequency (scaled ppm) (ro)
    pub jitter:    isize, // pps jitter (us) (ro)
    pub shift:     i32,   // interval duration (s) (shift) (ro)
    pub stabil:    isize, // pps stability (scaled ppm) (ro)
    pub jitcnt:    isize, // jitter limit exceeded (ro)
    pub calcnt:    isize, // calibration intervals (ro)
    pub errcnt:    isize, // calibration errors (ro)
    pub stbcnt:    isize, // stability limit exceeded (ro)
    pub tai:       i32,   // TAI offset (ro)
}

/// Cache for getcpu() to speed it up. (cpu.h)
#[derive(Debug)]
#[derive(Default)]
pub struct getcpu_cache_t {
    pub blob: [usize; 16], // 16 == 128 / sizeof(long)
}

#[derive(Debug)]
#[derive(Default)]
pub struct sched_param_t {
    pub sched_priority: i32,
}

/// Extended scheduling parameters data structure.
pub struct sched_attr_t {
    pub size:           u32, // size of the structure, for fwd/bwd compat.
    pub sched_policy:   u32, // task's scheduling policy
    pub sched_flags:    u64, // for customizing the scheduler behaviour
    pub sched_nice:     i32, // task's nice value. (SCHED_NORMAL/BATCH)
    pub sched_priority: u32, // task's static priority (SCHED_FIFO/RR)
    pub sched_runtime:  u64, // representative of the task's runtime
    pub sched_deadline: u64, // representative of the task's deadline
    pub sched_period:   u64, // representative of the task's period
}

/// TODO(Shaohua):
pub struct bpf_attr_t {
}


/// capability.h
pub struct cap_user_header_t {
    pub version: u32,
    pub pid: i32,
}

#[derive(Debug)]
#[derive(Default)]
pub struct cap_user_data_t {
    pub effective:   u32,
    pub permitted:   u32,
    pub inheritable: u32,
}

/// eventpoll.h
pub struct epoll_event_t {
    pub events: poll_t,
    pub data: u64,
}

/// fcntl.h
pub struct flock {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: off_t,
    pub l_len: off_t,
    pub l_pid: pid_t,
}

pub struct flock64 {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: loff_t,
    pub l_len: loff_t,
    pub l_pid: pid_t,
}

#[derive(Debug)]
#[derive(Default)]
pub struct ustat_t {
    f_tfree: daddr_t,
    f_tinode: ino_t,
	pub f_fname: [u8; 6],
    pub f_fpack: [u8; 6],
}

/// utime.h
pub struct utimbuf_t {
    pub actime: time_t,
    pub modtime: time_t,
}

/// siginfo.h
// TODO(Shaohua): Add optional pad.
#[derive(Default)]
pub struct siginfo_t {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    // TODO(Shaohua): Add union fields.
    //pub si_fields:
}

/// signal.h
pub struct sigaltstack_t {
    pub ss_sp: usize,
	pub ss_flags: i32,
	pub ss_size: size_t,
}

