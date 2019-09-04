// BEGIN of bitsperlong.h
#[cfg(target_pointer_width = "64")]
pub const BITS_PER_LONG: i32 = 64;

#[cfg(target_pointer_width = "32")]
pub const BITS_PER_LONG: i32 = 32;

pub const BITS_PER_LONG_LONG: i32 = 64;
// END of bitsperlong.h

// BEGIN of posix_types.h
pub type ino_t = usize;
pub type mode_t = u32;
pub type pid_t = i32;
pub type ipc_pid_t = i32;
pub type uid_t = u32;
pub type gid_t = u32;
pub type suseconds_t = isize;
pub type daddr_t = i32;
pub type uid32_t = u32;
pub type gid32_t = u32;

/// Most 32 bit architectures use "unsigned int" size_t,
/// and all 64 bit architectures use "unsigned long" size_t.
pub type size_t = usize;
pub type ssize_t = isize;
pub type ptrdiff_t = isize;

#[repr(C)]
pub struct fsid_t {
    pub val: [i32; 2],
}

/// anything below here should be completely generic
pub type off_t = isize;
pub type loff_t = i64;
pub type time_t = isize;
pub type time64_t = i64;
pub type clock_t = isize;
pub type timer_t = i32;
pub type clockid_t = i32;
pub type uid16_t = u16;
pub type gid16_t = u16;
// END of posix_types.h

// BEGIN of common types
pub type uintptr_t = usize;
pub type intptr_t = usize;
pub type regoff_t = usize;
pub type register_t = usize;

pub type blksize_t = usize;
pub type blkcnt_t = i64;
pub type fsblkcnt_t = u64;
pub type fsfilcnt_t = u64;

pub type wint_t = i32;
pub type wctype_t = usize;

pub type key_t = i32;
pub type useconds_t = u32;

//TYPEDEF struct __pthread * pthread_t;
pub type pthread_once_t = i32;
pub type pthread_key_t = i32;
pub type pthread_spinlock_t = i32;

#[repr(C)]
pub struct pthread_mutexattr_t {
    pub attr: u32,
}

#[repr(C)]
pub struct pthread_condattr_t {
    pub attr: u32,
}

#[repr(C)]
pub struct pthread_barrierattr_t {
    pub attr: i32,
}

#[repr(C)]
pub struct pthread_rwlockattr_t {
    pub attr: [u32; 2],
}

#[repr(C)]
pub struct io_file_t {
    pub x: u8,
}

pub type file_t = io_file_t;

//TYPEDEF struct __mbstate_t { unsigned __opaque1, __opaque2; } mbstate_t;

//TYPEDEF struct __locale_struct * locale_t;

pub type socklen_t = u32;
pub type sa_family_t = u16;

// END of common types
