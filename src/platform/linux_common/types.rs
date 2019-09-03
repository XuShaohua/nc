// BEGIN of bitsperlong.h
#[cfg(target_pointer_size = 64)]
pub const BITS_PER_LONG: i32 = 64;

#[cfg(target_pointer_size = 32)]
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
pub type suseconds_t = usize;
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
//typedef char *		__kernel_caddr_t;  // TODO(Shaohua):
pub type uid16_t = u16;
pub type gid16_t = u16;
// END of posix_types.h
