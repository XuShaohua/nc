use super::time::*;
use super::types::*;

#[repr(C)]
pub struct kernel_timespec_t {
    pub tv_sec: time64_t, /* seconds */
    pub tv_nsec: i64,     /* nanoseconds */
}

#[repr(C)]
pub struct kernel_itimerspec_t {
    pub it_interval: timespec_t, /* timer period */
    pub it_value: timespec_t,    /* timer expiration */
}

/// legacy timeval structure, only embedded in structures that
/// traditionally used 'timeval' to pass time intervals (not absolute times).
/// Do not add new users. If user space fails to compile here,
/// this is probably because it is not y2038 safe and needs to
/// be changed to use another interface.
#[repr(C)]
pub struct kernle_old_timeval_t {
    pub tv_sec: isize,
    pub tv_usec: isize,
}

#[repr(C)]
pub struct kernel_sock_timeval_t {
    pub tv_sec: i64,
    pub tv_usec: i64,
}
