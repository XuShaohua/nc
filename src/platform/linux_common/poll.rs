/// These are specified by iBCS2
pub const POLLIN: i32 = 0x0001;
pub const POLLPRI: i32 = 0x0002;
pub const POLLOUT: i32 = 0x0004;
pub const POLLERR: i32 = 0x0008;
pub const POLLHUP: i32 = 0x0010;
pub const POLLNVAL: i32 = 0x0020;

/// The rest seem to be more-or-less nonstandard. Check them!
pub const POLLRDNORM: i32 = 0x0040;
pub const POLLRDBAND: i32 = 0x0080;
pub const POLLWRNORM: i32 = 0x0100;
pub const POLLWRBAND: i32 = 0x0200;
pub const POLLMSG: i32 = 0x0400;
pub const POLLREMOVE: i32 = 0x1000;
pub const POLLRDHUP: i32 = 0x2000;

/// currently only for epoll
pub const POLLFREE: poll_t = 0x4000;

pub const POLL_BUSY_LOOP: poll_t = 0x8000;

#[repr(C)]
pub struct pollfd_t {
    pub fd: i32,
    pub events: i16,
    revents: i16,
}
