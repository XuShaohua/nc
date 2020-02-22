use super::fcntl::*;
use super::types::*;

/// Flags for epoll_create1.
pub const EPOLL_CLOEXEC: i32 = O_CLOEXEC;

/// Valid opcodes to issue to sys_epoll_ctl()
pub const EPOLL_CTL_ADD: i32 = 1;
pub const EPOLL_CTL_DEL: i32 = 2;
pub const EPOLL_CTL_MOD: i32 = 3;

/// Epoll event masks
pub const EPOLLIN: poll_t = 0x00000001;
pub const EPOLLPRI: poll_t = 0x00000002;
pub const EPOLLOUT: poll_t = 0x00000004;
pub const EPOLLERR: poll_t = 0x00000008;
pub const EPOLLHUP: poll_t = 0x00000010;
pub const EPOLLNVAL: poll_t = 0x00000020;
pub const EPOLLRDNORM: poll_t = 0x00000040;
pub const EPOLLRDBAND: poll_t = 0x00000080;
pub const EPOLLWRNORM: poll_t = 0x00000100;
pub const EPOLLWRBAND: poll_t = 0x00000200;
pub const EPOLLMSG: poll_t = 0x00000400;
pub const EPOLLRDHUP: poll_t = 0x00002000;

/// Set exclusive wakeup mode for the target file descriptor
pub const EPOLLEXCLUSIVE: poll_t = 1 << 28;

/// Request the handling of system wakeup events so as to prevent system suspends
/// from happening while those events are being processed.
///
/// Assuming neither EPOLLET nor EPOLLONESHOT is set, system suspends will not be
/// re-allowed until epoll_wait is called again after consuming the wakeup
/// event(s).
///
/// Requires CAP_BLOCK_SUSPEND
pub const EPOLLWAKEUP: poll_t = 1 << 29;

/// Set the One Shot behaviour for the target file descriptor
pub const EPOLLONESHOT: poll_t = 1 << 30;

/// Set the Edge Triggered behaviour for the target file descriptor
pub const EPOLLET: poll_t = 1 << 31;

/*
 * On x86-64 make the 64bit structure have the same alignment as the
 * 32bit structure. This makes 32bit emulation easier.
 *
 * UML/x86_64 needs the same packing as x86_64
 */
//#ifdef __x86_64__
//#define EPOLL_PACKED __attribute__((packed))
// TODO(Shaohua): pack struct

#[repr(C)]
pub struct epoll_event_t {
    pub events: poll_t,
    data: u64,
}
