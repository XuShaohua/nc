#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

// First import architecture specific types.
#[cfg(target_arch = "aarch64")]
#[path = "aarch64/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "arm")]
#[path = "arm/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "mips")]
#[path = "mips/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "mips64")]
#[path = "mips64/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "ppc64")]
#[path = "ppc64/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "s390x")]
#[path = "s390x/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "x86")]
#[path = "x86/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
mod arch;
pub use arch::*;

mod aio_abi;
mod bpf;
mod capability;
mod compat;
mod dqblk_xfs;
mod eventpoll;
mod fcntl;
mod fs;
mod fs_readdir;
mod getcpu;
mod hugetlb_encode;
mod ioctl;
mod ioctls;
mod ipc;
mod ipcbuf;
mod key;
mod limits;
mod linux_dirent;
mod linux_fs;
mod linux_fs_types;
mod linux_quota;
mod linux_socket;
mod linux_time64;
mod linux_timex;
mod mempolicy;
mod mman;
mod mman_common;
mod mount;
mod mqueue;
mod msg;
mod msgbuf;
mod poll;
mod quota;
mod resource;
mod sched_types;
mod sem;
mod shm;
mod shmbuf;
mod siginfo;
mod signal;
mod signal_defs;
mod socket;
mod sockios;
mod stat;
mod statfs;
mod sysctl;
mod sysinfo;
mod termbits;
mod termios;
mod time;
mod time_types;
mod times;
mod timex;
mod types;
mod uapi_fcntl;
mod uapi_in;
mod uapi_in6;
mod uapi_serial;
mod uapi_socket;
mod uapi_stat;
mod uio;
mod utime;
mod utsname;

pub use aio_abi::*;
pub use bpf::*;
pub use capability::*;
pub use compat::*;
pub use dqblk_xfs::*;
pub use eventpoll::*;
pub use fcntl::*;
pub use fs::*;
pub use fs_readdir::*;
pub use getcpu::*;
pub use hugetlb_encode::*;
pub use ioctl::*;
pub use ioctls::*;
pub use ipc::*;
pub use ipcbuf::*;
pub use key::*;
pub use limits::*;
pub use linux_dirent::*;
pub use linux_fs::*;
pub use linux_fs_types::*;
pub use linux_quota::*;
pub use linux_socket::*;
pub use linux_time64::*;
pub use linux_timex::*;
pub use mempolicy::*;
pub use mman::*;
pub use mman_common::*;
pub use mount::*;
pub use mqueue::*;
pub use msg::*;
pub use msgbuf::*;
pub use poll::*;
pub use quota::*;
pub use resource::*;
pub use sched_types::*;
pub use sem::*;
pub use shm::*;
pub use shmbuf::*;
pub use siginfo::*;
pub use signal::*;
pub use signal_defs::*;
pub use socket::*;
pub use sockios::*;
pub use stat::*;
pub use statfs::*;
pub use sysctl::*;
pub use sysinfo::*;
pub use termbits::*;
pub use termios::*;
pub use time::*;
pub use time_types::*;
pub use times::*;
pub use timex::*;
pub use types::*;
pub use uapi_fcntl::*;
pub use uapi_in::*;
pub use uapi_in6::*;
pub use uapi_serial::*;
pub use uapi_socket::*;
pub use uapi_stat::*;
pub use uio::*;
pub use utime::*;
pub use utsname::*;
