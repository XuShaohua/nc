// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub type c_char = u8;

// First import architecture specific types.
#[cfg(target_arch = "aarch64")]
#[path = "aarch64/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "arm")]
#[path = "arm/mod.rs"]
mod arch;
pub use arch::*;

#[cfg(target_arch = "loongarch64")]
#[path = "loongarch64/mod.rs"]
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

#[cfg(target_arch = "powerpc64")]
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

mod page;
pub use page::*;

#[cfg(any(target_arch = "aarch64", target_arch = "loongarch64"))]
mod signal;
#[cfg(any(target_arch = "aarch64", target_arch = "loongarch64"))]
pub use signal::*;

#[cfg(target_arch = "loongarch64")]
mod stat;
#[cfg(target_arch = "loongarch64")]
pub use stat::*;

mod basic_types;
mod bitsperlong;
mod bpf;
mod capability;
mod eventpoll;
mod fcntl;
mod fs;
mod fs_readdir;
mod hugetlb_encode;
mod ioctl;
mod ioctls;
mod ioprio;
mod ipc;
mod ipcbuf;
mod kernel;
mod limits;
mod linux;
mod linux_dirent;
mod linux_fs;
mod linux_fs_types;
mod linux_net;
mod linux_quota;
mod linux_signal;
mod linux_socket;
mod linux_time64;
mod linux_timex;
mod membarrier;
mod memfd;
mod mempolicy;
mod mman;
mod mount;
mod mqueue;
mod msg;
mod msgbuf;
mod perf_event;
mod personality;
mod poll;
mod posix_types;
mod prctl;
mod ptrace;
mod resource;
mod rseq;
mod sched;
mod sched_types;
mod seccomp;
mod sem;
mod shm;
mod shmbuf;
mod siginfo;
mod signal_defs;
mod socket;
mod sockios;
mod splice;
mod statfs;
mod swap;
mod sysctl;
mod sysinfo;
mod termbits;
mod termios;
mod time;
mod time_types;
mod times;
mod timex;
mod uapi;
mod uapi_fadvise;
mod uapi_fcntl;
mod uapi_in;
mod uapi_in6;
mod uapi_linux_tcp;
mod utime;

pub use basic_types::*;
pub use bitsperlong::*;
pub use bpf::*;
pub use capability::*;
pub use eventpoll::*;
pub use fcntl::*;
pub use fs::*;
pub use fs_readdir::*;
pub use hugetlb_encode::*;
pub use ioctl::*;
pub use ioctls::*;
pub use ioprio::*;
pub use ipc::*;
pub use ipcbuf::*;
pub use kernel::*;
pub use limits::*;
pub use linux::*;
pub use linux_dirent::*;
pub use linux_fs::*;
pub use linux_fs_types::*;
pub use linux_net::*;
pub use linux_quota::*;
pub use linux_signal::*;
pub use linux_socket::*;
pub use linux_time64::*;
pub use linux_timex::*;
pub use membarrier::*;
pub use memfd::*;
pub use mempolicy::*;
pub use mman::*;
pub use mman::*;
pub use mount::*;
pub use mqueue::*;
pub use msg::*;
pub use msgbuf::*;
pub use perf_event::*;
pub use personality::*;
pub use poll::*;
pub use posix_types::*;
pub use prctl::*;
pub use ptrace::*;
pub use resource::*;
pub use rseq::*;
pub use sched::*;
pub use sched_types::*;
pub use seccomp::*;
pub use sem::*;
pub use shm::*;
pub use shmbuf::*;
pub use siginfo::*;
pub use signal_defs::*;
pub use socket::*;
pub use sockios::*;
pub use splice::*;
pub use statfs::*;
pub use swap::*;
pub use sysctl::*;
pub use sysinfo::*;
pub use termbits::*;
pub use termios::*;
pub use time::*;
pub use time_types::*;
pub use times::*;
pub use timex::*;
pub use uapi::*;
pub use uapi_fadvise::*;
pub use uapi_fcntl::*;
pub use uapi_in::*;
pub use uapi_in6::*;
pub use uapi_linux_tcp::*;
pub use utime::*;
