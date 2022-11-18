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
mod rseq;
mod uapi;

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
pub use rseq::*;
pub use uapi::*;
