#![allow(dead_code)]
#![no_std]
#![cfg_attr(nightly, feature(asm, const_raw_ptr_deref, const_slice_len))]

#[macro_use]
extern crate alloc;

pub mod c_str;

#[cfg(target_os = "freebsd")]
#[path = "platform/freebsd-types/mod.rs"]
pub mod types;

#[cfg(target_os = "netbsd")]
#[path = "platform/netbsd-types/mod.rs"]
pub mod types;

#[cfg(target_os = "linux")]
#[path = "platform/linux-types/mod.rs"]
pub mod types;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "platform/linux-aarch64/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "arm"))]
#[path = "platform/linux-arm/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "mips"))]
#[path = "platform/linux-mips/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "mips64"))]
#[path = "platform/linux-mips64/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "powerpc64"))]
#[path = "platform/linux-ppc64/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "s390x"))]
#[path = "platform/linux-s390x/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "x86"))]
#[path = "platform/linux-x86/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "platform/linux-x86_64/mod.rs"]
mod platform;

#[cfg(all(target_os = "freebsd", target_arch = "x86"))]
#[path = "platform/freebsd-x86/mod.rs"]
mod platform;

#[cfg(all(target_os = "freebsd", target_arch = "x86_64"))]
#[path = "platform/freebsd-x86_64/mod.rs"]
mod platform;

#[cfg(all(target_os = "netbsd", target_arch = "x86"))]
#[path = "platform/netbsd-x86/mod.rs"]
mod platform;

#[cfg(all(target_os = "netbsd", target_arch = "x86_64"))]
#[path = "platform/netbsd-x86_64/mod.rs"]
mod platform;

mod syscalls;

// Re-export functions
pub use platform::*;
pub use types::*;
