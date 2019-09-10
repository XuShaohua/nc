#![allow(dead_code)]
#![feature(asm)]
#![feature(const_raw_ptr_deref)]
#![feature(const_slice_len)]
#![no_std]

#[macro_use]
extern crate alloc;

pub mod c_str;

#[cfg(target_os = "freebsd")]
#[path = "platform/freebsd-asm-generic/mod.rs"]
mod asm_generic;

#[cfg(target_os = "netbsd")]
#[path = "platform/netbsd-asm-generic/mod.rs"]
mod asm_generic;

#[cfg(target_os = "linux")]
#[path = "platform/linux-types/mod.rs"]
mod types;

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

// Re-export functions
pub use platform::*;
