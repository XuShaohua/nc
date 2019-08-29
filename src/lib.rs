#![crate_name = "nc"]
#![crate_type = "lib"]
#![allow(non_camel_case_types)]
#![feature(asm)]
#![feature(const_raw_ptr_deref)]
#![feature(const_slice_len)]
#![no_std]

#[macro_use]
extern crate alloc;

pub mod c_str;

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[path = "platform/linux-aarch64/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "arm"))]
#[path = "platform/linux-arm/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "mips"))]
#[path = "platform/linux-mips/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "mips64"))]
#[path = "platform/linux-mips64/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "powerpc"))]
#[path = "platform/linux-powerpc/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "powerpc64"))]
#[path = "platform/linux-powerpc64/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "s390x"))]
#[path = "platform/linux-s390x/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "x86"))]
#[path = "platform/linux-x86/mod.rs"]
pub mod platform;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[path = "platform/linux-x86_64/mod.rs"]
pub mod platform;

// Re-export functions
pub use platform::c::*;
pub use platform::consts::*;
pub use platform::errno::*;
pub use platform::sysno::*;
pub use platform::types::*;
