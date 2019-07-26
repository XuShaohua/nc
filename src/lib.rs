
#![crate_name="nc"]
#![crate_type="lib"]

#![allow(non_camel_case_types)]
#![feature(asm)]
#![feature(const_raw_ptr_deref)]
#![feature(const_slice_len)]
#![no_std]

pub mod c_str;

#[cfg(all(target_os="linux", target_arch="x86_64"))]
#[path="platform/linux-x86_64/mod.rs"]
pub mod platform;

// Re-export functions
pub use platform::c::*;
pub use platform::consts::*;
pub use platform::errno::*;
pub use platform::sysno::*;
pub use platform::types::*;

