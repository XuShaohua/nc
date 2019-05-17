
#![crate_name="nc"]
#![crate_type="lib"]

#![feature(asm)]
#![no_std]

pub use platform::c::*;
pub use platform::nums::*;
pub use platform::types::*;

#[cfg(all(target_os="linux", target_arch="x86_64"))]
#[path="platform/linux-x86_64/mod.rs"]
pub mod platform;
