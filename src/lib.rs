// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! Execute system call directly without `std` or `libc`.
//!
//! - [Documentation](https://docs.rs/nc)
//! - [Release notes](https://github.com/xushaohua/nc/releases)
//!
//! ## Usage
//! Add this to `Cargo.toml`:
//! ```toml
//! [dependencies]
//! nc = "0.8"
//! ```
//!
//! ## Examples
//! Get file stat:
//! ```rust
//! let mut statbuf = nc::stat_t::default();
//! let path = "/etc/passwd";
//! #[cfg(not(target_arch = "aarch64"))]
//! let ret = unsafe { nc::stat(path, &mut statbuf) };
//! #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
//! let ret = unsafe { nc::fstatat(nc::AT_FDCWD, path, &mut statbuf, 0) };
//! match ret {
//!     Ok(_) => println!("s: {:?}", statbuf),
//!     Err(errno) => eprintln!("Failed to get file status, got errno: {}", errno),
//! }
//! ```
//!
//! Fork process:
//! ```rust
//! let pid = unsafe { nc::fork() };
//! match pid {
//!     Ok(pid) => {
//!         if pid == 0 {
//!             println!("child process: {}", pid);
//!             let args = [""];
//!             let env = [""];
//!             match unsafe { nc::execve("/bin/ls", &args, &env) } {
//!                 Ok(_) => {},
//!                 Err(errno) => eprintln!("`ls` got err: {}", errno),
//!             }
//!         } else if pid < 0 {
//!             eprintln!("fork() error!");
//!         } else {
//!             println!("parent process!");
//!         }
//!     },
//!     Err(errno) => eprintln!("errno: {}", errno),
//! }
//! ```
//!
//! Kill init process:
//! ```rust
//! let ret = unsafe { nc::kill(1, nc::SIGTERM) };
//! assert_eq!(ret, Err(nc::EPERM));
//! ```
//!
//! Or get system info:
//! ```rust
//! pub fn cstr_to_str(input: &[u8]) -> &str {
//!     let nul_index = input.iter().position(|&b| b == 0).unwrap_or(input.len());
//!     std::str::from_utf8(&input[0..nul_index]).unwrap()
//! }
//!
//! fn main() {
//!     let mut uts = nc::utsname_t::default();
//!     let ret = unsafe { nc::uname(&mut uts) };
//!     assert!(ret.is_ok());
//!
//!     let mut result = Vec::new();
//!
//!     result.push(cstr_to_str(&uts.sysname));
//!     result.push(cstr_to_str(&uts.nodename));
//!     result.push(cstr_to_str(&uts.release));
//!     result.push(cstr_to_str(&uts.version));
//!     result.push(cstr_to_str(&uts.machine));
//!     let domain_name = cstr_to_str(&uts.domainname);
//!     if domain_name != "(none)" {
//!         result.push(domain_name);
//!     }
//!
//!     let result = result.join(" ");
//!     println!("{}", result);
//! }
//! ```
//!
//! ## Stable version
//! For stable version of rustc, please install a C compiler (`gcc` or `clang`) first.
//! As `asm!` feature is unavailable in stable version.
//!
//! ## Supported Operating Systems and Architectures
//! - linux
//!   - x86
//!   - x86-64
//!   - arm
//!   - aarch64
//!   - loongarch64
//!   - mips
//!   - mipsel
//!   - mips64
//!   - mips64el
//!   - powerpc64
//!   - s390x
//! - android
//!   - aarch64
//! - freebsd
//!   - x86-64
//! - netbsd
//!   - x86-64
//! - mac os
//!   - x86-64
//!
//! ## Related projects
//! * [nix][nix]
//! * [syscall][syscall]
//! * [relibc][relibc]
//!
//! [syscall]: https://github.com/kmcallister/syscall.rs
//! [relibc]: https://gitlab.redox-os.org/redox-os/relibc.git
//! [nix]: https://github.com/nix-rust/nix

#![deny(
    warnings,
    clippy::all,
    clippy::cargo,
    clippy::nursery,
    clippy::pedantic
)]
#![allow(dead_code)]
#![allow(unknown_lints)]
#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod c_str;
pub mod path;
pub mod syscalls;
pub use syscalls::Errno;

#[cfg(target_os = "macos")]
#[path = "platform/darwin-types/mod.rs"]
pub mod types;

#[cfg(target_os = "freebsd")]
#[path = "platform/freebsd-types/mod.rs"]
pub mod types;

#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "platform/linux-types/mod.rs"]
pub mod types;

#[cfg(target_os = "netbsd")]
#[path = "platform/netbsd-types/mod.rs"]
pub mod types;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
#[path = "platform/linux-aarch64/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "arm"))]
#[path = "platform/linux-arm/mod.rs"]
mod platform;

#[cfg(all(target_os = "linux", target_arch = "loongarch64"))]
#[path = "platform/linux-loongarch64/mod.rs"]
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

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
#[path = "platform/darwin-x86_64/mod.rs"]
mod platform;

pub mod util;

// Re-export functions
pub use platform::*;
pub use types::*;
