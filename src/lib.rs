// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! Execute system call directly. `nc` do not depend on `std`.
//!
//! - [Documentation](https://docs.rs/nc)
//! - [Release notes](https://github.com/xushaohua/nc/releases)
//!
//! ## Usage
//! Add this to `Cargo.toml`:
//! ```toml
//! [dependencies]
//! nc = "0.7"
//! ```
//!
//! ## Examples
//! Get file stat:
//! ```rust
//! let mut statbuf = nc::stat_t::default();
//! match nc::stat("/etc/passwd", &mut statbuf) {
//!     Ok(_) => println!("s: {:?}", statbuf),
//!     Err(errno) => eprintln!("Failed to get file status, got errno: {}", errno),
//! }
//! ```
//!
//! Fork process:
//! ```rust
//! let pid = nc::fork();
//! match pid {
//!     Ok(pid) => {
//!         if pid == 0 {
//!             println!("child process: {}", pid);
//!             let args = [""];
//!             let env = [""];
//!             match nc::execve("/bin/ls", &args, &env) {
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
//! Kill self:
//! ```rust
//! let pid = nc::getpid();
//! let ret = nc::kill(pid, nc::SIGTERM);
//! // Never reach here.
//! println!("ret: {:?}", ret);
//! ```
//!
//! Or handle signals:
//! ```rust
//! fn handle_alarm(signum: i32) {
//!     assert_eq!(signum, nc::SIGALRM);
//! }
//!
//! fn main() {
//!     let ret = nc::signal(nc::SIGALRM, handle_alarm as nc::sighandler_t);
//!     assert!(ret.is_ok());
//!     let remaining = nc::alarm(1);
//!     let ret = nc::pause();
//!     assert!(ret.is_err());
//!     assert_eq!(ret, Err(nc::EINTR));
//!     assert_eq!(remaining, 0);
//! }
//! ```
//!
//! ## Stable version
//! For stable version of rustc, please install a C compiler (`gcc` or `clang`) first.
//! As `asm!` feature is unavailable in stable version.
//!
//! ## Platforms and Architectures
//! - Linux
//!   - [x] x86
//!   - [x] x86-64
//!   - [x] arm
//!   - [x] aarch64
//!   - [x] mips
//!   - [x] mipsel
//!   - [x] mips64
//!   - [x] mips64el
//!   - [x] powerpc64
//!   - [x] s390x
//!
//! Current work is focused on linux networking.
//! FreeBSD and other OS are unavailable yet.
//!
//!
//! ## Related projects
//! * [nix][nix]
//! * [syscall][syscall]
//! * [relibc][relibc]
//!
//! [syscall]: https://github.com/kmcallister/syscall.rs
//! [relibc]: https://gitlab.redox-os.org/redox-os/relibc.git
//! [nix]: https://github.com/nix-rust/nix

#![allow(dead_code)]
#![no_std]
#![cfg_attr(has_asm, feature(llvm_asm))]

#[macro_use]
extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod c_str;
pub mod path;
pub mod syscalls;
pub use syscalls::Errno;

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

// Re-export functions
pub use platform::*;
pub use types::*;
