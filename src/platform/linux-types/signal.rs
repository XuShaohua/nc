// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! From include/uapi/asm-generic/signal.h

use crate::{sighandler_t, size_t, BITS_PER_LONG};

pub const _NSIG: usize = 64;
pub const _NSIG_BPW: usize = BITS_PER_LONG;
pub const _NSIG_WORDS: usize = _NSIG / _NSIG_BPW;

pub const SIGHUP: u32 = 1;
pub const SIGINT: u32 = 2;
pub const SIGQUIT: u32 = 3;
pub const SIGILL: u32 = 4;
pub const SIGTRAP: u32 = 5;
pub const SIGABRT: u32 = 6;
pub const SIGIOT: u32 = 6;
pub const SIGBUS: u32 = 7;
pub const SIGFPE: u32 = 8;
pub const SIGKILL: u32 = 9;
pub const SIGUSR1: u32 = 10;
pub const SIGSEGV: u32 = 11;
pub const SIGUSR2: u32 = 12;
pub const SIGPIPE: u32 = 13;
pub const SIGALRM: u32 = 14;
pub const SIGTERM: u32 = 15;
pub const SIGSTKFLT: u32 = 16;
pub const SIGCHLD: u32 = 17;
pub const SIGCONT: u32 = 18;
pub const SIGSTOP: u32 = 19;
pub const SIGTSTP: u32 = 20;
pub const SIGTTIN: u32 = 21;
pub const SIGTTOU: u32 = 22;
pub const SIGURG: u32 = 23;
pub const SIGXCPU: u32 = 24;
pub const SIGXFSZ: u32 = 25;
pub const SIGVTALRM: u32 = 26;
pub const SIGPROF: u32 = 27;
pub const SIGWINCH: u32 = 28;
pub const SIGIO: u32 = 29;
pub const SIGPOLL: u32 = SIGIO;
//pub const SIGLOST: u32 = 29;
pub const SIGPWR: u32 = 30;
pub const SIGSYS: u32 = 31;
pub const SIGUNUSED: u32 = 31;

/// These should not be considered constants from userland.
pub const SIGRTMIN: u32 = 32;
pub const SIGRTMAX: u32 = _NSIG as u32;

pub const MINSIGSTKSZ: usize = 2048;
pub const SIGSTKSZ: usize = 8192;

#[repr(C)]
#[derive(Debug)]
pub struct sigset_t {
    pub sig: [usize; _NSIG_WORDS],
}

/// not actually used, but required for linux/syscalls.h
pub type old_sigset_t = usize;

#[cfg(any(target_arch = "arm", target_arch = "powerpc64", target_arch = "s390x"))]
#[repr(C)]
#[derive(Debug)]
pub struct sigaction_t {
    pub sa_handler: __sighandler_t,
    pub sa_flags: usize,
    pub sa_restorer: __sigrestore_t,
}

// No SA_RESTORER
#[cfg(any(target_arch = "aarch64", target_arch = "mips", target_arch = "mips64")))]
#[repr(C)]
#[derive(Debug)]
pub struct sigaction_t {
	pub sa_handler: __sighandler_t,
	pub sa_flags: usize,
    /// mask last for extensibility
	pub sigset_t sa_mask;
}

pub struct sigaltstack_t {
    pub ss_sp: usize,
    pub ss_flags: i32,
    pub ss_size: size_t,
}

pub type stack_t = signalstack_t;
