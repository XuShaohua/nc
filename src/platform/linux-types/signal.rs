// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use super::types::*;

// TODO(Shaohua): Update from 64 to 128
pub const _NSIG: i32 = 128;
pub const _NSIG_BPW: i32 = BITS_PER_LONG;
pub const _NSIG_WORDS: i32 = _NSIG / _NSIG_BPW;

pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGTRAP: i32 = 5;
pub const SIGABRT: i32 = 6;
pub const SIGIOT: i32 = 6;
pub const SIGBUS: i32 = 7;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGSTKFLT: i32 = 16;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;
pub const SIGTTIN: i32 = 21;
pub const SIGTTOU: i32 = 22;
pub const SIGURG: i32 = 23;
pub const SIGXCPU: i32 = 24;
pub const SIGXFSZ: i32 = 25;
pub const SIGVTALRM: i32 = 26;
pub const SIGPROF: i32 = 27;
pub const SIGWINCH: i32 = 28;
pub const SIGIO: i32 = 29;
pub const SIGPOLL: i32 = SIGIO;
//pub const SIGLOST: i32 = 29;
pub const SIGPWR: i32 = 30;
pub const SIGSYS: i32 = 31;
pub const SIGUNUSED: i32 = 31;

/// These should not be considered constants from userland.
pub const SIGRTMIN: i32 = 32;
pub const SIGRTMAX: i32 = _NSIG;

/// SA_FLAGS values:
///
/// SA_ONSTACK indicates that a registered stack_t will be used.
/// SA_RESTART flag to get restarting signals (which were the default long ago)
/// SA_NOCLDSTOP flag to turn off SIGCHLD when children stop.
/// SA_RESETHAND clears the handler when the signal is delivered.
/// SA_NOCLDWAIT flag on SIGCHLD to inhibit zombies.
/// SA_NODEFER prevents the current signal from being masked in the handler.
///
/// SA_ONESHOT and SA_NOMASK are the historical Linux names for the Single
/// Unix names RESETHAND and NODEFER respectively.
pub const SA_NOCLDSTOP: i32 = 0x0000_0001;
pub const SA_NOCLDWAIT: i32 = 0x0000_0002;
pub const SA_SIGINFO: i32 = 0x0000_0004;
pub const SA_ONSTACK: i32 = 0x0800_0000;
pub const SA_RESTART: i32 = 0x1000_0000;
pub const SA_NODEFER: i32 = 0x4000_0000;
#[allow(overflowing_literals)]
pub const SA_RESETHAND: i32 = 0x8000_0000;

pub const SA_NOMASK: i32 = SA_NODEFER;
pub const SA_ONESHOT: i32 = SA_RESETHAND;

// New architectures should not define the obsolete SA_RESTORER	0x04000000
pub const MINSIGSTKSZ: i32 = 2048;
pub const SIGSTKSZ: i32 = 8192;

#[repr(C)]
#[derive(Debug, Default)]
pub struct sigset_t {
    pub sig: [usize; _NSIG_WORDS as usize],
}

/// not actually used, but required for linux/syscalls.h
pub type old_sigset_t = usize;

//#include <asm-generic/signal-defs.h>

//#ifdef SA_RESTORER
//#define __ARCH_HAS_SA_RESTORER
//#endif

#[repr(C)]
#[derive(Debug, Default)]
pub struct sigaction_t {
    pub sa_handler: sighandler_t,
    pub sa_flags: usize,
    //#ifdef SA_RESTORER
    //__sigrestore_t sa_restorer;
    //#endif
    /// mask last for extensibility
    pub sa_mask: sigset_t,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct sigaltstack_t {
    pub ss_sp: usize,
    pub ss_flags: i32,
    pub ss_size: size_t,
}
