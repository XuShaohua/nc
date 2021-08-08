// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From arch/x86/include/uapi/asm/signal.h

use core::fmt;

use crate::{sighandler_t, siginfo_t, sigrestore_t, size_t, SIG_DFL, _NSIG};

pub const NSIG: usize = 32;

pub type sigset_t = usize;

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
pub const SIGPWR: u32 = 30;
pub const SIGSYS: u32 = 31;
pub const SIGUNUSED: u32 = 31;

/// These should not be considered constants from userland.
pub const SIGRTMIN: u32 = 32;
pub const SIGRTMAX: u32 = _NSIG as u32;

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
pub const SA_NOCLDSTOP: usize = 0x00000001;
pub const SA_NOCLDWAIT: usize = 0x00000002;
pub const SA_SIGINFO: usize = 0x00000004;
pub const SA_ONSTACK: usize = 0x08000000;
pub const SA_RESTART: usize = 0x10000000;
pub const SA_NODEFER: usize = 0x40000000;
pub const SA_RESETHAND: usize = 0x80000000;

pub const SA_NOMASK: usize = SA_NODEFER;
pub const SA_ONESHOT: usize = SA_RESETHAND;

pub const SA_RESTORER: usize = 0x04000000;

pub const MINSIGSTKSZ: i32 = 2048;
pub const SIGSTKSZ: i32 = 8192;

pub type sa_sigaction_fn_t = fn(i32, &mut siginfo_t, usize);

/// sa_sigaction_fn_t as usize
pub type sa_sigaction_t = usize;

#[repr(C)]
#[derive(Clone, Copy)]
pub union sigaction_u_t {
    pub sa_handler: sighandler_t,
    pub sa_sigaction: sa_sigaction_t,
}

impl Default for sigaction_u_t {
    fn default() -> Self {
        sigaction_u_t {
            sa_handler: SIG_DFL,
        }
    }
}

impl fmt::Debug for sigaction_u_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ptr = unsafe { self.sa_handler };
        write!(f, "sigaction_u_t: {}", ptr)
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct sigaction_t {
    pub u: sigaction_u_t,
    pub sa_mask: sigset_t,
    pub sa_flags: usize,
    pub sa_restorer: sigrestore_t,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct sigaltstack_t {
    pub ss_sp: usize,
    pub ss_flags: i32,
    pub ss_size: size_t,
}

pub type stack_t = sigaltstack_t;
