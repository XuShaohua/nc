// Copyright (c) 2021 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by General Public License that can be found
// in the LICENSE file.

//! From arch/x86/include/uapi/asm/signal.h

use super::signal::_NSIG;
use crate::{sighandler_t, sigrestore_t, size_t};

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

pub const SA_RESTORER: u32 = 0x04000000;

pub const MINSIGSTKSZ: usize = 2048;
pub const SIGSTKSZ: usize = 8192;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct sigaction_t {
    pub sa_handler: sighandler_t,
    pub sa_flags: usize,
    pub sa_restorer: sigrestore_t,

    /// mask last for extensibility
    pub sa_mask: sigset_t,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct sigaltstack_t {
    pub ss_sp: usize,
    pub ss_flags: i32,
    pub ss_size: size_t,
}

pub type stack_t = sigaltstack_t;
