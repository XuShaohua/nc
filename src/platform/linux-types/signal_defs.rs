// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

/// for blocking signals
pub const SIG_BLOCK: i32 = 0;
/// for unblocking signals
pub const SIG_UNBLOCK: i32 = 1;
/// for setting the signal mask
pub const SIG_SETMASK: i32 = 2;

pub type signalfn_t = fn(i32);

/// Type of a signal handler.
/// signalfn_t as usize
pub type sighandler_t = usize;

pub type restorefn_t = fn();

/// restorefn_t as usize
pub type sigrestore_t = usize;

/// default signal handling
pub const SIG_DFL: sighandler_t = 0;
/// ignore signal
pub const SIG_IGN: sighandler_t = 1;
/// error return from signal
pub const SIG_ERR: sighandler_t = (-1_isize) as sighandler_t;
