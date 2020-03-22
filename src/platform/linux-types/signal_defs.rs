// Copyright (c) 2020 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

use super::types::*;

/// for blocking signals
pub const SIG_BLOCK: i32 = 0;
/// for unblocking signals
pub const SIG_UNBLOCK: i32 = 1;
/// for setting the signal mask
pub const SIG_SETMASK: i32 = 2;

// TODO(Shaohua):
//pub type signalfn_t = Fn<i32> -> !;
//typedef void __signalfn_t(int);
//typedef __signalfn_t __user *__sighandler_t;
//typedef void __restorefn_t(void);
//typedef __restorefn_t __user *__sigrestore_t;

/// default signal handling
pub const SIG_DFL: sighandler_t = 0;
/// ignore signal
pub const SIG_IGN: sighandler_t = 1;
/// error return from signal
pub const SIG_ERR: sighandler_t = -1;
