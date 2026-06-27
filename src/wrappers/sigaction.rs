// Copyright (c) 2024 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

#![allow(clippy::module_name_repetitions)]

#[cfg(target_os = "macos")]
use crate::sigaction_u;
#[cfg(not(target_os = "macos"))]
use crate::{SA_RESTART, sighandler_t};

/// Create a new `sigaction_t` for signal handling.
///
/// On macOS the struct layout uses a union for the handler and has no
/// `sa_restorer` field.
#[cfg(target_os = "macos")]
#[inline]
pub fn new_sigaction(handler: fn(i32)) -> crate::sigaction_t {
    crate::sigaction_t {
        __sigaction_u: sigaction_u {
            sa_handler: handler,
        },
        sa_mask: 0,
        sa_flags: crate::SA_RESTART,
    }
}

/// Create a new `sigaction_t` for signal handling on Linux.
#[cfg(not(target_os = "macos"))]
#[cfg(nc_has_sa_restorer)]
#[inline]
pub fn new_sigaction(handler: fn(i32)) -> crate::sigaction_t {
    crate::sigaction_t {
        sa_handler: handler as sighandler_t,
        sa_flags: SA_RESTART | crate::SA_RESTORER,
        sa_restorer: crate::restore::get_sa_restorer(),
        ..crate::sigaction_t::default()
    }
}

/// Create a new `sigaction_t` for signal handling on Linux (no sa_restorer).
#[cfg(not(target_os = "macos"))]
#[cfg(not(nc_has_sa_restorer))]
#[inline]
pub fn new_sigaction(handler: fn(i32)) -> crate::sigaction_t {
    crate::sigaction_t {
        sa_handler: handler as sighandler_t,
        sa_flags: SA_RESTART,
        ..crate::sigaction_t::default()
    }
}
