// Copyright (c) 2024 Xu Shaohua <shaohua@biofan.org>. All rights reserved.
// Use of this source is governed by Apache-2.0 License that can be found
// in the LICENSE file.

//! macOS-specific restore implementation.
//!
//! On macOS, the kernel handles signal trampolines automatically,
//! so there is no need for a user-space restorer function.

/// On macOS, `sigaction_t` does not have a `sa_restorer` field,
/// so this always returns `None`.
#[must_use]
#[inline]
pub fn get_sa_restorer() -> Option<crate::restorefn_t> {
    None
}
